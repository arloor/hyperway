use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::extract::Request;
use axum_bootstrap::InterceptResult;
use http::header::{CONNECTION, HOST, LOCATION, UPGRADE};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use http_body_util::{BodyExt as _, Full, combinators::BoxBody};
use hyper::body::{Bytes, Incoming};
use hyper::{Response, Version};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use log::{debug, warn};
use regex::Regex;

use crate::axum_handler::{self, AppProxyError};
use crate::config::Config;
use crate::gateway_runtime::{
    GatewayListenerConfig, GatewayRuntime, HttpHeaderModifierV1, HttpPathMatchTypeV1, HttpPathModifierTypeV1,
    HttpRouteMatchV1, HttpRouteRuleV1, HttpStringMatchTypeV1, WeightedBackendRefV1,
};
use crate::metrics::METRICS;

#[allow(dead_code)]
pub(crate) enum InterceptResultAdapter {
    Drop,
    Return(Response<BoxBody<Bytes, io::Error>>),
    Continue(Request<Incoming>),
}

impl From<InterceptResultAdapter> for InterceptResult<AppProxyError> {
    fn from(value: InterceptResultAdapter) -> Self {
        match value {
            InterceptResultAdapter::Drop => InterceptResult::Drop,
            InterceptResultAdapter::Return(resp) => {
                let (parts, body) = resp.into_parts();
                InterceptResult::Return(Response::from_parts(parts, axum::body::Body::new(body)))
            }
            InterceptResultAdapter::Continue(req) => InterceptResult::Continue(req),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct GatewayRuntimeApplyStats {
    pub(crate) route_count: usize,
    pub(crate) listener_count: usize,
}

#[derive(Clone)]
struct RuntimeState {
    listeners: Vec<GatewayListenerConfig>,
    http_routes_v1: Vec<HttpRouteRuleV1>,
}

pub struct ProxyHandler {
    runtime: Arc<RwLock<RuntimeState>>,
    reverse_proxy_client: legacy::Client<
        HttpsConnector<HttpConnector>,
        http_body_util::combinators::BoxBody<axum::body::Bytes, std::io::Error>,
    >,
    request_seq: AtomicU64,
}

impl ProxyHandler {
    pub fn new(config: Arc<Config>) -> Result<Self, crate::DynError> {
        let listeners = normalize_listeners(config.initial_runtime.listeners.clone());
        Ok(Self {
            runtime: Arc::new(RwLock::new(RuntimeState {
                listeners,
                http_routes_v1: config.initial_runtime.http_routes_v1.clone(),
            })),
            reverse_proxy_client: build_hyper_legacy_client(),
            request_seq: AtomicU64::new(0),
        })
    }

    pub fn replace_gateway_runtime(
        &self, runtime: GatewayRuntime,
    ) -> Result<GatewayRuntimeApplyStats, crate::DynError> {
        let listeners = normalize_listeners(runtime.listeners);
        let route_count = runtime.http_routes_v1.len();
        let listener_count = listeners.len();
        let mut guard = self
            .runtime
            .write()
            .map_err(|_| io::Error::other("runtime lock poisoned"))?;
        *guard = RuntimeState {
            listeners,
            http_routes_v1: runtime.http_routes_v1,
        };
        Ok(GatewayRuntimeApplyStats {
            route_count,
            listener_count,
        })
    }

    pub fn current_listeners(&self) -> Result<Vec<GatewayListenerConfig>, crate::DynError> {
        let guard = self
            .runtime
            .read()
            .map_err(|_| io::Error::other("runtime lock poisoned"))?;
        Ok(guard.listeners.clone())
    }

    pub async fn handle(
        &self, req: Request<Incoming>, client_socket_addr: SocketAddr, default_scheme: &'static str, listener_port: u16,
    ) -> Result<InterceptResultAdapter, io::Error> {
        if axum_handler::AXUM_PATHS.contains(&req.uri().path()) {
            return Ok(InterceptResultAdapter::Continue(req));
        }

        let (original_scheme_host_port, req_domain) = extract_scheme_host_port(&req, default_scheme)?;

        let selected_v1 = {
            let guard = self
                .runtime
                .read()
                .map_err(|_| io::Error::other("runtime lock poisoned"))?;
            select_route_v1(&guard.http_routes_v1, listener_port, &req_domain.0, &req)
        };

        if let Some(selected_v1) = selected_v1 {
            return self
                .execute_v1_route(selected_v1, req, client_socket_addr, &original_scheme_host_port, &req_domain.0)
                .await;
        }

        Ok(InterceptResultAdapter::Continue(req))
    }

    async fn execute_v1_route(
        &self, selected: SelectedRouteV1, mut req: Request<Incoming>, client_socket_addr: SocketAddr,
        original_scheme_host_port: &SchemeHostPort, request_host: &str,
    ) -> Result<InterceptResultAdapter, io::Error> {
        METRICS.reverse_proxy_requests.inc();

        if let Some(redirect) = selected.rule.request_redirect.as_ref() {
            let location = build_redirect_location(redirect, &selected, &req, original_scheme_host_port);
            let status = normalize_redirect_status(redirect.status_code);
            let mut builder = Response::builder().status(status);
            if !location.is_empty() {
                builder = builder.header(LOCATION, location);
            }
            let response = builder
                .body(empty_box_body())
                .map_err(|err| io::Error::new(ErrorKind::InvalidData, err))?;
            return Ok(InterceptResultAdapter::Return(response));
        }

        let Some(backend) = self.pick_backend(&selected.rule.backends) else {
            let response = Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(empty_box_body())
                .map_err(|err| io::Error::new(ErrorKind::InvalidData, err))?;
            return Ok(InterceptResultAdapter::Return(response));
        };

        let is_websocket = is_websocket_upgrade(&req);
        if is_websocket {
            debug!(
                "[reverse-v1] websocket {} => {} route={} backend={}/{}:{}",
                client_socket_addr,
                original_scheme_host_port,
                selected.rule.id,
                backend.namespace,
                backend.name,
                backend.port
            );

            let client_upgrade = hyper::upgrade::on(&mut req);
            let upstream_req =
                build_upstream_req_v1_streaming(&selected, &backend, req, original_scheme_host_port, request_host)?;
            let upstream_req = box_request_body(upstream_req);

            let timeout_ms = selected
                .rule
                .backend_request_timeout_ms
                .or(selected.rule.request_timeout_ms);
            let mut upstream_resp = request_with_timeout(&self.reverse_proxy_client, upstream_req, timeout_ms).await?;
            if let Some(modifier) = selected.rule.response_header_modifier.as_ref() {
                apply_header_modifier_to_response(upstream_resp.headers_mut(), modifier);
            }
            if upstream_resp.status() != StatusCode::SWITCHING_PROTOCOLS {
                return Ok(InterceptResultAdapter::Return(map_response_body(upstream_resp)));
            }

            let upstream_upgrade = hyper::upgrade::on(&mut upstream_resp);
            spawn_websocket_tunnel(client_upgrade, upstream_upgrade, "reverse-v1");
            return Ok(InterceptResultAdapter::Return(map_response_body(upstream_resp)));
        }

        let method = req.method().clone();
        let version = req.version();
        let headers = req.headers().clone();
        let path = req.uri().path().to_string();
        let query = req.uri().query().map(str::to_string);
        let body_bytes = req
            .into_body()
            .collect()
            .await
            .map_err(|err| io::Error::new(ErrorKind::InvalidData, err))?
            .to_bytes();

        if !selected.rule.request_mirrors.is_empty() {
            self.spawn_mirror_requests(
                &selected,
                &method,
                version,
                &headers,
                &path,
                query.as_deref(),
                body_bytes.clone(),
                original_scheme_host_port,
                request_host,
            );
        }

        let retry_policy = selected.rule.retry.clone();
        let retry_attempts = retry_policy.as_ref().map(|retry| retry.attempts.max(1)).unwrap_or(1);
        let timeout_ms = selected
            .rule
            .backend_request_timeout_ms
            .or(selected.rule.request_timeout_ms);

        let mut attempt: u16 = 0;
        loop {
            attempt = attempt.saturating_add(1);
            let upstream_req = build_upstream_req_v1_buffered(
                &selected,
                &backend,
                &method,
                version,
                &headers,
                &path,
                query.as_deref(),
                body_bytes.clone(),
                original_scheme_host_port,
                request_host,
            )?;

            match request_with_timeout(&self.reverse_proxy_client, upstream_req, timeout_ms).await {
                Ok(mut resp) => {
                    let should_retry = retry_policy
                        .as_ref()
                        .map(|retry| should_retry_status(retry, resp.status()))
                        .unwrap_or(false);
                    if should_retry && attempt < retry_attempts {
                        if let Some(backoff_ms) = retry_policy.as_ref().and_then(|retry| retry.backoff_ms) {
                            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        }
                        continue;
                    }

                    if let Some(modifier) = selected.rule.response_header_modifier.as_ref() {
                        apply_header_modifier_to_response(resp.headers_mut(), modifier);
                    }
                    if resp.status().is_redirection() && resp.headers().contains_key(LOCATION) {
                        normalize_redirect_response(original_scheme_host_port, resp.headers_mut())?;
                    }
                    return Ok(InterceptResultAdapter::Return(map_response_body(resp)));
                }
                Err(err) => {
                    if attempt >= retry_attempts {
                        return Err(err);
                    }
                    if let Some(backoff_ms) = retry_policy.as_ref().and_then(|retry| retry.backoff_ms) {
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    }
                }
            }
        }
    }

    fn pick_backend(&self, backends: &[WeightedBackendRefV1]) -> Option<WeightedBackendRefV1> {
        if backends.is_empty() {
            return None;
        }

        let total_weight: u64 = backends.iter().map(|backend| backend.weight as u64).sum();
        if total_weight == 0 {
            return backends.first().cloned();
        }

        let seq = self.request_seq.fetch_add(1, Ordering::Relaxed);
        let mut slot = seq % total_weight;
        for backend in backends {
            let weight = backend.weight as u64;
            if slot < weight {
                return Some(backend.clone());
            }
            slot -= weight;
        }

        backends.last().cloned()
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_mirror_requests(
        &self, selected: &SelectedRouteV1, method: &Method, version: Version, headers: &HeaderMap, path: &str,
        query: Option<&str>, body_bytes: Bytes, original_scheme_host_port: &SchemeHostPort, request_host: &str,
    ) {
        for mirror in &selected.rule.request_mirrors {
            if let Some(percent) = mirror.fraction_percent
                && percent < 100
            {
                let seq = self.request_seq.fetch_add(1, Ordering::Relaxed);
                if (seq % 100) as u8 >= percent {
                    continue;
                }
            }

            let req = match build_upstream_req_v1_buffered(
                selected,
                &mirror.backend,
                method,
                version,
                headers,
                path,
                query,
                body_bytes.clone(),
                original_scheme_host_port,
                request_host,
            ) {
                Ok(req) => req,
                Err(err) => {
                    warn!("build mirror request failed: {err}");
                    continue;
                }
            };

            let client = self.reverse_proxy_client.clone();
            tokio::spawn(async move {
                if let Err(err) = client.request(req).await {
                    warn!("mirror request failed: {err}");
                }
            });
        }
    }
}

#[derive(Clone)]
struct SelectedRouteV1 {
    rule: HttpRouteRuleV1,
    matched: HttpRouteMatchV1,
    score: i64,
}

fn select_route_v1(
    routes: &[HttpRouteRuleV1], listener_port: u16, request_host: &str, req: &Request<Incoming>,
) -> Option<SelectedRouteV1> {
    let query_pairs = parse_query_pairs(req.uri().query());
    let mut selected = None::<SelectedRouteV1>;

    for rule in routes {
        if rule.listener_port != listener_port {
            continue;
        }
        if !match_route_hostnames(&rule.hostnames, request_host) {
            continue;
        }

        let candidate_matches = if rule.matches.is_empty() {
            vec![HttpRouteMatchV1::default()]
        } else {
            rule.matches.clone()
        };

        for route_match in candidate_matches {
            if !match_route_match(req, &query_pairs, &route_match) {
                continue;
            }
            let score = route_match_score(&route_match);
            let candidate = SelectedRouteV1 {
                rule: rule.clone(),
                matched: route_match,
                score,
            };
            match &selected {
                Some(current) if current.score >= score => {}
                _ => {
                    selected = Some(candidate);
                }
            }
        }
    }

    selected
}

fn match_route_hostnames(patterns: &[String], host: &str) -> bool {
    if patterns.is_empty() {
        return true;
    }
    patterns.iter().any(|pattern| hostname_matches(pattern, host))
}

fn hostname_matches(pattern: &str, host: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        let required_suffix = format!(".{suffix}");
        if host.len() <= required_suffix.len() {
            return false;
        }
        return host.ends_with(&required_suffix);
    }
    pattern.eq_ignore_ascii_case(host)
}

fn parse_query_pairs(query: Option<&str>) -> HashMap<String, Vec<String>> {
    let mut parsed = HashMap::<String, Vec<String>>::new();
    let Some(query) = query else {
        return parsed;
    };
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut split = pair.splitn(2, '=');
        let key = split.next().unwrap_or_default().to_string();
        let value = split.next().unwrap_or_default().to_string();
        parsed.entry(key).or_default().push(value);
    }
    parsed
}

fn match_route_match(
    req: &Request<Incoming>, query_pairs: &HashMap<String, Vec<String>>, route_match: &HttpRouteMatchV1,
) -> bool {
    if let Some(path) = route_match.path.as_ref()
        && !match_path(path, req.uri().path())
    {
        return false;
    }

    if let Some(method) = route_match.method.as_ref()
        && req.method().as_str() != method
    {
        return false;
    }

    for header in &route_match.headers {
        let Some(value) = req.headers().get(header.name.as_str()) else {
            return false;
        };
        let Ok(value) = value.to_str() else {
            return false;
        };
        if !match_string(&header.value, header.match_type, value) {
            return false;
        }
    }

    for query in &route_match.query_params {
        let Some(values) = query_pairs.get(&query.name) else {
            return false;
        };
        if !values
            .iter()
            .any(|value| match_string(&query.value, query.match_type, value))
        {
            return false;
        }
    }

    true
}

fn match_path(path_match: &crate::gateway_runtime::HttpPathMatchV1, request_path: &str) -> bool {
    match path_match.match_type {
        HttpPathMatchTypeV1::Exact => request_path == path_match.value,
        HttpPathMatchTypeV1::PathPrefix => request_path.starts_with(&path_match.value),
        HttpPathMatchTypeV1::RegularExpression => Regex::new(&path_match.value)
            .map(|regex| regex.is_match(request_path))
            .unwrap_or(false),
    }
}

fn match_string(pattern: &str, match_type: HttpStringMatchTypeV1, input: &str) -> bool {
    match match_type {
        HttpStringMatchTypeV1::Exact => pattern == input,
        HttpStringMatchTypeV1::RegularExpression => {
            Regex::new(pattern).map(|regex| regex.is_match(input)).unwrap_or(false)
        }
    }
}

fn route_match_score(route_match: &HttpRouteMatchV1) -> i64 {
    let mut score = 0_i64;
    if let Some(path) = route_match.path.as_ref() {
        score += match path.match_type {
            HttpPathMatchTypeV1::Exact => 100_000,
            HttpPathMatchTypeV1::PathPrefix => 60_000,
            HttpPathMatchTypeV1::RegularExpression => 20_000,
        };
        score += path.value.len() as i64;
    }
    if route_match.method.is_some() {
        score += 1_000;
    }
    score += (route_match.headers.len() as i64) * 100;
    score += (route_match.query_params.len() as i64) * 10;
    score
}

fn normalize_redirect_status(status_code: Option<u16>) -> StatusCode {
    match status_code.unwrap_or(302) {
        301 => StatusCode::MOVED_PERMANENTLY,
        302 => StatusCode::FOUND,
        303 => StatusCode::SEE_OTHER,
        307 => StatusCode::TEMPORARY_REDIRECT,
        308 => StatusCode::PERMANENT_REDIRECT,
        _ => StatusCode::FOUND,
    }
}

fn build_redirect_location(
    redirect: &crate::gateway_runtime::HttpRequestRedirectV1, selected: &SelectedRouteV1, req: &Request<Incoming>,
    original_scheme_host_port: &SchemeHostPort,
) -> String {
    let scheme = redirect
        .scheme
        .as_deref()
        .unwrap_or(original_scheme_host_port.scheme.as_str());
    let host = redirect
        .hostname
        .as_deref()
        .unwrap_or(original_scheme_host_port.host.as_str());
    let port_part = match redirect.port {
        Some(port) => format!(":{port}"),
        None => String::new(),
    };
    let rewritten_path =
        rewrite_path(req.uri().path(), req.uri().query(), selected.matched.path.as_ref(), redirect.path.as_ref());
    format!("{scheme}://{host}{port_part}{rewritten_path}")
}

#[allow(clippy::too_many_arguments)]
fn build_upstream_req_v1_buffered(
    selected: &SelectedRouteV1, backend: &WeightedBackendRefV1, method: &Method, version: Version, headers: &HeaderMap,
    path: &str, query: Option<&str>, body: Bytes, original_scheme_host_port: &SchemeHostPort, request_host: &str,
) -> io::Result<Request<BoxBody<Bytes, io::Error>>> {
    let upstream_uri = build_upstream_uri(selected, backend, path, query)?;
    let upstream_version = normalize_upstream_version(version, &upstream_uri);
    let mut req_builder = Request::builder()
        .method(method.clone())
        .version(upstream_version)
        .uri(upstream_uri);
    let req_headers = req_builder
        .headers_mut()
        .ok_or_else(|| io::Error::other("headers_mut returned None"))?;

    for (name, value) in headers {
        if name != HOST {
            req_headers.append(name.clone(), value.clone());
        }
    }

    if let Some(modifier) = selected.rule.request_header_modifier.as_ref() {
        apply_header_modifier_to_request(req_headers, modifier);
    }

    if let Some(hostname) = selected
        .rule
        .url_rewrite
        .as_ref()
        .and_then(|rewrite| rewrite.hostname.as_ref())
    {
        if let Ok(host_value) = HeaderValue::from_str(hostname) {
            req_headers.insert(HOST, host_value);
        }
    }

    req_headers.remove(CONNECTION);
    req_headers.remove(UPGRADE);
    if request_host.is_empty() {
        req_headers.remove(HOST);
    }

    let request = req_builder
        .body(full_body(body))
        .map_err(|err| io::Error::new(ErrorKind::InvalidData, err))?;

    let _ = original_scheme_host_port;
    Ok(request)
}

fn build_upstream_req_v1_streaming(
    selected: &SelectedRouteV1, backend: &WeightedBackendRefV1, req: Request<Incoming>,
    original_scheme_host_port: &SchemeHostPort, request_host: &str,
) -> io::Result<Request<Incoming>> {
    let method = req.method().clone();
    let headers = req.headers().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(str::to_string);

    let upstream_uri = build_upstream_uri(selected, backend, &path, query.as_deref())?;
    // WebSocket tunnel uses HTTP/1.1 Upgrade semantics.
    let mut builder = Request::builder()
        .method(method)
        .version(Version::HTTP_11)
        .uri(upstream_uri);
    let new_headers = builder
        .headers_mut()
        .ok_or_else(|| io::Error::other("headers_mut returned None"))?;

    for (name, value) in &headers {
        if name != HOST {
            new_headers.append(name.clone(), value.clone());
        }
    }

    if let Some(modifier) = selected.rule.request_header_modifier.as_ref() {
        apply_header_modifier_to_request(new_headers, modifier);
    }

    if let Some(hostname) = selected
        .rule
        .url_rewrite
        .as_ref()
        .and_then(|rewrite| rewrite.hostname.as_ref())
    {
        if let Ok(host_value) = HeaderValue::from_str(hostname) {
            new_headers.insert(HOST, host_value);
        }
    }

    if request_host.is_empty() {
        new_headers.remove(HOST);
    }

    let _ = original_scheme_host_port;
    builder
        .body(req.into_body())
        .map_err(|err| io::Error::new(ErrorKind::InvalidData, err))
}

fn build_upstream_uri(
    selected: &SelectedRouteV1, backend: &WeightedBackendRefV1, original_path: &str, original_query: Option<&str>,
) -> io::Result<Uri> {
    let rewritten = rewrite_path(
        original_path,
        original_query,
        selected.matched.path.as_ref(),
        selected
            .rule
            .url_rewrite
            .as_ref()
            .and_then(|rewrite| rewrite.path.as_ref()),
    );

    let uri = format!("http://{}.{}.svc.cluster.local:{}{}", backend.name, backend.namespace, backend.port, rewritten);
    Uri::from_str(&uri).map_err(|err| io::Error::new(ErrorKind::InvalidData, err))
}

fn normalize_upstream_version(request_version: Version, upstream_uri: &Uri) -> Version {
    if request_version == Version::HTTP_2
        && upstream_uri
            .scheme_str()
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https"))
    {
        return Version::HTTP_2;
    }
    Version::HTTP_11
}

fn rewrite_path(
    original_path: &str, original_query: Option<&str>, matched_path: Option<&crate::gateway_runtime::HttpPathMatchV1>,
    modifier: Option<&crate::gateway_runtime::HttpPathModifierV1>,
) -> String {
    let mut rewritten_path = original_path.to_string();
    if let Some(modifier) = modifier {
        match modifier.modifier_type {
            HttpPathModifierTypeV1::ReplaceFullPath => {
                if let Some(path) = modifier.replace_full_path.as_ref() {
                    rewritten_path = normalize_path(path);
                }
            }
            HttpPathModifierTypeV1::ReplacePrefixMatch => {
                if let Some(path) = modifier.replace_prefix_match.as_ref() {
                    let replacement = normalize_path(path);
                    if let Some(matched_path) = matched_path {
                        if matches!(
                            matched_path.match_type,
                            HttpPathMatchTypeV1::PathPrefix | HttpPathMatchTypeV1::Exact
                        ) && rewritten_path.starts_with(&matched_path.value)
                        {
                            rewritten_path = format!(
                                "{}{}",
                                replacement.trim_end_matches('/'),
                                &rewritten_path[matched_path.value.len()..]
                            );
                            if !rewritten_path.starts_with('/') {
                                rewritten_path.insert(0, '/');
                            }
                        }
                    }
                }
            }
        }
    }

    if let Some(query) = original_query
        && !query.is_empty()
    {
        return format!("{rewritten_path}?{query}");
    }
    rewritten_path
}

fn apply_header_modifier_to_request(headers: &mut HeaderMap, modifier: &HttpHeaderModifierV1) {
    for name in &modifier.remove {
        if let Ok(name) = HeaderName::from_str(name) {
            headers.remove(name);
        }
    }

    for mutation in &modifier.set {
        let Ok(name) = HeaderName::from_str(&mutation.name) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_str(&mutation.value) else {
            continue;
        };
        headers.insert(name, value);
    }

    for mutation in &modifier.add {
        let Ok(name) = HeaderName::from_str(&mutation.name) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_str(&mutation.value) else {
            continue;
        };
        headers.append(name, value);
    }
}

fn apply_header_modifier_to_response(headers: &mut HeaderMap, modifier: &HttpHeaderModifierV1) {
    for name in &modifier.remove {
        if let Ok(name) = HeaderName::from_str(name) {
            headers.remove(name);
        }
    }

    for mutation in &modifier.set {
        let Ok(name) = HeaderName::from_str(&mutation.name) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_str(&mutation.value) else {
            continue;
        };
        headers.insert(name, value);
    }

    for mutation in &modifier.add {
        let Ok(name) = HeaderName::from_str(&mutation.name) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_str(&mutation.value) else {
            continue;
        };
        headers.append(name, value);
    }
}

fn should_retry_status(retry: &crate::gateway_runtime::HttpRetryPolicyV1, status: StatusCode) -> bool {
    if retry.codes.is_empty() {
        return status.is_server_error();
    }
    retry.codes.iter().any(|code| *code == status.as_u16())
}

async fn request_with_timeout(
    client: &legacy::Client<HttpsConnector<HttpConnector>, BoxBody<Bytes, io::Error>>,
    req: Request<BoxBody<Bytes, io::Error>>, timeout_ms: Option<u64>,
) -> io::Result<Response<Incoming>> {
    if let Some(timeout_ms) = timeout_ms {
        let fut = client.request(req);
        let timed = tokio::time::timeout(Duration::from_millis(timeout_ms), fut)
            .await
            .map_err(|_| io::Error::new(ErrorKind::TimedOut, "upstream request timeout"))?;
        return timed.map_err(|err| io::Error::new(ErrorKind::InvalidData, err));
    }
    client
        .request(req)
        .await
        .map_err(|err| io::Error::new(ErrorKind::InvalidData, err))
}

fn normalize_redirect_response(
    original_scheme_host_port: &SchemeHostPort, resp_headers: &mut HeaderMap,
) -> Result<(), io::Error> {
    let Some(location_value) = resp_headers.get(LOCATION).cloned() else {
        return Ok(());
    };

    let location = location_value
        .to_str()
        .map_err(|err| io::Error::new(ErrorKind::InvalidData, err))?
        .parse::<Uri>()
        .map_err(|err| io::Error::new(ErrorKind::InvalidData, err))?;
    if location.scheme().is_none() {
        return Ok(());
    }

    let Some(redirect_host) = location.host() else {
        return Ok(());
    };
    if !redirect_host.ends_with(".svc.cluster.local") {
        return Ok(());
    }

    let path_and_query = location.path_and_query().map(|value| value.as_str()).unwrap_or("/");
    let authority = match original_scheme_host_port.port {
        Some(port) => format!("{}:{port}", original_scheme_host_port.host),
        None => original_scheme_host_port.host.clone(),
    };
    let normalized = format!("{}://{}{}", original_scheme_host_port.scheme, authority, path_and_query);
    let normalized = HeaderValue::from_str(&normalized).map_err(|err| io::Error::new(ErrorKind::InvalidData, err))?;
    resp_headers.insert(LOCATION, normalized);
    Ok(())
}

fn normalize_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn normalize_listeners(mut listeners: Vec<GatewayListenerConfig>) -> Vec<GatewayListenerConfig> {
    listeners.retain(|listener| listener.port != 0 && !listener.name.trim().is_empty());
    listeners.sort_by(|left, right| left.port.cmp(&right.port).then_with(|| left.name.cmp(&right.name)));
    listeners.dedup();
    listeners
}

fn full_body(bytes: Bytes) -> BoxBody<Bytes, io::Error> {
    Full::new(bytes).map_err(|never| match never {}).boxed()
}

fn empty_box_body() -> BoxBody<Bytes, io::Error> {
    full_body(Bytes::new())
}

fn box_request_body(req: Request<Incoming>) -> Request<BoxBody<Bytes, io::Error>> {
    req.map(|body| body.map_err(|err| io::Error::new(ErrorKind::InvalidData, err)).boxed())
}

fn map_response_body(resp: Response<Incoming>) -> Response<BoxBody<Bytes, io::Error>> {
    resp.map(|body| body.map_err(|err| io::Error::new(ErrorKind::InvalidData, err)).boxed())
}

fn build_hyper_legacy_client() -> legacy::Client<
    hyper_rustls::HttpsConnector<HttpConnector>,
    http_body_util::combinators::BoxBody<axum::body::Bytes, std::io::Error>,
> {
    let mut http_connector = HttpConnector::new();
    http_connector.enforce_http(false);

    #[cfg(debug_assertions)]
    let https_connector = {
        warn!("debug mode: TLS certificate verification is disabled for upstream requests");
        use tokio_rustls::rustls::ClientConfig;
        use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
        use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
        use tokio_rustls::rustls::{DigitallySignedStruct, SignatureScheme};

        #[derive(Debug)]
        struct NoVerifier;
        impl ServerCertVerifier for NoVerifier {
            fn verify_server_cert(
                &self, _end_entity: &CertificateDer<'_>, _intermediates: &[CertificateDer<'_>],
                _server_name: &ServerName<'_>, _ocsp_response: &[u8], _now: UnixTime,
            ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                vec![
                    SignatureScheme::RSA_PKCS1_SHA256,
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                    SignatureScheme::RSA_PSS_SHA256,
                    SignatureScheme::ED25519,
                ]
            }
        }

        let tls_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();

        HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_all_versions()
            .wrap_connector(http_connector)
    };

    #[cfg(not(debug_assertions))]
    let https_connector = HttpsConnectorBuilder::new()
        .with_platform_verifier()
        .https_or_http()
        .enable_all_versions()
        .wrap_connector(http_connector);

    legacy::Client::builder(TokioExecutor::new()).build(https_connector)
}

#[derive(Clone, Debug)]
pub(crate) struct SchemeHostPort {
    pub(crate) scheme: String,
    pub(crate) host: String,
    pub(crate) port: Option<u16>,
}

impl Display for SchemeHostPort {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.port {
            Some(port) => write!(f, "{}://{}:{}", self.scheme, self.host, port),
            None => write!(f, "{}://{}", self.scheme, self.host),
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct RequestDomain(String);

fn extract_scheme_host_port(
    req: &Request<Incoming>, default_scheme: &str,
) -> io::Result<(SchemeHostPort, RequestDomain)> {
    let uri = req.uri();
    let scheme = uri.scheme_str().unwrap_or(default_scheme);
    if req.version() == Version::HTTP_2 {
        let host_in_url = uri
            .host()
            .ok_or(io::Error::new(ErrorKind::InvalidData, "authority is absent in HTTP/2"))?
            .to_string();
        let host_in_header = req
            .headers()
            .get(HOST)
            .and_then(|host| host.to_str().ok())
            .and_then(|host_str| host_str.split(':').next())
            .map(str::to_string);
        Ok((
            SchemeHostPort {
                scheme: scheme.to_owned(),
                host: host_in_url.clone(),
                port: uri.port_u16(),
            },
            RequestDomain(host_in_header.unwrap_or(host_in_url)),
        ))
    } else {
        let host_header = req
            .headers()
            .get(HOST)
            .ok_or(io::Error::new(ErrorKind::InvalidData, "Host header is absent in HTTP/1.1"))?
            .to_str()
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        let mut split = host_header.split(':');
        let host = split
            .next()
            .ok_or(io::Error::new(ErrorKind::InvalidData, "host not in header"))?
            .to_string();
        let port = match split.next() {
            Some(port) => Some(
                port.parse::<u16>()
                    .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?,
            ),
            None => None,
        };
        Ok((
            SchemeHostPort {
                scheme: scheme.to_owned(),
                host: host.clone(),
                port,
            },
            RequestDomain(host),
        ))
    }
}

fn is_websocket_upgrade<B>(req: &Request<B>) -> bool {
    req.headers()
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

fn spawn_websocket_tunnel(
    client_upgrade: hyper::upgrade::OnUpgrade, upstream_upgrade: hyper::upgrade::OnUpgrade, scenario: &'static str,
) {
    tokio::spawn(async move {
        match (client_upgrade.await, upstream_upgrade.await) {
            (Ok(client_upgraded), Ok(upstream_upgraded)) => {
                let mut client_io = TokioIo::new(client_upgraded);
                let mut upstream_io = TokioIo::new(upstream_upgraded);
                if let Err(err) = tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io).await {
                    warn!("[{scenario}] websocket tunnel error: {err}");
                }
            }
            (Err(err), _) => warn!("[{scenario}] websocket client upgrade error: {err}"),
            (_, Err(err)) => warn!("[{scenario}] websocket upstream upgrade error: {err}"),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_upstream_version_forces_http11_on_http_uri() {
        let uri = Uri::from_static("http://svc.default.svc.cluster.local:80/");
        assert_eq!(normalize_upstream_version(Version::HTTP_2, &uri), Version::HTTP_11);
        assert_eq!(normalize_upstream_version(Version::HTTP_11, &uri), Version::HTTP_11);
    }

    #[test]
    fn normalize_upstream_version_keeps_http2_on_https_uri() {
        let uri = Uri::from_static("https://svc.default.svc.cluster.local:443/");
        assert_eq!(normalize_upstream_version(Version::HTTP_2, &uri), Version::HTTP_2);
        assert_eq!(normalize_upstream_version(Version::HTTP_11, &uri), Version::HTTP_11);
    }

    #[test]
    fn websocket_upgrade_header_is_detected_case_insensitively() {
        let req_result = Request::builder().header(UPGRADE, "WebSocket").body(());
        let req = match req_result {
            Ok(req) => req,
            Err(err) => panic!("build request failed: {err}"),
        };
        assert!(is_websocket_upgrade(&req));
    }

    #[test]
    fn websocket_upgrade_header_absent_is_not_websocket() {
        let req_result = Request::builder().body(());
        let req = match req_result {
            Ok(req) => req,
            Err(err) => panic!("build request failed: {err}"),
        };
        assert!(!is_websocket_upgrade(&req));
    }
}
