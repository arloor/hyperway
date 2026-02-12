use crate::DynError;
use crate::gateway_runtime::{GatewayListenerConfig, GatewayListenerTlsConfig, GatewayRuntime, GatewaySecretRef};
use crate::location::{DEFAULT_HOST, LocationConfig, LocationPathMatch, Upstream, Version};
use log::{info, warn};
use serde::Deserialize;
use serde_yaml_bw::Value;
use std::collections::HashMap;

#[derive(Clone, Debug, Default)]
pub(crate) struct GatewayApiParseOptions {
    pub(crate) controller_name: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct ObjectMeta {
    #[serde(default)]
    name: String,
    #[serde(default = "default_namespace")]
    namespace: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Gateway {
    metadata: ObjectMeta,
    #[serde(default)]
    spec: GatewaySpec,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GatewaySpec {
    #[serde(default)]
    gateway_class_name: Option<String>,
    #[serde(default)]
    listeners: Vec<GatewayListener>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GatewayListener {
    #[serde(default)]
    name: String,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    tls: Option<GatewayTlsConfig>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GatewayTlsConfig {
    #[serde(default)]
    certificate_refs: Vec<SecretRef>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecretRef {
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    name: String,
    #[serde(default)]
    namespace: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpRoute {
    metadata: ObjectMeta,
    #[serde(default)]
    spec: HttpRouteSpec,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpRouteSpec {
    #[serde(default)]
    parent_refs: Vec<ParentRef>,
    #[serde(default)]
    hostnames: Vec<String>,
    #[serde(default)]
    rules: Vec<HttpRouteRule>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ParentRef {
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    name: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    section_name: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpRouteRule {
    #[serde(default)]
    matches: Vec<HttpRouteMatch>,
    #[serde(default)]
    filters: Vec<HttpRouteFilter>,
    #[serde(default)]
    backend_refs: Vec<HttpBackendRef>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpRouteMatch {
    #[serde(default)]
    path: Option<HttpPathMatch>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpPathMatch {
    #[serde(rename = "type")]
    #[serde(default)]
    match_type: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpRouteFilter {
    #[serde(rename = "type")]
    #[serde(default)]
    filter_type: String,
    #[serde(default)]
    url_rewrite: Option<HttpUrlRewrite>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpUrlRewrite {
    #[serde(default)]
    path: Option<HttpPathModifier>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpPathModifier {
    #[serde(rename = "type")]
    #[serde(default)]
    modifier_type: String,
    #[serde(default)]
    replace_prefix_match: Option<String>,
    #[serde(default)]
    replace_full_path: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpBackendRef {
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    name: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    port: Option<u16>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GatewayClass {
    metadata: ObjectMeta,
    #[serde(default)]
    spec: GatewayClassSpec,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GatewayClassSpec {
    #[serde(default)]
    controller_name: String,
}

enum ParentBinding {
    Unspecified,
    MissingGateway,
    Matched { listener_hostnames: Vec<String> },
}

enum PathRewrite {
    Preserve,
    ReplacePrefix(String),
    ReplaceFull(String),
}

pub(crate) fn parse_gateway_api_runtime(
    path: &str, options: &GatewayApiParseOptions,
) -> Result<GatewayRuntime, DynError> {
    let content = std::fs::read_to_string(path)?;
    parse_gateway_api_runtime_from_str_with_options(&content, options)
}

#[cfg(test)]
fn parse_gateway_api_runtime_from_str(content: &str) -> Result<GatewayRuntime, DynError> {
    parse_gateway_api_runtime_from_str_with_options(content, &GatewayApiParseOptions::default())
}

pub(crate) fn parse_gateway_api_runtime_from_str_with_options(
    content: &str, options: &GatewayApiParseOptions,
) -> Result<GatewayRuntime, DynError> {
    let mut gateways = HashMap::<String, Gateway>::new();
    let mut gateway_classes = HashMap::<String, GatewayClass>::new();
    let mut routes = Vec::<HttpRoute>::new();

    for doc in serde_yaml_bw::Deserializer::from_str(content) {
        let value = Value::deserialize(doc)?;
        let kind = match value.get("kind").and_then(Value::as_str) {
            Some(kind) => kind,
            None => continue,
        };
        match kind {
            "Gateway" => {
                let gateway: Gateway = serde_yaml_bw::from_value(value)?;
                if gateway.metadata.name.is_empty() {
                    warn!("skip Gateway with empty metadata.name");
                    continue;
                }
                gateways.insert(gateway_key(&gateway.metadata.namespace, &gateway.metadata.name), gateway);
            }
            "GatewayClass" => {
                let gateway_class: GatewayClass = serde_yaml_bw::from_value(value)?;
                if gateway_class.metadata.name.is_empty() {
                    warn!("skip GatewayClass with empty metadata.name");
                    continue;
                }
                gateway_classes.insert(gateway_class.metadata.name.clone(), gateway_class);
            }
            "HTTPRoute" => {
                let route: HttpRoute = serde_yaml_bw::from_value(value)?;
                if route.metadata.name.is_empty() {
                    warn!("skip HTTPRoute with empty metadata.name");
                    continue;
                }
                routes.push(route);
            }
            _ => {}
        }
    }

    if let Some(controller_name) = options.controller_name.as_deref() {
        gateways.retain(|key, gateway| {
            let Some(gateway_class_name) = gateway.spec.gateway_class_name.as_deref() else {
                warn!("skip Gateway {key} because spec.gatewayClassName is empty");
                return false;
            };
            let Some(gateway_class) = gateway_classes.get(gateway_class_name) else {
                warn!("skip Gateway {key} because GatewayClass {gateway_class_name} is not found");
                return false;
            };
            if gateway_class.spec.controller_name != controller_name {
                info!(
                    "skip Gateway {key}: GatewayClass controllerName={} does not match {}",
                    gateway_class.spec.controller_name, controller_name
                );
                return false;
            }
            true
        });
    }

    let mut locations = HashMap::<String, Vec<LocationConfig>>::new();
    for route in routes {
        let route_namespace = route.metadata.namespace.clone();
        let parent_binding = resolve_parent_binding(&route, &gateways);
        if matches!(parent_binding, ParentBinding::MissingGateway) {
            warn!(
                "skip HTTPRoute {}/{} because no referenced Gateway exists in file",
                route_namespace, route.metadata.name
            );
            continue;
        }
        let hosts = resolve_hosts(&route, &parent_binding);
        for rule in &route.spec.rules {
            let backend = match pick_backend_ref(&route, rule) {
                Some(backend) => backend,
                None => continue,
            };
            let backend_base_url = backend_to_url_base(backend, &route_namespace);
            let rewrite = parse_path_rewrite(&route, rule);
            let matches = if rule.matches.is_empty() {
                vec![HttpRouteMatch::default()]
            } else {
                rule.matches.clone()
            };
            for path_match in matches {
                let (location, match_type) = parse_match_path(&route, path_match.path.as_ref());
                let upstream_path = match &rewrite {
                    PathRewrite::Preserve => location.clone(),
                    PathRewrite::ReplacePrefix(path) => path.clone(),
                    PathRewrite::ReplaceFull(path) => {
                        if match_type == LocationPathMatch::Exact {
                            path.clone()
                        } else {
                            warn!(
                                "HTTPRoute {}/{} uses ReplaceFullPath with non-Exact match {}, fallback to preserving path",
                                route_namespace, route.metadata.name, location
                            );
                            location.clone()
                        }
                    }
                };
                let upstream_url_base = join_url_base(&backend_base_url, &upstream_path);
                for host in &hosts {
                    locations
                        .entry(host.clone())
                        .or_default()
                        .push(LocationConfig::ReverseProxy {
                            location: location.clone(),
                            match_type,
                            upstream: Upstream {
                                url_base: upstream_url_base.clone(),
                                version: Version::Auto,
                                headers: None,
                            },
                        });
                }
            }
        }
    }

    let listeners = collect_gateway_listeners(&gateways);

    info!(
        "parsed Gateway API resources: gateways={}, host entries={}, listeners={}",
        gateways.len(),
        locations.len(),
        listeners.len()
    );
    Ok(GatewayRuntime { locations, listeners })
}

fn collect_gateway_listeners(gateways: &HashMap<String, Gateway>) -> Vec<GatewayListenerConfig> {
    let mut listeners = Vec::<GatewayListenerConfig>::new();
    for gateway in gateways.values() {
        for listener in &gateway.spec.listeners {
            let Some(port) = listener.port else {
                warn!(
                    "skip listener {}/{}:{} because port is empty",
                    gateway.metadata.namespace, gateway.metadata.name, listener.name
                );
                continue;
            };
            if port == 0 {
                warn!(
                    "skip listener {}/{}:{} because port is 0",
                    gateway.metadata.namespace, gateway.metadata.name, listener.name
                );
                continue;
            }

            let protocol = listener.protocol.as_deref().unwrap_or("HTTP");
            let tls = match protocol {
                "HTTP" => None,
                "HTTPS" | "TLS" => Some(parse_listener_tls(listener, gateway)),
                unknown => {
                    warn!(
                        "skip listener {}/{}:{} because protocol {} is unsupported",
                        gateway.metadata.namespace, gateway.metadata.name, listener.name, unknown
                    );
                    continue;
                }
            };

            let listener_name = if listener.name.is_empty() {
                format!("listener-{port}")
            } else {
                listener.name.clone()
            };
            listeners.push(GatewayListenerConfig {
                name: format!("{}/{}/{}", gateway.metadata.namespace, gateway.metadata.name, listener_name),
                port,
                tls,
            });
        }
    }

    listeners.sort_by(|left, right| left.port.cmp(&right.port).then_with(|| left.name.cmp(&right.name)));
    listeners.dedup();
    listeners
}

fn parse_listener_tls(listener: &GatewayListener, gateway: &Gateway) -> GatewayListenerTlsConfig {
    let mut certificate_refs = Vec::<GatewaySecretRef>::new();
    let refs = listener
        .tls
        .as_ref()
        .map(|tls| tls.certificate_refs.clone())
        .unwrap_or_default();

    for cert_ref in refs {
        let group = cert_ref.group.as_deref().unwrap_or_default();
        let kind = cert_ref.kind.as_deref().unwrap_or("Secret");
        if !group.is_empty() || kind != "Secret" {
            warn!(
                "skip listener certRef {}/{}:{} because only core Secret is supported",
                gateway.metadata.namespace, gateway.metadata.name, listener.name
            );
            continue;
        }
        if cert_ref.name.trim().is_empty() {
            warn!(
                "skip listener certRef {}/{}:{} because name is empty",
                gateway.metadata.namespace, gateway.metadata.name, listener.name
            );
            continue;
        }
        certificate_refs.push(GatewaySecretRef {
            namespace: cert_ref.namespace.unwrap_or_else(|| gateway.metadata.namespace.clone()),
            name: cert_ref.name,
        });
    }

    if certificate_refs.is_empty() {
        warn!(
            "listener {}/{}:{} enables TLS but has no usable certificateRefs",
            gateway.metadata.namespace, gateway.metadata.name, listener.name
        );
    }

    GatewayListenerTlsConfig {
        certificate_refs,
        cert_pem: None,
        key_pem: None,
    }
}

fn parse_match_path(route: &HttpRoute, path_match: Option<&HttpPathMatch>) -> (String, LocationPathMatch) {
    let mut path = path_match
        .and_then(|path| path.value.as_ref())
        .cloned()
        .unwrap_or_else(|| "/".to_string());
    if path.is_empty() {
        path = "/".to_string();
    }
    if !path.starts_with('/') {
        path = format!("/{path}");
    }

    let match_type = match path_match
        .and_then(|path| path.match_type.as_deref())
        .unwrap_or("PathPrefix")
    {
        "PathPrefix" => LocationPathMatch::Prefix,
        "Exact" => LocationPathMatch::Exact,
        unknown => {
            warn!(
                "HTTPRoute {}/{} path.type={} not supported, fallback to PathPrefix",
                route.metadata.namespace, route.metadata.name, unknown
            );
            LocationPathMatch::Prefix
        }
    };
    (path, match_type)
}

fn parse_path_rewrite(route: &HttpRoute, rule: &HttpRouteRule) -> PathRewrite {
    let Some(filter) = rule.filters.iter().find(|filter| filter.filter_type == "URLRewrite") else {
        return PathRewrite::Preserve;
    };

    let Some(path_modifier) = filter.url_rewrite.as_ref().and_then(|rewrite| rewrite.path.as_ref()) else {
        return PathRewrite::Preserve;
    };

    match path_modifier.modifier_type.as_str() {
        "ReplacePrefixMatch" => {
            let Some(path) = path_modifier.replace_prefix_match.as_ref() else {
                warn!(
                    "HTTPRoute {}/{} URLRewrite ReplacePrefixMatch missing replacePrefixMatch, ignore filter",
                    route.metadata.namespace, route.metadata.name
                );
                return PathRewrite::Preserve;
            };
            PathRewrite::ReplacePrefix(normalize_path(path))
        }
        "ReplaceFullPath" => {
            let Some(path) = path_modifier.replace_full_path.as_ref() else {
                warn!(
                    "HTTPRoute {}/{} URLRewrite ReplaceFullPath missing replaceFullPath, ignore filter",
                    route.metadata.namespace, route.metadata.name
                );
                return PathRewrite::Preserve;
            };
            PathRewrite::ReplaceFull(normalize_path(path))
        }
        unknown => {
            warn!(
                "HTTPRoute {}/{} URLRewrite path.type={} is unsupported, ignore filter",
                route.metadata.namespace, route.metadata.name, unknown
            );
            PathRewrite::Preserve
        }
    }
}

fn pick_backend_ref<'a>(route: &HttpRoute, rule: &'a HttpRouteRule) -> Option<&'a HttpBackendRef> {
    if rule.backend_refs.len() > 1 {
        warn!(
            "HTTPRoute {}/{} has multiple backendRefs, only the first supported Service backend is used",
            route.metadata.namespace, route.metadata.name
        );
    }
    let backend = rule
        .backend_refs
        .iter()
        .find(|backend| is_supported_service_backend(backend));
    if backend.is_none() {
        warn!(
            "HTTPRoute {}/{} has no supported Service backendRef, skip rule",
            route.metadata.namespace, route.metadata.name
        );
    }
    backend
}

fn is_supported_service_backend(backend: &HttpBackendRef) -> bool {
    let group = backend.group.as_deref().unwrap_or_default();
    let kind = backend.kind.as_deref().unwrap_or("Service");
    group.is_empty() && kind == "Service" && !backend.name.is_empty()
}

fn backend_to_url_base(backend: &HttpBackendRef, route_namespace: &str) -> String {
    let namespace = backend.namespace.as_deref().unwrap_or(route_namespace);
    let port = backend.port.unwrap_or(80);
    format!("http://{}.{}.svc.cluster.local:{port}", backend.name, namespace)
}

fn resolve_hosts(route: &HttpRoute, parent_binding: &ParentBinding) -> Vec<String> {
    let route_hosts = normalize_hosts(&route.spec.hostnames);
    if !route_hosts.is_empty() {
        return route_hosts;
    }
    match parent_binding {
        ParentBinding::Matched { listener_hostnames } if !listener_hostnames.is_empty() => listener_hostnames.clone(),
        _ => vec![DEFAULT_HOST.to_string()],
    }
}

fn resolve_parent_binding(route: &HttpRoute, gateways: &HashMap<String, Gateway>) -> ParentBinding {
    if route.spec.parent_refs.is_empty() {
        return ParentBinding::Unspecified;
    }

    let mut matched = false;
    let mut listener_hostnames = Vec::<String>::new();
    for parent_ref in &route.spec.parent_refs {
        if !is_gateway_parent_ref(parent_ref) {
            continue;
        }
        let gateway_namespace = parent_ref.namespace.as_deref().unwrap_or(&route.metadata.namespace);
        let key = gateway_key(gateway_namespace, &parent_ref.name);
        let Some(gateway) = gateways.get(&key) else {
            continue;
        };

        matched = true;
        if let Some(section_name) = parent_ref.section_name.as_deref() {
            for listener in &gateway.spec.listeners {
                if listener.name == section_name
                    && let Some(hostname) = listener.hostname.as_deref().and_then(normalize_hostname)
                {
                    listener_hostnames.push(hostname);
                }
            }
            continue;
        }
        for listener in &gateway.spec.listeners {
            if let Some(hostname) = listener.hostname.as_deref().and_then(normalize_hostname) {
                listener_hostnames.push(hostname);
            }
        }
    }

    if !matched {
        return ParentBinding::MissingGateway;
    }

    listener_hostnames.sort();
    listener_hostnames.dedup();
    ParentBinding::Matched { listener_hostnames }
}

fn is_gateway_parent_ref(parent_ref: &ParentRef) -> bool {
    let kind = parent_ref.kind.as_deref().unwrap_or("Gateway");
    let group = parent_ref.group.as_deref().unwrap_or("gateway.networking.k8s.io");
    kind == "Gateway" && group == "gateway.networking.k8s.io" && !parent_ref.name.is_empty()
}

fn gateway_key(namespace: &str, name: &str) -> String {
    format!("{namespace}/{name}")
}

fn normalize_hosts(hostnames: &[String]) -> Vec<String> {
    let mut normalized = hostnames
        .iter()
        .filter_map(|hostname| normalize_hostname(hostname))
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    normalized
}

fn normalize_hostname(hostname: &str) -> Option<String> {
    let normalized = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    Some(normalized)
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

fn join_url_base(base: &str, path: &str) -> String {
    let path = normalize_path(path);
    if path == "/" {
        if base.ends_with('/') {
            base.to_string()
        } else {
            format!("{base}/")
        }
    } else if base.ends_with('/') {
        format!("{base}{}", path.trim_start_matches('/'))
    } else {
        format!("{base}{path}")
    }
}

fn default_namespace() -> String {
    "default".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_httproute_with_gateway_listener_hostname() {
        let config = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: example
spec:
  controllerName: hyperway.arloor.dev/gateway-controller
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: demo
spec:
  listeners:
    - name: http
      port: 80
      protocol: HTTP
      hostname: app.example.com
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: app
  namespace: demo
spec:
  parentRefs:
    - name: edge
      sectionName: http
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /api
      backendRefs:
        - name: app-svc
          port: 8080
"#;
        let runtime = match parse_gateway_api_runtime_from_str(config) {
            Ok(runtime) => runtime,
            Err(err) => panic!("parse should succeed: {err}"),
        };
        assert_eq!(runtime.listeners.len(), 1);
        assert_eq!(runtime.listeners[0].port, 80);
        let host_locations = match runtime.locations.get("app.example.com") {
            Some(host_locations) => host_locations,
            None => panic!("host should exist"),
        };
        assert_eq!(host_locations.len(), 1);
        let LocationConfig::ReverseProxy {
            location,
            match_type,
            upstream,
        } = &host_locations[0];
        assert_eq!(location, "/api");
        assert_eq!(*match_type, LocationPathMatch::Prefix);
        assert_eq!(upstream.url_base, "http://app-svc.demo.svc.cluster.local:8080/api");
    }

    #[test]
    fn gateway_controller_name_filter_works() {
        let config = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: owned
spec:
  controllerName: hyperway.arloor.dev/gateway-controller
---
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: foreign
spec:
  controllerName: other-controller.example/gw
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: good-gw
  namespace: demo
spec:
  gatewayClassName: owned
  listeners:
    - name: http
      port: 80
      protocol: HTTP
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: bad-gw
  namespace: demo
spec:
  gatewayClassName: foreign
  listeners:
    - name: http
      port: 80
      protocol: HTTP
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: good-route
  namespace: demo
spec:
  parentRefs:
    - name: good-gw
  hostnames: ["good.example.com"]
  rules:
    - backendRefs:
        - name: svc-good
          port: 8080
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: bad-route
  namespace: demo
spec:
  parentRefs:
    - name: bad-gw
  hostnames: ["bad.example.com"]
  rules:
    - backendRefs:
        - name: svc-bad
          port: 8080
"#;
        let runtime = match parse_gateway_api_runtime_from_str_with_options(
            config,
            &GatewayApiParseOptions {
                controller_name: Some("hyperway.arloor.dev/gateway-controller".to_string()),
            },
        ) {
            Ok(runtime) => runtime,
            Err(err) => panic!("parse should succeed: {err}"),
        };
        assert!(runtime.locations.contains_key("good.example.com"));
        assert!(!runtime.locations.contains_key("bad.example.com"));
        assert_eq!(runtime.listeners.len(), 1);
    }

    #[test]
    fn parse_httproute_exact_match_and_full_path_rewrite() {
        let config = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: exact-rewrite
spec:
  hostnames:
    - exact.example.com
  rules:
    - matches:
        - path:
            type: Exact
            value: /old
      filters:
        - type: URLRewrite
          urlRewrite:
            path:
              type: ReplaceFullPath
              replaceFullPath: /new
      backendRefs:
        - name: exact-svc
          port: 9000
"#;
        let runtime = match parse_gateway_api_runtime_from_str(config) {
            Ok(runtime) => runtime,
            Err(err) => panic!("parse should succeed: {err}"),
        };
        let host_locations = match runtime.locations.get("exact.example.com") {
            Some(host_locations) => host_locations,
            None => panic!("host should exist"),
        };
        let LocationConfig::ReverseProxy {
            location,
            match_type,
            upstream,
        } = &host_locations[0];
        assert_eq!(location, "/old");
        assert_eq!(*match_type, LocationPathMatch::Exact);
        assert_eq!(upstream.url_base, "http://exact-svc.default.svc.cluster.local:9000/new");
    }

    #[test]
    fn parse_listener_tls_refs() {
        let config = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: demo
spec:
  listeners:
    - name: https
      port: 443
      protocol: HTTPS
      tls:
        certificateRefs:
          - name: edge-cert
"#;
        let runtime = match parse_gateway_api_runtime_from_str(config) {
            Ok(runtime) => runtime,
            Err(err) => panic!("parse should succeed: {err}"),
        };
        assert_eq!(runtime.listeners.len(), 1);
        let listener = &runtime.listeners[0];
        assert_eq!(listener.port, 443);
        let tls = match listener.tls.as_ref() {
            Some(tls) => tls,
            None => panic!("tls should exist"),
        };
        assert_eq!(tls.certificate_refs.len(), 1);
        assert_eq!(tls.certificate_refs[0].namespace, "demo");
        assert_eq!(tls.certificate_refs[0].name, "edge-cert");
    }
}
