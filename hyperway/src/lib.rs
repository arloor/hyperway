#![deny(warnings)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

mod axum_handler;
pub mod config;
mod gateway_api;
mod gateway_api_k8s;
mod gateway_api_snapshot_sync;
mod gateway_runtime;
mod metrics;
mod proxy;

pub use metrics::METRICS;

use crate::axum_handler::{AppProxyError, build_router};
use crate::config::{GatewayApiK8sSyncConfig, Param};
use crate::gateway_api_k8s::spawn_gateway_api_k8s_sync;
use crate::gateway_api_snapshot_sync::spawn_gateway_api_snapshot_sync;
use crate::proxy::ProxyHandler;

use axum::response::IntoResponse;
use axum_bootstrap::{InterceptResult, ReqInterceptor};
use config::load_config;
use futures_util::future::join_all;
use log::{error, info, warn};
use tokio::net::TcpListener;
use tokio::sync::broadcast::{self, Sender};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{
    self,
    crypto::CryptoProvider,
    pki_types::CertificateDer,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

use std::collections::{BTreeMap, HashMap};
use std::error::Error as StdError;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::io::BufReader;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tower::util::ServiceExt;

pub const IDLE_TIMEOUT: Duration = Duration::from_secs(if !cfg!(debug_assertions) { 600 } else { 60 });
const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

pub type DynError = Box<dyn StdError + Send + Sync>;

pub const BUILD_TIME: &str = build_time::build_time_local!("%Y-%m-%d %H:%M:%S %:z");

pub fn spawn_gateway_controller_snapshot_process(
    snapshot_namespace: String, snapshot_name: String, namespace: Option<String>, poll_interval: Duration,
    controller_name: String,
) {
    crate::gateway_api_k8s::spawn_gateway_api_k8s_sync_to_snapshot(
        snapshot_namespace,
        snapshot_name,
        Some(GatewayApiK8sSyncConfig {
            namespace,
            poll_interval,
            controller_name,
        }),
    );
}

#[derive(Clone)]
struct ProxyInterceptor {
    proxy_handler: Arc<ProxyHandler>,
    default_scheme: &'static str,
    listener_port: u16,
}

impl ReqInterceptor for ProxyInterceptor {
    type Error = AppProxyError;

    async fn intercept(
        &self, req: http::Request<hyper::body::Incoming>, ip: std::net::SocketAddr,
    ) -> InterceptResult<Self::Error> {
        match self
            .proxy_handler
            .handle(req, ip, self.default_scheme, self.listener_port)
            .await
        {
            Ok(result) => result.into(),
            Err(err) => {
                warn!("request handling error: {err}");
                InterceptResult::Error(AppProxyError::new(err))
            }
        }
    }
}

#[derive(Clone)]
struct ListenerTlsSniEntry {
    listener_name: String,
    listener_hostname: Option<String>,
    cert_pem: String,
    key_pem: String,
    fingerprint: String,
}

#[derive(Clone)]
struct ListenerTlsMultiMaterial {
    entries: Vec<ListenerTlsSniEntry>,
    fingerprint: String,
}

#[derive(Clone)]
enum DesiredTls {
    Multi(ListenerTlsMultiMaterial),
}

impl DesiredTls {
    fn fingerprint(&self) -> &str {
        match self {
            Self::Multi(material) => &material.fingerprint,
        }
    }
}

#[derive(Clone)]
struct DesiredListener {
    name: String,
    port: u16,
    tls: Option<DesiredTls>,
}

struct RunningListener {
    name: String,
    tls_fingerprint: Option<String>,
    shutdown_tx: Sender<()>,
    task: tokio::task::JoinHandle<Result<(), std::io::Error>>,
}

#[derive(Clone)]
struct ListenerTlsCandidate {
    listener_name: String,
    listener_hostname: Option<String>,
    cert_pem: String,
    key_pem: String,
}

#[derive(Clone, Debug)]
struct SniPatternMatcher<T: Clone> {
    exact: HashMap<String, T>,
    wildcard: Vec<(String, T)>,
    default: Option<T>,
}

impl<T: Clone> Default for SniPatternMatcher<T> {
    fn default() -> Self {
        Self {
            exact: HashMap::new(),
            wildcard: Vec::new(),
            default: None,
        }
    }
}

impl<T: Clone> SniPatternMatcher<T> {
    fn insert(&mut self, listener_hostname: Option<&str>, value: T) {
        match listener_hostname {
            Some("*") => {
                if self.default.is_none() {
                    self.default = Some(value);
                }
            }
            Some(hostname) => {
                if let Some(suffix) = hostname.strip_prefix("*.") {
                    self.wildcard.push((suffix.to_string(), value));
                } else {
                    self.exact.entry(hostname.to_string()).or_insert(value);
                }
            }
            None => {
                if self.default.is_none() {
                    self.default = Some(value);
                }
            }
        }
    }

    fn finalize(&mut self) {
        self.wildcard.sort_by(|left, right| right.0.len().cmp(&left.0.len()));
    }

    fn resolve(&self, server_name: Option<&str>) -> Option<T> {
        let normalized = server_name.and_then(normalize_hostname_for_sni);
        if let Some(ref hostname) = normalized {
            if let Some(value) = self.exact.get(hostname) {
                return Some(value.clone());
            }
            for (suffix, value) in &self.wildcard {
                if wildcard_suffix_matches(hostname, suffix) {
                    return Some(value.clone());
                }
            }
        }
        self.default.clone()
    }
}

#[derive(Debug)]
struct SniCertificateResolver {
    matcher: SniPatternMatcher<Arc<CertifiedKey>>,
}

impl SniCertificateResolver {
    fn from_entries(entries: &[ListenerTlsSniEntry], provider: &CryptoProvider) -> Result<Self, DynError> {
        let mut certified_keys = HashMap::<String, Arc<CertifiedKey>>::new();
        let mut matcher = SniPatternMatcher::<Arc<CertifiedKey>>::default();

        for entry in entries {
            let key = if let Some(key) = certified_keys.get(&entry.fingerprint) {
                key.clone()
            } else {
                let key = Arc::new(load_certified_key(&entry.cert_pem, &entry.key_pem, provider)?);
                certified_keys.insert(entry.fingerprint.clone(), key.clone());
                key
            };
            matcher.insert(entry.listener_hostname.as_deref(), key);
        }

        matcher.finalize();
        Ok(Self { matcher })
    }

    fn resolve_server_name(&self, server_name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        self.matcher.resolve(server_name)
    }
}

impl ResolvesServerCert for SniCertificateResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.resolve_server_name(client_hello.server_name())
    }
}

fn build_desired_listeners(proxy_handler: &Arc<ProxyHandler>) -> Result<BTreeMap<u16, DesiredListener>, DynError> {
    let listeners = proxy_handler.current_listeners()?;
    build_desired_listeners_from_configs(listeners)
}

fn tls_fingerprint(cert_pem: &str, key_pem: &str) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    cert_pem.hash(&mut hasher);
    key_pem.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn build_multi_tls_fingerprint(entries: &[ListenerTlsSniEntry]) -> String {
    let mut parts = entries
        .iter()
        .map(|entry| {
            format!(
                "{}:{}:{}",
                entry.fingerprint,
                entry.listener_name,
                entry.listener_hostname.clone().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>();
    parts.sort();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for part in parts {
        part.hash(&mut hasher);
    }
    format!("{:016x}", hasher.finish())
}

fn normalize_hostname_for_sni(hostname: &str) -> Option<String> {
    let normalized = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    Some(normalized)
}

fn wildcard_suffix_matches(hostname: &str, suffix: &str) -> bool {
    let required_suffix = format!(".{suffix}");
    hostname.len() > required_suffix.len() && hostname.ends_with(&required_suffix)
}

fn build_desired_listeners_from_configs(
    listeners: Vec<crate::gateway_runtime::GatewayListenerConfig>,
) -> Result<BTreeMap<u16, DesiredListener>, DynError> {
    let mut by_port = BTreeMap::<u16, Vec<crate::gateway_runtime::GatewayListenerConfig>>::new();
    for listener in listeners {
        by_port.entry(listener.port).or_default().push(listener);
    }

    let mut desired = BTreeMap::<u16, DesiredListener>::new();
    for (port, listeners_on_port) in by_port {
        let mut plain_names = Vec::<String>::new();
        let mut tls_names = Vec::<String>::new();
        let mut tls_candidates = Vec::<ListenerTlsCandidate>::new();

        for listener in listeners_on_port {
            match listener.tls.as_ref() {
                None => {
                    plain_names.push(listener.name);
                }
                Some(tls) => {
                    let cert_pem = match tls.cert_pem.as_ref() {
                        Some(cert) if !cert.trim().is_empty() => cert.clone(),
                        _ => {
                            warn!("skip TLS listener {} on port {}: cert_pem not resolved yet", listener.name, port);
                            continue;
                        }
                    };
                    let key_pem = match tls.key_pem.as_ref() {
                        Some(key) if !key.trim().is_empty() => key.clone(),
                        _ => {
                            warn!("skip TLS listener {} on port {}: key_pem not resolved yet", listener.name, port);
                            continue;
                        }
                    };
                    tls_names.push(listener.name.clone());
                    tls_candidates.push(ListenerTlsCandidate {
                        listener_name: listener.name,
                        listener_hostname: listener.hostname.as_deref().and_then(normalize_hostname_for_sni),
                        cert_pem,
                        key_pem,
                    });
                }
            }
        }

        if plain_names.is_empty() && tls_candidates.is_empty() {
            continue;
        }

        if !plain_names.is_empty() && !tls_candidates.is_empty() {
            let all_names = plain_names
                .iter()
                .chain(tls_names.iter())
                .cloned()
                .collect::<Vec<_>>()
                .join(",");
            warn!(
                "skip listeners on port {} because HTTP and HTTPS listeners cannot share the same port in current runtime: {}",
                port, all_names
            );
            continue;
        }

        if !tls_candidates.is_empty() {
            let mut entries = tls_candidates
                .into_iter()
                .map(|candidate| ListenerTlsSniEntry {
                    listener_name: candidate.listener_name,
                    listener_hostname: candidate.listener_hostname,
                    fingerprint: tls_fingerprint(&candidate.cert_pem, &candidate.key_pem),
                    cert_pem: candidate.cert_pem,
                    key_pem: candidate.key_pem,
                })
                .collect::<Vec<_>>();
            entries.sort_by(|left, right| left.listener_name.cmp(&right.listener_name));
            let tls = Some(DesiredTls::Multi(ListenerTlsMultiMaterial {
                fingerprint: build_multi_tls_fingerprint(&entries),
                entries,
            }));
            let mut names = tls_names;
            names.sort();
            names.dedup();
            desired.insert(
                port,
                DesiredListener {
                    name: names.join(","),
                    port,
                    tls,
                },
            );
            continue;
        }

        let mut names = plain_names;
        names.sort();
        names.dedup();
        desired.insert(
            port,
            DesiredListener {
                name: names.join(","),
                port,
                tls: None,
            },
        );
    }

    Ok(desired)
}

fn load_certified_key(cert_pem: &str, key_pem: &str, provider: &CryptoProvider) -> Result<CertifiedKey, DynError> {
    let mut cert_reader = BufReader::new(cert_pem.as_bytes());
    let cert_chain = rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<CertificateDer<'static>>, _>>()?;
    if cert_chain.is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "tls cert chain is empty").into());
    }

    let mut key_reader = BufReader::new(key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "tls private key is empty"))?;

    Ok(CertifiedKey::from_der(cert_chain, key, provider)?)
}

fn build_multi_tls_server_config(entries: &[ListenerTlsSniEntry]) -> Result<Arc<rustls::ServerConfig>, DynError> {
    if entries.is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "multi-cert tls entries are empty").into());
    }

    let builder = rustls::ServerConfig::builder().with_no_client_auth();
    let provider = builder.crypto_provider().clone();
    let resolver = Arc::new(SniCertificateResolver::from_entries(entries, provider.as_ref())?);
    let mut config = builder.with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn bind_listener(port: u16) -> Result<TcpListener, std::io::Error> {
    let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;

    #[cfg(not(windows))]
    socket.set_reuse_address(true)?;

    socket.set_only_v6(false)?;
    let addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, port));
    socket.bind(&addr.into())?;
    socket.listen(1024)?;

    let std_listener = std::net::TcpListener::from(socket);
    std_listener.set_nonblocking(true)?;
    TcpListener::from_std(std_listener)
}

async fn handle_listener_request(
    request: http::Request<hyper::body::Incoming>, client_socket_addr: SocketAddr, app: axum::Router,
    interceptor: ProxyInterceptor,
) -> Result<axum::response::Response, std::io::Error> {
    match interceptor.intercept(request, client_socket_addr).await {
        InterceptResult::Return(response) => Ok(response),
        InterceptResult::Drop => Err(std::io::Error::other("Request dropped by interceptor")),
        InterceptResult::Continue(request) => Ok(unwrap_infallible(app.oneshot(request).await)),
        InterceptResult::Error(err) => Ok(err.into_response()),
    }
}

async fn run_multi_cert_tls_listener(
    port: u16, tls: ListenerTlsMultiMaterial, interceptor: ProxyInterceptor, mut shutdown_rx: broadcast::Receiver<()>,
) -> Result<(), std::io::Error> {
    let tls_config = build_multi_tls_server_config(&tls.entries)
        .map_err(|err| std::io::Error::other(format!("build multi-cert tls config failed: {err}")))?;
    let acceptor = TlsAcceptor::from(tls_config);
    let listener = bind_listener(port)?;
    let server = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    let app = build_router();

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                info!("start graceful shutdown!");
                drop(listener);
                break;
            }
            incoming = listener.accept() => {
                match incoming {
                    Ok((stream, client_socket_addr)) => {
                        let acceptor = acceptor.clone();
                        let server = server.clone();
                        let app = app.clone();
                        let interceptor = interceptor.clone();
                        let watcher = graceful.watcher();
                        tokio::spawn(async move {
                            let tls_stream = match acceptor.accept(stream).await {
                                Ok(tls_stream) => tls_stream,
                                Err(err) => {
                                    warn!("TLS handshake failed from {}: {}", client_socket_addr, err);
                                    return;
                                }
                            };
                            use hyper::Request;
                            use hyper_util::rt::TokioIo;
                            let stream = TokioIo::new(tls_stream);
                            let hyper_service = hyper::service::service_fn(move |request: Request<hyper::body::Incoming>| {
                                handle_listener_request(request, client_socket_addr, app.clone(), interceptor.clone())
                            });
                            let conn = server.serve_connection_with_upgrades(stream, hyper_service);
                            let conn = watcher.watch(conn.into_owned());
                            if let Err(err) = conn.await {
                                warn!("HTTPS connection error from {}: {}", client_socket_addr, err);
                            }
                        });
                    }
                    Err(err) => {
                        warn!("accept error: {}", err);
                    }
                }
            }
        }
    }

    match tokio::time::timeout(GRACEFUL_SHUTDOWN_TIMEOUT, graceful.shutdown()).await {
        Ok(_) => info!("Gracefully shutdown!"),
        Err(_) => info!("Waited {:?} for graceful shutdown, aborting...", GRACEFUL_SHUTDOWN_TIMEOUT),
    }
    Ok(())
}

fn unwrap_infallible<T>(result: Result<T, std::convert::Infallible>) -> T {
    match result {
        Ok(value) => value,
        Err(err) => match err {},
    }
}

fn spawn_listener_task(
    desired: &DesiredListener, proxy_handler: Arc<ProxyHandler>, global_shutdown_tx: Sender<()>,
) -> RunningListener {
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let tls_fingerprint = desired.tls.as_ref().map(|tls| tls.fingerprint().to_string());

    let port = desired.port;
    let name = desired.name.clone();

    if let Some(DesiredTls::Multi(tls)) = desired.tls.as_ref() {
        let tls = tls.clone();
        let interceptor = ProxyInterceptor {
            proxy_handler,
            default_scheme: "https",
            listener_port: desired.port,
        };
        let task = tokio::spawn(async move {
            let result = run_multi_cert_tls_listener(port, tls, interceptor, shutdown_rx).await;
            match &result {
                Ok(()) => info!("listener {name} on port {port} exited gracefully"),
                Err(err) => {
                    error!("listener {name} on port {port} exited with error: {err}");
                    let _ = global_shutdown_tx.send(());
                }
            }
            result
        });

        return RunningListener {
            name: desired.name.clone(),
            tls_fingerprint,
            shutdown_tx,
            task,
        };
    }

    let server = axum_bootstrap::new_server(desired.port, build_router(), shutdown_rx)
        .with_timeout(IDLE_TIMEOUT)
        .with_interceptor(ProxyInterceptor {
            proxy_handler,
            default_scheme: "http",
            listener_port: desired.port,
        });

    let task = tokio::spawn(async move {
        let result = server.run().await;
        match &result {
            Ok(()) => info!("listener {name} on port {port} exited gracefully"),
            Err(err) => {
                error!("listener {name} on port {port} exited with error: {err}");
                let _ = global_shutdown_tx.send(());
            }
        }
        result
    });

    RunningListener {
        name: desired.name.clone(),
        tls_fingerprint,
        shutdown_tx,
        task,
    }
}

async fn stop_listener(running: RunningListener) -> Result<(), std::io::Error> {
    let _ = running.shutdown_tx.send(());
    match running.task.await {
        Ok(result) => result,
        Err(err) => Err(std::io::Error::other(format!("listener task join error for {}: {err}", running.name))),
    }
}

async fn run_listener_manager(
    proxy_handler: Arc<ProxyHandler>, shutdown_tx: Sender<()>,
) -> Vec<Result<(), std::io::Error>> {
    let mut shutdown_rx = shutdown_tx.subscribe();
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut running = HashMap::<u16, RunningListener>::new();
    let mut results = Vec::<Result<(), std::io::Error>>::new();

    loop {
        tokio::select! {
            _ = interval.tick() => {
                METRICS.listener_reconcile_total.inc();
                let desired = match build_desired_listeners(&proxy_handler) {
                    Ok(desired) => desired,
                    Err(err) => {
                        warn!("build desired listeners failed: {err}");
                        continue;
                    }
                };

                let mut ports_to_stop = Vec::<u16>::new();
                for (port, running_listener) in &running {
                    if running_listener.task.is_finished() {
                        ports_to_stop.push(*port);
                        continue;
                    }
                    let Some(desired_listener) = desired.get(port) else {
                        ports_to_stop.push(*port);
                        continue;
                    };
                    let desired_fp = desired_listener.tls.as_ref().map(|tls| tls.fingerprint().to_string());
                    if running_listener.tls_fingerprint != desired_fp {
                        ports_to_stop.push(*port);
                    }
                }

                for port in ports_to_stop {
                    if let Some(running_listener) = running.remove(&port) {
                        match stop_listener(running_listener).await {
                            Ok(()) => info!("listener on port {port} stopped"),
                            Err(err) => results.push(Err(err)),
                        }
                    }
                }

                for (port, desired_listener) in desired {
                    if running.contains_key(&port) {
                        continue;
                    }
                    let running_listener = spawn_listener_task(&desired_listener, proxy_handler.clone(), shutdown_tx.clone());
                    info!(
                        "listener started: name={}, port={}, tls={}",
                        desired_listener.name,
                        desired_listener.port,
                        if desired_listener.tls.is_some() { "enabled" } else { "disabled" }
                    );
                    running.insert(port, running_listener);
                }
            }
            recv = shutdown_rx.recv() => {
                if recv.is_ok() {
                    info!("received shutdown signal, stopping listeners");
                }
                break;
            }
        }
    }

    let mut shutdown_futures = Vec::new();
    for (_, running_listener) in running {
        shutdown_futures.push(stop_listener(running_listener));
    }
    for result in join_all(shutdown_futures).await {
        results.push(result);
    }

    if results.is_empty() {
        results.push(Ok(()));
    }
    results
}

#[allow(clippy::type_complexity)]
pub fn create_futures(
    param: Param,
) -> Result<(impl Future<Output = Vec<Result<(), std::io::Error>>>, Sender<()>), DynError> {
    let config = Arc::new(load_config(param)?);
    let proxy_handler = Arc::new(ProxyHandler::new(config.clone())?);

    spawn_gateway_api_k8s_sync(proxy_handler.clone(), config.gateway_api_k8s_sync.clone());
    spawn_gateway_api_snapshot_sync(proxy_handler.clone(), config.gateway_api_snapshot_sync.clone());

    let (shutdown_tx, _) = broadcast::channel(4);
    let manager_future = run_listener_manager(proxy_handler, shutdown_tx.clone());

    Ok((manager_future, shutdown_tx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway_runtime::{GatewayListenerConfig, GatewayListenerTlsConfig};
    use std::net::{Ipv6Addr, SocketAddr};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::{ClientConfig, RootCertStore, pki_types::ServerName};

    fn generate_self_signed_cert(hostname: &str) -> (String, String, Vec<u8>) {
        let cert = match rcgen::generate_simple_self_signed(vec![hostname.to_string()]) {
            Ok(cert) => cert,
            Err(err) => panic!("generate self-signed cert should succeed: {err}"),
        };
        let cert_pem = cert.cert.pem();
        let cert_der = cert.cert.der().to_vec();
        let key_pem = cert.key_pair.serialize_pem();
        (cert_pem, key_pem, cert_der)
    }

    async fn fetch_server_cert_der(
        addr: SocketAddr, server_name: &str, trusted_roots: &[Vec<u8>],
    ) -> Result<Vec<u8>, std::io::Error> {
        let mut root_store = RootCertStore::empty();
        for root in trusted_roots {
            root_store
                .add(CertificateDer::from(root.clone()))
                .map_err(|err| std::io::Error::other(format!("add root cert failed: {err}")))?;
        }
        let client_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));

        let stream = TcpStream::connect(addr).await?;
        let server_name = ServerName::try_from(server_name.to_string()).map_err(|err| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("invalid server name: {err}"))
        })?;
        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|err| std::io::Error::other(format!("TLS client connect failed: {err}")))?;
        let certs = tls_stream
            .get_ref()
            .1
            .peer_certificates()
            .ok_or_else(|| std::io::Error::other("peer certificate list is empty"))?;
        let cert = certs
            .first()
            .ok_or_else(|| std::io::Error::other("peer certificate list has no end-entity cert"))?;
        Ok(cert.as_ref().to_vec())
    }

    fn plain_listener(name: &str, port: u16) -> GatewayListenerConfig {
        GatewayListenerConfig {
            name: name.to_string(),
            port,
            hostname: None,
            tls: None,
        }
    }

    fn tls_listener(name: &str, port: u16, hostname: Option<&str>, cert: &str, key: &str) -> GatewayListenerConfig {
        GatewayListenerConfig {
            name: name.to_string(),
            port,
            hostname: hostname.map(ToString::to_string),
            tls: Some(GatewayListenerTlsConfig {
                certificate_refs: Vec::new(),
                cert_pem: Some(cert.to_string()),
                key_pem: Some(key.to_string()),
            }),
        }
    }

    #[test]
    fn same_port_http_listeners_are_merged() {
        let listeners = vec![
            plain_listener("default/gw/http-a", 80),
            plain_listener("default/gw/http-b", 80),
        ];
        let desired = match build_desired_listeners_from_configs(listeners) {
            Ok(desired) => desired,
            Err(err) => panic!("build desired listeners should succeed: {err}"),
        };
        assert_eq!(desired.len(), 1);
        let listener = match desired.get(&80) {
            Some(listener) => listener,
            None => panic!("listener on port 80 should exist"),
        };
        assert!(listener.tls.is_none());
        assert_eq!(listener.name, "default/gw/http-a,default/gw/http-b");
    }

    #[test]
    fn same_port_tls_listeners_with_same_cert_are_merged() {
        let listeners = vec![
            tls_listener("default/gw/https-a", 443, Some("a.example.com"), "cert-1", "key-1"),
            tls_listener("default/gw/https-b", 443, Some("b.example.com"), "cert-1", "key-1"),
        ];
        let desired = match build_desired_listeners_from_configs(listeners) {
            Ok(desired) => desired,
            Err(err) => panic!("build desired listeners should succeed: {err}"),
        };
        assert_eq!(desired.len(), 1);
        let listener = match desired.get(&443) {
            Some(listener) => listener,
            None => panic!("listener on port 443 should exist"),
        };
        match listener.tls.as_ref() {
            Some(DesiredTls::Multi(material)) => assert_eq!(material.entries.len(), 2),
            _ => panic!("listener should use multi-cert tls material"),
        }
    }

    #[test]
    fn same_port_http_and_https_are_rejected() {
        let listeners = vec![
            plain_listener("default/gw/http", 8443),
            tls_listener("default/gw/https", 8443, None, "cert-1", "key-1"),
        ];
        let desired = match build_desired_listeners_from_configs(listeners) {
            Ok(desired) => desired,
            Err(err) => panic!("build desired listeners should succeed: {err}"),
        };
        assert!(desired.is_empty());
    }

    #[test]
    fn same_port_tls_with_different_cert_use_multi_cert_sni() {
        let listeners = vec![
            tls_listener("default/gw/https-a", 443, Some("a.example.com"), "cert-1", "key-1"),
            tls_listener("default/gw/https-b", 443, Some("b.example.com"), "cert-2", "key-2"),
        ];
        let desired = match build_desired_listeners_from_configs(listeners) {
            Ok(desired) => desired,
            Err(err) => panic!("build desired listeners should succeed: {err}"),
        };
        assert_eq!(desired.len(), 1);
        let listener = match desired.get(&443) {
            Some(listener) => listener,
            None => panic!("listener on port 443 should exist"),
        };
        match listener.tls.as_ref() {
            Some(DesiredTls::Multi(material)) => assert_eq!(material.entries.len(), 2),
            _ => panic!("listener should use multi-cert tls material"),
        }
    }

    #[test]
    fn sni_pattern_matcher_prefers_exact_then_wildcard_then_default() {
        let mut matcher = SniPatternMatcher::<&str>::default();
        matcher.insert(Some("*.example.com"), "wildcard");
        matcher.insert(Some("api.example.com"), "exact");
        matcher.insert(None, "default");
        matcher.finalize();

        assert_eq!(matcher.resolve(Some("api.example.com")), Some("exact"));
        assert_eq!(matcher.resolve(Some("foo.example.com")), Some("wildcard"));
        assert_eq!(matcher.resolve(Some("unknown.test")), Some("default"));
        assert_eq!(matcher.resolve(None), Some("default"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multi_cert_tls_selects_certificate_by_sni() {
        let (cert_a_pem, key_a_pem, cert_a_der) = generate_self_signed_cert("a.example.com");
        let (cert_b_pem, key_b_pem, cert_b_der) = generate_self_signed_cert("b.example.com");
        let entries = vec![
            ListenerTlsSniEntry {
                listener_name: "default/gw/https-a".to_string(),
                listener_hostname: Some("a.example.com".to_string()),
                cert_pem: cert_a_pem,
                key_pem: key_a_pem,
                fingerprint: tls_fingerprint("cert-a", "key-a"),
            },
            ListenerTlsSniEntry {
                listener_name: "default/gw/https-b".to_string(),
                listener_hostname: Some("b.example.com".to_string()),
                cert_pem: cert_b_pem,
                key_pem: key_b_pem,
                fingerprint: tls_fingerprint("cert-b", "key-b"),
            },
        ];
        let server_config = match build_multi_tls_server_config(&entries) {
            Ok(config) => config,
            Err(err) => panic!("build multi-cert tls config should succeed: {err}"),
        };
        let acceptor = TlsAcceptor::from(server_config);
        let listener = match bind_listener(0) {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                return;
            }
            Err(err) => panic!("bind test listener should succeed: {err}"),
        };
        let port = match listener.local_addr() {
            Ok(addr) => addr.port(),
            Err(err) => panic!("read test listener addr should succeed: {err}"),
        };
        let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
        let server_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await?;
                acceptor
                    .accept(stream)
                    .await
                    .map_err(|err| std::io::Error::other(format!("server TLS accept failed: {err}")))?;
            }
            Ok::<(), std::io::Error>(())
        });

        let trusted_roots = vec![cert_a_der.clone(), cert_b_der.clone()];
        let selected_a = match fetch_server_cert_der(addr, "a.example.com", &trusted_roots).await {
            Ok(cert) => cert,
            Err(err) => panic!("client handshake for a.example.com should succeed: {err}"),
        };
        assert_eq!(selected_a, cert_a_der);

        let selected_b = match fetch_server_cert_der(addr, "b.example.com", &trusted_roots).await {
            Ok(cert) => cert,
            Err(err) => panic!("client handshake for b.example.com should succeed: {err}"),
        };
        assert_eq!(selected_b, cert_b_der);

        let server_result = match server_task.await {
            Ok(result) => result,
            Err(err) => panic!("server task join should succeed: {err}"),
        };
        if let Err(err) = server_result {
            panic!("server task should complete successfully: {err}");
        }
    }
}
