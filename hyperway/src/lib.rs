#![deny(warnings)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

mod axum_handler;
pub mod config;
mod gateway_api;
mod gateway_api_k8s;
mod gateway_api_snapshot_sync;
mod gateway_runtime;
mod location;
mod metrics;
mod proxy;

pub use metrics::METRICS;

use crate::axum_handler::{AppProxyError, build_router};
use crate::config::{GatewayApiK8sSyncConfig, Param};
use crate::gateway_api_k8s::spawn_gateway_api_k8s_sync;
use crate::gateway_api_snapshot_sync::spawn_gateway_api_snapshot_sync;
use crate::proxy::ProxyHandler;

use axum_bootstrap::{InterceptResult, ReqInterceptor, TlsParam};
use config::load_config;
use futures_util::future::join_all;
use log::{error, info, warn};
use tokio::sync::broadcast::{self, Sender};

use std::collections::{BTreeMap, HashMap};
use std::error::Error as StdError;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;

pub const IDLE_TIMEOUT: Duration = Duration::from_secs(if !cfg!(debug_assertions) { 600 } else { 60 });

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
}

impl ReqInterceptor for ProxyInterceptor {
    type Error = AppProxyError;

    async fn intercept(
        &self, req: http::Request<hyper::body::Incoming>, ip: std::net::SocketAddr,
    ) -> InterceptResult<Self::Error> {
        match self.proxy_handler.handle(req, ip, self.default_scheme).await {
            Ok(result) => result.into(),
            Err(err) => {
                warn!("request handling error: {err}");
                InterceptResult::Error(AppProxyError::new(err))
            }
        }
    }
}

#[derive(Clone)]
struct ListenerTlsMaterial {
    cert_path: String,
    key_path: String,
    fingerprint: String,
}

#[derive(Clone)]
struct DesiredListener {
    name: String,
    port: u16,
    tls: Option<ListenerTlsMaterial>,
}

struct RunningListener {
    name: String,
    tls_fingerprint: Option<String>,
    shutdown_tx: Sender<()>,
    task: tokio::task::JoinHandle<Result<(), std::io::Error>>,
}

fn build_desired_listeners(proxy_handler: &Arc<ProxyHandler>) -> Result<BTreeMap<u16, DesiredListener>, DynError> {
    let listeners = proxy_handler.current_listeners()?;
    let mut selected = BTreeMap::<u16, crate::gateway_runtime::GatewayListenerConfig>::new();

    for listener in listeners {
        if let Some(existing) = selected.get(&listener.port) {
            warn!(
                "multiple listeners share port {}, keep {} and ignore {}",
                listener.port, existing.name, listener.name
            );
            continue;
        }
        selected.insert(listener.port, listener);
    }

    let mut desired = BTreeMap::<u16, DesiredListener>::new();
    for (port, listener) in selected {
        let tls = if let Some(tls_config) = listener.tls.as_ref() {
            let cert_pem = match tls_config.cert_pem.as_ref() {
                Some(cert) if !cert.trim().is_empty() => cert,
                _ => {
                    warn!("skip TLS listener {} on port {}: cert_pem not resolved yet", listener.name, port);
                    continue;
                }
            };
            let key_pem = match tls_config.key_pem.as_ref() {
                Some(key) if !key.trim().is_empty() => key,
                _ => {
                    warn!("skip TLS listener {} on port {}: key_pem not resolved yet", listener.name, port);
                    continue;
                }
            };
            Some(materialize_tls_files(&listener.name, port, cert_pem, key_pem)?)
        } else {
            None
        };
        desired.insert(
            port,
            DesiredListener {
                name: listener.name,
                port,
                tls,
            },
        );
    }

    Ok(desired)
}

fn materialize_tls_files(
    listener_name: &str, port: u16, cert_pem: &str, key_pem: &str,
) -> Result<ListenerTlsMaterial, DynError> {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    cert_pem.hash(&mut hasher);
    key_pem.hash(&mut hasher);
    let fingerprint = format!("{:016x}", hasher.finish());

    let base_dir = std::path::Path::new("/tmp/hyperway/tls");
    std::fs::create_dir_all(base_dir)?;

    let sanitized_name = sanitize_listener_name(listener_name);
    let cert_path = base_dir.join(format!("{port}-{sanitized_name}-{fingerprint}.crt.pem"));
    let key_path = base_dir.join(format!("{port}-{sanitized_name}-{fingerprint}.key.pem"));

    std::fs::write(&cert_path, cert_pem)?;
    std::fs::write(&key_path, key_pem)?;

    Ok(ListenerTlsMaterial {
        cert_path: cert_path.to_string_lossy().to_string(),
        key_path: key_path.to_string_lossy().to_string(),
        fingerprint,
    })
}

fn sanitize_listener_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() { "listener".to_string() } else { out }
}

fn spawn_listener_task(
    desired: &DesiredListener, proxy_handler: Arc<ProxyHandler>, global_shutdown_tx: Sender<()>,
) -> RunningListener {
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

    let tls_param = desired.tls.as_ref().map(|tls| TlsParam {
        tls: true,
        cert: tls.cert_path.clone(),
        key: tls.key_path.clone(),
    });
    let default_scheme = if tls_param.is_some() { "https" } else { "http" };

    let server = axum_bootstrap::new_server(desired.port, build_router(), shutdown_rx)
        .with_timeout(IDLE_TIMEOUT)
        .with_tls_param(tls_param)
        .with_interceptor(ProxyInterceptor {
            proxy_handler,
            default_scheme,
        });

    let port = desired.port;
    let name = desired.name.clone();
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
        tls_fingerprint: desired.tls.as_ref().map(|tls| tls.fingerprint.clone()),
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
                    let desired_fp = desired_listener.tls.as_ref().map(|tls| tls.fingerprint.clone());
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
