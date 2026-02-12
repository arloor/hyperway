use crate::DynError;
use crate::config::GatewayApiSnapshotSyncConfig;
use crate::gateway_runtime::GatewayRuntime;
use crate::proxy::ProxyHandler;
use http::header::{ACCEPT, AUTHORIZATION};
use http::{Method, Request, Uri};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Bytes;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use log::{info, warn};
use serde_json::Value;
use std::sync::Arc;
use tokio::time::MissedTickBehavior;
use tokio_rustls::rustls::RootCertStore;

type K8sClient = legacy::Client<HttpsConnector<HttpConnector>, Full<Bytes>>;
const SNAPSHOT_API_GROUP: &str = "hyperway.arloor.dev";
const SNAPSHOT_API_VERSION: &str = "v1alpha1";
const SNAPSHOT_RESOURCE: &str = "routesnapshots";

pub(crate) fn spawn_gateway_api_snapshot_sync(
    proxy_handler: Arc<ProxyHandler>, sync_config: Option<GatewayApiSnapshotSyncConfig>,
) {
    let Some(sync_config) = sync_config else {
        return;
    };

    tokio::spawn(async move {
        let context = match SnapshotApiContext::new(sync_config.clone()) {
            Ok(context) => context,
            Err(err) => {
                warn!("failed to initialize Gateway API snapshot sync: {err}");
                return;
            }
        };
        info!(
            "Gateway API snapshot sync started, namespace={}, name={}, interval={:?}",
            sync_config.namespace, sync_config.name, sync_config.poll_interval
        );

        let mut snapshot_missing_logged = false;
        match sync_once(&proxy_handler, &context).await {
            Ok(SnapshotSyncState::Missing) => {
                warn!("RouteSnapshot {}/{} does not exist yet", context.namespace, context.name);
                snapshot_missing_logged = true;
            }
            Ok(SnapshotSyncState::Unchanged) => {}
            Ok(SnapshotSyncState::Applied {
                location_count,
                listener_count,
            }) => {
                info!(
                    "Gateway API snapshot sync applied from {}/{}, locations={}, listeners={}",
                    context.namespace, context.name, location_count, listener_count
                );
                snapshot_missing_logged = false;
            }
            Err(err) => {
                warn!("initial Gateway API snapshot sync failed: {err}");
            }
        }

        let mut interval = tokio::time::interval(sync_config.poll_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            match sync_once(&proxy_handler, &context).await {
                Ok(SnapshotSyncState::Missing) => {
                    if !snapshot_missing_logged {
                        warn!("RouteSnapshot {}/{} does not exist yet", context.namespace, context.name);
                        snapshot_missing_logged = true;
                    }
                }
                Ok(SnapshotSyncState::Unchanged) => {}
                Ok(SnapshotSyncState::Applied {
                    location_count,
                    listener_count,
                }) => {
                    info!(
                        "Gateway API snapshot sync applied from {}/{}, locations={}, listeners={}",
                        context.namespace, context.name, location_count, listener_count
                    );
                    snapshot_missing_logged = false;
                }
                Err(err) => {
                    warn!("failed to sync RouteSnapshot {}/{}: {err}", context.namespace, context.name);
                }
            }
        }
    });
}

enum SnapshotSyncState {
    Missing,
    Unchanged,
    Applied {
        location_count: usize,
        listener_count: usize,
    },
}

async fn sync_once(
    proxy_handler: &Arc<ProxyHandler>, context: &SnapshotApiContext,
) -> Result<SnapshotSyncState, DynError> {
    let Some(snapshot_value) = context.fetch_snapshot().await? else {
        return Ok(SnapshotSyncState::Missing);
    };
    let spec_value = snapshot_value
        .get("spec")
        .ok_or_else(|| "snapshot.spec is missing".to_string())?;

    let checksum = spec_value.get("checksum").map(normalize_checksum_value);
    if let (Some(new_checksum), Ok(guard)) = (checksum.as_ref(), context.cached_checksum.lock())
        && guard
            .as_ref()
            .is_some_and(|cached_checksum| cached_checksum == new_checksum)
    {
        return Ok(SnapshotSyncState::Unchanged);
    }

    let runtime = parse_runtime_from_snapshot_spec(spec_value)?;
    let apply_stats = proxy_handler.replace_gateway_runtime(runtime)?;

    if let Ok(mut guard) = context.cached_checksum.lock() {
        *guard = checksum;
    }

    Ok(SnapshotSyncState::Applied {
        location_count: apply_stats.location_count,
        listener_count: apply_stats.listener_count,
    })
}

fn parse_runtime_from_snapshot_spec(spec_value: &Value) -> Result<GatewayRuntime, DynError> {
    let locations = match spec_value.get("locations") {
        Some(locations) => serde_json::from_value(locations.clone()).map_err(|err| {
            format!(
                "parse snapshot.spec.locations failed: {err}; check RouteSnapshot CRD schema keeps locations fields (x-kubernetes-preserve-unknown-fields)"
            )
        })?,
        None => Default::default(),
    };

    let listeners = match spec_value.get("listeners") {
        Some(listeners) => serde_json::from_value(listeners.clone())
            .map_err(|err| format!("parse snapshot.spec.listeners failed: {err}"))?,
        None => Vec::new(),
    };

    Ok(GatewayRuntime { locations, listeners })
}

struct SnapshotApiContext {
    base_url: String,
    token: String,
    namespace: String,
    name: String,
    client: K8sClient,
    cached_checksum: std::sync::Mutex<Option<String>>,
}

impl SnapshotApiContext {
    fn new(config: GatewayApiSnapshotSyncConfig) -> Result<Self, DynError> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST")?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".to_string());
        let base_url = format!("https://{host}:{port}");

        let token = std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token")?
            .trim()
            .to_string();
        let ca_pem = std::fs::read("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")?;
        let client = build_k8s_client(ca_pem)?;

        Ok(Self {
            base_url,
            token,
            namespace: config.namespace.trim().to_string(),
            name: config.name,
            client,
            cached_checksum: std::sync::Mutex::new(None),
        })
    }

    async fn fetch_snapshot(&self) -> Result<Option<Value>, DynError> {
        let path = build_snapshot_path(&self.namespace, &self.name);
        let uri = format!("{}{}", self.base_url, path).parse::<Uri>()?;
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .body(Full::new(Bytes::new()))?;
        let resp = self.client.request(req).await?;
        let status = resp.status();
        let bytes = resp.into_body().collect().await?.to_bytes();
        if status == http::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            let body = String::from_utf8_lossy(&bytes);
            return Err(format!("request {} failed: {} {}", path, status, body).into());
        }
        let value: Value = serde_json::from_slice(&bytes)?;
        Ok(Some(value))
    }
}

fn build_snapshot_path(namespace: &str, name: &str) -> String {
    format!("/apis/{SNAPSHOT_API_GROUP}/{SNAPSHOT_API_VERSION}/namespaces/{namespace}/{SNAPSHOT_RESOURCE}/{name}")
}

fn build_k8s_client(ca_pem: Vec<u8>) -> Result<K8sClient, DynError> {
    let mut root_store = RootCertStore::empty();
    let mut reader = std::io::BufReader::new(ca_pem.as_slice());
    for cert in rustls_pemfile::certs(&mut reader) {
        let cert = cert?;
        root_store.add(cert)?;
    }
    let tls_config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let mut http_connector = HttpConnector::new();
    http_connector.enforce_http(false);
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_only()
        .enable_http1()
        .wrap_connector(http_connector);
    Ok(legacy::Client::builder(TokioExecutor::new()).build(https))
}

fn normalize_checksum_value(value: &Value) -> String {
    if let Some(checksum) = value.as_str() {
        return checksum.to_string();
    }
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_path() {
        assert_eq!(
            build_snapshot_path("demo", "default"),
            "/apis/hyperway.arloor.dev/v1alpha1/namespaces/demo/routesnapshots/default"
        );
    }
}
