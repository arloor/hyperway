use crate::DynError;
use crate::config::GatewayApiK8sSyncConfig;
use crate::gateway_api::{GatewayApiParseOptions, parse_gateway_api_runtime_from_str_with_options};
use crate::gateway_runtime::{GatewayClassStatusV1, GatewayListenerStatusV1, GatewayRuntime, RouteParentDiagnosticV1};
use crate::proxy::ProxyHandler;
use base64::Engine;
use chrono::{SecondsFormat, Utc};
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use http::{Method, Request, Uri};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Bytes;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use log::{info, warn};
use serde::Deserialize;
use serde_json::Value;
use serde_json::json;
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::time::MissedTickBehavior;
use tokio_rustls::rustls::RootCertStore;

type K8sClient = legacy::Client<HttpsConnector<HttpConnector>, Full<Bytes>>;
const WATCH_TIMEOUT_SECONDS: u32 = 300;
const WATCH_RECONNECT_DELAY: Duration = Duration::from_secs(2);
const SNAPSHOT_API_GROUP: &str = "hyperway.arloor.dev";
const SNAPSHOT_API_VERSION: &str = "v1alpha1";
const SNAPSHOT_RESOURCE: &str = "routesnapshots";

#[derive(Clone)]
enum SyncTarget {
    Proxy(Arc<ProxyHandler>),
    SnapshotCrd(SnapshotCrdTarget),
}

#[derive(Clone)]
struct SnapshotCrdTarget {
    namespace: String,
    name: String,
    cached_hash: Arc<std::sync::Mutex<Option<u64>>>,
}

#[derive(Clone, Copy)]
struct SnapshotStatusCounts {
    route_rule_count: u64,
    listener_count: u64,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ObjectMeta {
    #[serde(default)]
    name: String,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    generation: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GatewayClassSpec {
    #[serde(default)]
    controller_name: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GatewayClassResource {
    #[serde(default)]
    metadata: ObjectMeta,
    #[serde(default)]
    spec: GatewayClassSpec,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GatewaySpec {
    #[serde(default)]
    gateway_class_name: Option<String>,
    #[serde(default)]
    addresses: Vec<GatewayAddressSpec>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GatewayAddressSpec {
    #[serde(rename = "type")]
    #[serde(default)]
    address_type: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GatewayResource {
    #[serde(default)]
    metadata: ObjectMeta,
    #[serde(default)]
    spec: GatewaySpec,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpRouteResource {
    #[serde(default)]
    metadata: ObjectMeta,
}

struct GatewayApiSnapshot {
    gateway_classes_raw: Vec<Value>,
    gateways_raw: Vec<Value>,
    http_routes_raw: Vec<Value>,
    namespaces_raw: Vec<Value>,
    services_raw: Vec<Value>,
    reference_grants_raw: Vec<Value>,
    gateway_classes: Vec<GatewayClassResource>,
    gateways: Vec<GatewayResource>,
    http_routes: Vec<HttpRouteResource>,
}

impl GatewayApiSnapshot {
    fn to_documents(&self) -> Result<String, DynError> {
        let mut docs = String::new();
        for item in self
            .gateway_classes_raw
            .iter()
            .chain(self.gateways_raw.iter())
            .chain(self.http_routes_raw.iter())
            .chain(self.namespaces_raw.iter())
            .chain(self.services_raw.iter())
            .chain(self.reference_grants_raw.iter())
        {
            docs.push_str("---\n");
            docs.push_str(&serde_yaml_bw::to_string(item)?);
        }
        Ok(docs)
    }
}

pub(crate) fn spawn_gateway_api_k8s_sync(
    proxy_handler: Arc<ProxyHandler>, sync_config: Option<GatewayApiK8sSyncConfig>,
) {
    spawn_gateway_api_k8s_sync_with_target(SyncTarget::Proxy(proxy_handler), sync_config);
}

pub(crate) fn spawn_gateway_api_k8s_sync_to_snapshot(
    snapshot_namespace: String, snapshot_name: String, sync_config: Option<GatewayApiK8sSyncConfig>,
) {
    spawn_gateway_api_k8s_sync_with_target(
        SyncTarget::SnapshotCrd(SnapshotCrdTarget {
            namespace: snapshot_namespace.trim().to_string(),
            name: snapshot_name,
            cached_hash: Arc::new(std::sync::Mutex::new(None)),
        }),
        sync_config,
    );
}

fn spawn_gateway_api_k8s_sync_with_target(sync_target: SyncTarget, sync_config: Option<GatewayApiK8sSyncConfig>) {
    let Some(sync_config) = sync_config else {
        return;
    };

    tokio::spawn(async move {
        let context = match K8sApiContext::new(sync_config.clone()) {
            Ok(context) => context,
            Err(err) => {
                warn!("failed to initialize Kubernetes Gateway API sync: {err}");
                return;
            }
        };
        info!(
            "Kubernetes Gateway API sync started, namespace={:?}, interval={:?}, target={}",
            sync_config.namespace,
            sync_config.poll_interval,
            describe_sync_target(&sync_target)
        );

        if let Err(err) = sync_once(&sync_target, &context).await {
            warn!("initial Gateway API sync failed: {err}");
        }

        let (watch_event_tx, watch_event_rx) = mpsc::channel::<WatchSignal>(64);
        spawn_watch_loop(context.clone(), "gatewayclasses", WatchScope::Cluster, watch_event_tx.clone());
        spawn_watch_loop(context.clone(), "gateways", WatchScope::Namespaced, watch_event_tx.clone());
        spawn_watch_loop(context.clone(), "httproutes", WatchScope::Namespaced, watch_event_tx);

        let mut watch_event_rx = Some(watch_event_rx);
        let mut interval = tokio::time::interval(sync_config.poll_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            if let Some(rx) = watch_event_rx.as_mut() {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(err) = sync_once(&sync_target, &context).await {
                            warn!("failed to sync Gateway API from Kubernetes by periodic tick: {err}");
                        }
                    }
                    watch_event = rx.recv() => {
                        match watch_event {
                            Some(mut event) => {
                                while let Some(receiver) = watch_event_rx.as_mut() {
                                    match receiver.try_recv() {
                                        Ok(extra_event) => event = extra_event,
                                        Err(TryRecvError::Empty) => break,
                                        Err(TryRecvError::Disconnected) => {
                                            watch_event_rx = None;
                                            break;
                                        }
                                    }
                                }
                                info!(
                                    "received Gateway API watch event: resource={}, type={}",
                                    event.resource, event.event_type
                                );
                                if let Err(err) = sync_once(&sync_target, &context).await {
                                    warn!("failed to sync Gateway API from Kubernetes by watch event: {err}");
                                }
                            }
                            None => {
                                warn!("watch event channel closed unexpectedly, fallback to periodic sync only");
                                watch_event_rx = None;
                            }
                        }
                    }
                }
            } else {
                interval.tick().await;
                if let Err(err) = sync_once(&sync_target, &context).await {
                    warn!("failed to sync Gateway API from Kubernetes by periodic tick: {err}");
                }
            }
        }
    });
}

#[derive(Clone, Copy)]
enum WatchScope {
    Cluster,
    Namespaced,
}

#[derive(Debug)]
struct WatchSignal {
    resource: &'static str,
    event_type: String,
}

#[derive(Debug, Deserialize)]
struct WatchEvent {
    #[serde(rename = "type")]
    event_type: String,
}

async fn sync_once(sync_target: &SyncTarget, context: &K8sApiContext) -> Result<(), DynError> {
    let snapshot = context.fetch_gateway_api_snapshot().await?;
    let documents = snapshot.to_documents()?;
    let mut runtime = parse_gateway_api_runtime_from_str_with_options(
        &documents,
        &GatewayApiParseOptions {
            controller_name: Some(context.controller_name.clone()),
        },
    )?;
    context.resolve_listener_tls(&mut runtime).await?;
    let apply_stats = apply_sync_target(sync_target, context, runtime.clone()).await?;
    info!(
        "Kubernetes Gateway API sync applied, route_rules={}, listeners={}, gateways={}, httproutes={}",
        apply_stats.route_count,
        apply_stats.listener_count,
        snapshot.gateways.len(),
        snapshot.http_routes.len()
    );
    if let Err(err) = context.sync_controller_status(&snapshot, &runtime).await {
        warn!("failed to patch Gateway API status: {err}");
    }
    Ok(())
}

async fn apply_sync_target(
    sync_target: &SyncTarget, context: &K8sApiContext, runtime: GatewayRuntime,
) -> Result<crate::proxy::GatewayRuntimeApplyStats, DynError> {
    match sync_target {
        SyncTarget::Proxy(proxy_handler) => proxy_handler.replace_gateway_runtime(runtime),
        SyncTarget::SnapshotCrd(snapshot_target) => {
            let hash = hash_gateway_runtime(&runtime)?;
            if let Ok(guard) = snapshot_target.cached_hash.lock()
                && guard.is_some_and(|cached_hash| cached_hash == hash)
            {
                return Ok(crate::proxy::GatewayRuntimeApplyStats {
                    route_count: runtime.http_routes_v1.len(),
                    listener_count: runtime.listeners.len(),
                });
            }
            context.upsert_route_snapshot(snapshot_target, &runtime).await?;
            if let Ok(mut guard) = snapshot_target.cached_hash.lock() {
                *guard = Some(hash);
            }
            Ok(crate::proxy::GatewayRuntimeApplyStats {
                route_count: runtime.http_routes_v1.len(),
                listener_count: runtime.listeners.len(),
            })
        }
    }
}

fn describe_sync_target(sync_target: &SyncTarget) -> String {
    match sync_target {
        SyncTarget::Proxy(_) => "proxy-memory".to_string(),
        SyncTarget::SnapshotCrd(snapshot_target) => {
            format!("snapshot:{}/{}", snapshot_target.namespace, snapshot_target.name)
        }
    }
}

fn spawn_watch_loop(
    context: K8sApiContext, resource: &'static str, scope: WatchScope, watch_event_tx: mpsc::Sender<WatchSignal>,
) {
    tokio::spawn(async move {
        loop {
            match context.watch_resource(resource, scope, &watch_event_tx).await {
                Ok(()) => {
                    warn!("watch stream ended: resource={resource}");
                }
                Err(err) => {
                    warn!("watch stream error: resource={resource}, err={err}");
                }
            }
            tokio::time::sleep(WATCH_RECONNECT_DELAY).await;
        }
    });
}

#[derive(Clone)]
struct K8sApiContext {
    base_url: String,
    token: String,
    namespace: Option<String>,
    controller_name: String,
    condition_transition_time: String,
    client: K8sClient,
}

impl K8sApiContext {
    fn new(config: GatewayApiK8sSyncConfig) -> Result<Self, DynError> {
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
            namespace: normalize_namespace(config.namespace),
            controller_name: config.controller_name,
            condition_transition_time: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            client,
        })
    }

    async fn fetch_gateway_api_snapshot(&self) -> Result<GatewayApiSnapshot, DynError> {
        let gateway_classes_raw = self.fetch_cluster_resource_items("gatewayclasses").await?;
        let gateways_raw = self.fetch_resource_items("gateways").await?;
        let http_routes_raw = self.fetch_resource_items("httproutes").await?;
        let namespaces_raw = self
            .fetch_core_cluster_resource_items("namespaces")
            .await
            .unwrap_or_else(|err| {
                warn!("fetch namespaces failed: {err}");
                Vec::new()
            });
        let services_raw = self.fetch_core_resource_items("services").await.unwrap_or_else(|err| {
            warn!("fetch services failed: {err}");
            Vec::new()
        });
        let reference_grants_raw = self
            .fetch_gateway_resource_items_with_fallback(
                "referencegrants",
                self.namespace.as_deref(),
                &["v1", "v1beta1", "v1alpha2"],
            )
            .await
            .unwrap_or_else(|err| {
                warn!("fetch referencegrants failed: {err}");
                Vec::new()
            });

        Ok(GatewayApiSnapshot {
            gateway_classes: parse_k8s_items("gatewayclasses", &gateway_classes_raw)?,
            gateways: parse_k8s_items("gateways", &gateways_raw)?,
            http_routes: parse_k8s_items("httproutes", &http_routes_raw)?,
            gateway_classes_raw,
            gateways_raw,
            http_routes_raw,
            namespaces_raw,
            services_raw,
            reference_grants_raw,
        })
    }

    async fn fetch_resource_items(&self, resource: &str) -> Result<Vec<Value>, DynError> {
        self.fetch_items_by_path(&self.resource_path(resource)).await
    }

    fn resource_path(&self, resource: &str) -> String {
        build_resource_path(self.namespace.as_deref(), resource)
    }

    async fn fetch_cluster_resource_items(&self, resource: &str) -> Result<Vec<Value>, DynError> {
        self.fetch_items_by_path(&build_cluster_resource_path(resource)).await
    }

    async fn fetch_core_resource_items(&self, resource: &str) -> Result<Vec<Value>, DynError> {
        self.fetch_items_by_path(&build_core_resource_path(self.namespace.as_deref(), resource))
            .await
    }

    async fn fetch_core_cluster_resource_items(&self, resource: &str) -> Result<Vec<Value>, DynError> {
        self.fetch_items_by_path(&build_core_cluster_resource_path(resource))
            .await
    }

    async fn fetch_gateway_resource_items_with_fallback(
        &self, resource: &str, namespace: Option<&str>, versions: &[&str],
    ) -> Result<Vec<Value>, DynError> {
        let mut last_err = None::<DynError>;
        for version in versions {
            let path = build_gateway_resource_path_by_version(namespace, resource, version);
            match self.fetch_items_by_path(&path).await {
                Ok(items) => return Ok(items),
                Err(err) => {
                    last_err = Some(err);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| format!("no available gateway api version for resource {resource}").into()))
    }

    async fn fetch_items_by_path(&self, path: &str) -> Result<Vec<Value>, DynError> {
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
        if !status.is_success() {
            let body = String::from_utf8_lossy(&bytes);
            return Err(format!("request {} failed: {} {}", path, status, body).into());
        }
        let value: Value = serde_json::from_slice(&bytes)?;
        let items = value
            .get("items")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("invalid kubernetes list response at {}", path))?;
        Ok(items.clone())
    }

    async fn fetch_object_by_path(&self, path: &str) -> Result<Value, DynError> {
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
        if !status.is_success() {
            let body = String::from_utf8_lossy(&bytes);
            return Err(format!("request {} failed: {} {}", path, status, body).into());
        }
        Ok(serde_json::from_slice(&bytes)?)
    }

    async fn resolve_listener_tls(&self, runtime: &mut GatewayRuntime) -> Result<(), DynError> {
        let mut cache = HashMap::<(String, String), (String, String)>::new();
        for listener in &mut runtime.listeners {
            let Some(tls) = listener.tls.as_mut() else {
                continue;
            };
            if tls.cert_pem.is_some() && tls.key_pem.is_some() {
                continue;
            }
            let Some(cert_ref) = tls.certificate_refs.first() else {
                continue;
            };
            let cache_key = (cert_ref.namespace.clone(), cert_ref.name.clone());
            let (cert_pem, key_pem) = if let Some(cached) = cache.get(&cache_key) {
                cached.clone()
            } else {
                let loaded = match self.fetch_tls_secret(&cert_ref.namespace, &cert_ref.name).await {
                    Ok(loaded) => loaded,
                    Err(err) => {
                        warn!(
                            "resolve tls secret failed for listener {} -> {}/{}: {}",
                            listener.name, cert_ref.namespace, cert_ref.name, err
                        );
                        continue;
                    }
                };
                cache.insert(cache_key.clone(), loaded.clone());
                loaded
            };
            tls.cert_pem = Some(cert_pem);
            tls.key_pem = Some(key_pem);
        }
        Ok(())
    }

    async fn fetch_tls_secret(&self, namespace: &str, name: &str) -> Result<(String, String), DynError> {
        let path = format!("/api/v1/namespaces/{namespace}/secrets/{name}");
        let secret = self.fetch_object_by_path(&path).await?;

        let data = secret
            .get("data")
            .and_then(Value::as_object)
            .ok_or_else(|| format!("secret {namespace}/{name} has no data field"))?;
        let cert_b64 = data
            .get("tls.crt")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("secret {namespace}/{name} missing data['tls.crt']"))?;
        let key_b64 = data
            .get("tls.key")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("secret {namespace}/{name} missing data['tls.key']"))?;

        let cert_pem = base64::engine::general_purpose::STANDARD
            .decode(cert_b64)
            .map_err(|err| format!("decode tls.crt for secret {namespace}/{name} failed: {err}"))?;
        let key_pem = base64::engine::general_purpose::STANDARD
            .decode(key_b64)
            .map_err(|err| format!("decode tls.key for secret {namespace}/{name} failed: {err}"))?;

        let cert_pem = String::from_utf8(cert_pem)
            .map_err(|err| format!("tls.crt in secret {namespace}/{name} is not valid utf-8 PEM: {err}"))?;
        let key_pem = String::from_utf8(key_pem)
            .map_err(|err| format!("tls.key in secret {namespace}/{name} is not valid utf-8 PEM: {err}"))?;
        Ok((cert_pem, key_pem))
    }

    async fn upsert_route_snapshot(
        &self, target: &SnapshotCrdTarget, runtime: &GatewayRuntime,
    ) -> Result<(), DynError> {
        let namespace = target.namespace.trim();
        let name = target.name.trim();
        if namespace.is_empty() {
            return Err("snapshot namespace cannot be empty".into());
        }
        if name.is_empty() {
            return Err("snapshot name cannot be empty".into());
        }
        let checksum_hash = hash_gateway_runtime(runtime)?;
        let checksum = format_checksum(checksum_hash);
        let counts = SnapshotStatusCounts {
            route_rule_count: runtime.http_routes_v1.len() as u64,
            listener_count: runtime.listeners.len() as u64,
        };
        let payload = json!({
            "apiVersion": format!("{SNAPSHOT_API_GROUP}/{SNAPSHOT_API_VERSION}"),
            "kind": "RouteSnapshot",
            "metadata": {
                "name": name,
                "namespace": namespace,
            },
            "spec": {
                "controllerName": self.controller_name,
                "updatedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
                "checksum": checksum,
                "listeners": &runtime.listeners,
                "httpRoutesV1": &runtime.http_routes_v1,
                "routeDiagnostics": &runtime.route_diagnostics,
                "gatewayListenerStatuses": &runtime.gateway_listener_statuses,
                "gatewayClassStatuses": &runtime.gateway_class_statuses,
            }
        });
        let item_path = build_snapshot_item_path(namespace, name);
        let upserted_snapshot = if let Some(snapshot) = self.patch_resource_by_path(&item_path, &payload).await? {
            snapshot
        } else {
            let collection_path = build_snapshot_collection_path(namespace);
            if let Some(snapshot) = self.create_resource_by_path(&collection_path, &payload).await? {
                snapshot
            } else if let Some(snapshot) = self.patch_resource_by_path(&item_path, &payload).await? {
                snapshot
            } else {
                return Err(format!("failed to upsert snapshot {namespace}/{name}").into());
            }
        };

        let observed_generation = upserted_snapshot
            .get("metadata")
            .and_then(|metadata| metadata.get("generation"))
            .and_then(Value::as_u64);
        if let Err(err) = self
            .patch_snapshot_status(namespace, name, observed_generation, &checksum, counts)
            .await
        {
            warn!("failed to patch snapshot status for {namespace}/{name}: {err}");
        }
        Ok(())
    }

    async fn patch_resource_by_path(&self, path: &str, payload: &Value) -> Result<Option<Value>, DynError> {
        let uri = format!("{}{}", self.base_url, path).parse::<Uri>()?;
        let body = serde_json::to_vec(payload)?;
        let req = Request::builder()
            .method(Method::PATCH)
            .uri(uri)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/merge-patch+json")
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .body(Full::new(Bytes::from(body)))?;
        let resp = self.client.request(req).await?;
        let status = resp.status();
        let bytes = resp.into_body().collect().await?.to_bytes();
        if status == http::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            let body = String::from_utf8_lossy(&bytes);
            return Err(format!("patch {} failed: {} {}", path, status, body).into());
        }
        Ok(Some(serde_json::from_slice(&bytes)?))
    }

    async fn create_resource_by_path(&self, path: &str, payload: &Value) -> Result<Option<Value>, DynError> {
        let uri = format!("{}{}", self.base_url, path).parse::<Uri>()?;
        let body = serde_json::to_vec(payload)?;
        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .body(Full::new(Bytes::from(body)))?;
        let resp = self.client.request(req).await?;
        let status = resp.status();
        let bytes = resp.into_body().collect().await?.to_bytes();
        if status == http::StatusCode::CONFLICT {
            return Ok(None);
        }
        if !status.is_success() {
            let body = String::from_utf8_lossy(&bytes);
            return Err(format!("create {} failed: {} {}", path, status, body).into());
        }
        Ok(Some(serde_json::from_slice(&bytes)?))
    }

    async fn patch_snapshot_status(
        &self, namespace: &str, name: &str, observed_generation: Option<u64>, checksum: &str,
        counts: SnapshotStatusCounts,
    ) -> Result<(), DynError> {
        let mut status = json!({
            "lastSyncedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            "lastAppliedChecksum": checksum,
            "routeRuleCount": counts.route_rule_count,
            "listenerCount": counts.listener_count,
            "conditions": [self.status_condition(
                "Ready",
                "True",
                "Synced",
                "RouteSnapshot has been updated from Gateway API resources",
                observed_generation
            )]
        });
        if let Some(generation) = observed_generation {
            status["observedGeneration"] = Value::Number(generation.into());
        }
        let payload = json!({ "status": status });
        self.patch_status_by_path(&build_snapshot_status_path(namespace, name), payload)
            .await
    }

    async fn watch_resource(
        &self, resource: &'static str, scope: WatchScope, watch_event_tx: &mpsc::Sender<WatchSignal>,
    ) -> Result<(), DynError> {
        let path = match scope {
            WatchScope::Cluster => build_cluster_resource_path(resource),
            WatchScope::Namespaced => build_resource_path(self.namespace.as_deref(), resource),
        };
        let watch_path = build_watch_path(&path);
        let uri = format!("{}{}", self.base_url, watch_path).parse::<Uri>()?;
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .body(Full::new(Bytes::new()))?;
        let resp = self.client.request(req).await?;
        let status = resp.status();
        if !status.is_success() {
            let bytes = resp.into_body().collect().await?.to_bytes();
            let body = String::from_utf8_lossy(&bytes);
            return Err(format!("watch request {} failed: {} {}", watch_path, status, body).into());
        }

        let mut body = resp.into_body();
        let mut pending = String::new();
        while let Some(frame) = body.frame().await {
            let frame = frame?;
            let Some(data) = frame.data_ref() else {
                continue;
            };
            pending.push_str(std::str::from_utf8(data)?);
            while let Some(newline_pos) = pending.find('\n') {
                let line = pending[..newline_pos].trim().to_owned();
                pending.drain(..=newline_pos);
                handle_watch_line(resource, &line, watch_event_tx);
            }
        }
        let tail = pending.trim();
        if !tail.is_empty() {
            handle_watch_line(resource, tail, watch_event_tx);
        }
        Ok(())
    }

    async fn sync_controller_status(
        &self, snapshot: &GatewayApiSnapshot, runtime: &GatewayRuntime,
    ) -> Result<(), DynError> {
        let runtime_gateway_class_statuses = runtime
            .gateway_class_statuses
            .iter()
            .map(|status| (status.name.clone(), status))
            .collect::<HashMap<_, _>>();

        let owned_gateway_classes = snapshot
            .gateway_classes
            .iter()
            .filter(|gateway_class| gateway_class.spec.controller_name == self.controller_name)
            .filter_map(|gateway_class| {
                if gateway_class.metadata.name.is_empty() {
                    None
                } else {
                    Some(gateway_class.metadata.name.clone())
                }
            })
            .collect::<HashSet<_>>();

        for gateway_class in snapshot
            .gateway_classes
            .iter()
            .filter(|gateway_class| owned_gateway_classes.contains(&gateway_class.metadata.name))
        {
            self.patch_gateway_class_status(
                gateway_class,
                runtime_gateway_class_statuses
                    .get(&gateway_class.metadata.name)
                    .copied(),
            )
            .await?;
        }

        let mut listener_statuses_by_gateway = HashMap::<String, Vec<&GatewayListenerStatusV1>>::new();
        for listener_status in &runtime.gateway_listener_statuses {
            listener_statuses_by_gateway
                .entry(resource_key(&listener_status.gateway_namespace, &listener_status.gateway_name))
                .or_default()
                .push(listener_status);
        }

        for gateway in snapshot.gateways.iter() {
            if gateway.metadata.name.is_empty() {
                continue;
            }
            let Some(gateway_class_name) = gateway.spec.gateway_class_name.as_deref() else {
                continue;
            };
            if !owned_gateway_classes.contains(gateway_class_name) {
                continue;
            }
            let namespace = resource_namespace(&gateway.metadata);
            let gateway_key = resource_key(&namespace, &gateway.metadata.name);
            let listener_statuses = listener_statuses_by_gateway
                .get(&gateway_key)
                .cloned()
                .unwrap_or_default();
            self.patch_gateway_status(gateway, listener_statuses).await?;
        }

        let mut diagnostics_by_route = HashMap::<String, Vec<&RouteParentDiagnosticV1>>::new();
        for diagnostic in &runtime.route_diagnostics {
            diagnostics_by_route
                .entry(resource_key(&diagnostic.route_namespace, &diagnostic.route_name))
                .or_default()
                .push(diagnostic);
        }

        for (route, route_raw) in snapshot.http_routes.iter().zip(snapshot.http_routes_raw.iter()) {
            if route.metadata.name.is_empty() {
                continue;
            }
            let route_namespace = resource_namespace(&route.metadata);
            let route_key = resource_key(&route_namespace, &route.metadata.name);
            let diagnostics = diagnostics_by_route.get(&route_key).cloned().unwrap_or_default();
            if diagnostics.is_empty() {
                continue;
            }

            let owned_parent_statuses = diagnostics
                .iter()
                .map(|diagnostic| {
                    let mut status_parent_ref = json!({
                        "group": diagnostic.parent_group,
                        "kind": diagnostic.parent_kind,
                        "name": diagnostic.parent_name,
                    });
                    if let Some(namespace) = diagnostic.parent_namespace.as_ref() {
                        status_parent_ref["namespace"] = Value::String(namespace.clone());
                    }
                    if let Some(section_name) = diagnostic.parent_section_name.as_ref() {
                        status_parent_ref["sectionName"] = Value::String(section_name.clone());
                    }
                    if let Some(port) = diagnostic.parent_port {
                        status_parent_ref["port"] = Value::Number(port.into());
                    }
                    json!({
                        "parentRef": status_parent_ref,
                        "controllerName": self.controller_name,
                        "conditions": [
                            self.status_condition(
                                "Accepted",
                                if diagnostic.accepted { "True" } else { "False" },
                                &diagnostic.accepted_reason,
                                &diagnostic.accepted_message,
                                diagnostic.observed_generation
                            ),
                            self.status_condition(
                                "ResolvedRefs",
                                if diagnostic.resolved_refs { "True" } else { "False" },
                                &diagnostic.resolved_refs_reason,
                                &diagnostic.resolved_refs_message,
                                diagnostic.observed_generation
                            )
                        ]
                    })
                })
                .collect::<Vec<_>>();

            let existing_parent_statuses = extract_route_parent_statuses(route_raw);
            let route_parent_statuses = merge_route_parent_statuses(
                &self.controller_name,
                existing_parent_statuses.clone(),
                owned_parent_statuses,
            );
            if route_parent_statuses == existing_parent_statuses {
                continue;
            }
            self.patch_http_route_status(&route_namespace, &route.metadata.name, route_parent_statuses)
                .await?;
        }

        Ok(())
    }

    async fn patch_gateway_class_status(
        &self, gateway_class: &GatewayClassResource, runtime_status: Option<&GatewayClassStatusV1>,
    ) -> Result<(), DynError> {
        let accepted = runtime_status.map(|status| status.accepted).unwrap_or(true);
        let reason = runtime_status
            .map(|status| status.accepted_reason.as_str())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("Accepted");
        let message = runtime_status
            .map(|status| status.accepted_message.as_str())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("GatewayClass is accepted by hyperway controller");
        let supported_features = runtime_status
            .map(|status| status.supported_features.clone())
            .unwrap_or_default();
        let observed_generation = runtime_status
            .and_then(|status| status.observed_generation)
            .or(gateway_class.metadata.generation);
        let payload = json!({
            "status": {
                "conditions": [self.status_condition(
                    "Accepted",
                    if accepted { "True" } else { "False" },
                    reason,
                    message,
                    observed_generation
                )],
                "supportedFeatures": supported_features
            }
        });
        self.patch_status_by_path(
            &build_cluster_resource_status_path("gatewayclasses", &gateway_class.metadata.name),
            payload,
        )
        .await
    }

    async fn patch_gateway_status(
        &self, gateway: &GatewayResource, listener_statuses: Vec<&GatewayListenerStatusV1>,
    ) -> Result<(), DynError> {
        let namespace = resource_namespace(&gateway.metadata);
        let listeners = listener_statuses
            .iter()
            .map(|listener| {
                let supported_kinds = listener
                    .supported_kinds
                    .iter()
                    .map(|kind| {
                        let mut value = json!({ "kind": kind.kind });
                        if let Some(group) = kind.group.as_ref() {
                            value["group"] = Value::String(group.clone());
                        }
                        value
                    })
                    .collect::<Vec<_>>();
                json!({
                    "name": listener.listener_name,
                    "supportedKinds": supported_kinds,
                    "attachedRoutes": listener.attached_routes,
                    "conditions": [
                        self.status_condition(
                            "Accepted",
                            if listener.accepted { "True" } else { "False" },
                            &listener.accepted_reason,
                            &listener.accepted_message,
                            listener.observed_generation
                        )
                    ]
                })
            })
            .collect::<Vec<_>>();

        let addresses = gateway
            .spec
            .addresses
            .iter()
            .filter_map(|address| {
                let value = address.value.as_ref()?;
                let mut item = json!({ "value": value });
                if let Some(address_type) = address.address_type.as_ref() {
                    item["type"] = Value::String(address_type.clone());
                }
                Some(item)
            })
            .collect::<Vec<_>>();

        let payload = json!({
            "status": {
                "conditions": [
                    self.status_condition(
                        "Accepted",
                        "True",
                        "Accepted",
                        "Gateway is accepted by hyperway controller",
                        gateway.metadata.generation
                    ),
                    self.status_condition(
                        "Programmed",
                        "True",
                        "Programmed",
                        "Gateway has been programmed by hyperway controller",
                        gateway.metadata.generation
                    )
                ],
                "listeners": listeners,
                "addresses": addresses
            }
        });
        self.patch_status_by_path(&build_resource_status_path("gateways", &namespace, &gateway.metadata.name), payload)
            .await
    }

    async fn patch_http_route_status(
        &self, namespace: &str, name: &str, route_parent_statuses: Vec<Value>,
    ) -> Result<(), DynError> {
        let payload = json!({
            "status": {
                "parents": route_parent_statuses
            }
        });
        self.patch_status_by_path(&build_resource_status_path("httproutes", namespace, name), payload)
            .await
    }

    fn status_condition(
        &self, condition_type: &str, status: &str, reason: &str, message: &str, observed_generation: Option<u64>,
    ) -> Value {
        let mut condition = json!({
            "type": condition_type,
            "status": status,
            "reason": reason,
            "message": message,
            "lastTransitionTime": self.condition_transition_time,
        });
        if let Some(generation) = observed_generation {
            condition["observedGeneration"] = Value::Number(generation.into());
        }
        condition
    }

    async fn patch_status_by_path(&self, path: &str, payload: Value) -> Result<(), DynError> {
        let uri = format!("{}{}", self.base_url, path).parse::<Uri>()?;
        let body = serde_json::to_vec(&payload)?;
        let req = Request::builder()
            .method(Method::PATCH)
            .uri(uri)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/merge-patch+json")
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .body(Full::new(Bytes::from(body)))?;
        let resp = self.client.request(req).await?;
        let status = resp.status();
        let bytes = resp.into_body().collect().await?.to_bytes();
        if !status.is_success() {
            let body = String::from_utf8_lossy(&bytes);
            return Err(format!("patch status {} failed: {} {}", path, status, body).into());
        }
        Ok(())
    }
}

fn handle_watch_line(resource: &'static str, line: &str, watch_event_tx: &mpsc::Sender<WatchSignal>) {
    match serde_json::from_str::<WatchEvent>(line) {
        Ok(event) => {
            if event.event_type != "BOOKMARK" {
                let _ = watch_event_tx.try_send(WatchSignal {
                    resource,
                    event_type: event.event_type,
                });
            }
        }
        Err(err) => {
            warn!("failed to parse watch event line for resource={resource}: {err}");
        }
    }
}

fn normalize_namespace(namespace: Option<String>) -> Option<String> {
    namespace
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn resource_namespace(metadata: &ObjectMeta) -> String {
    metadata
        .namespace
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("default")
        .to_string()
}

fn resource_key(namespace: &str, name: &str) -> String {
    format!("{namespace}/{name}")
}

fn build_resource_path(namespace: Option<&str>, resource: &str) -> String {
    build_gateway_resource_path_by_version(namespace, resource, "v1")
}

fn build_cluster_resource_path(resource: &str) -> String {
    build_gateway_resource_path_by_version(None, resource, "v1")
}

fn build_gateway_resource_path_by_version(namespace: Option<&str>, resource: &str, version: &str) -> String {
    match namespace {
        Some(namespace) => format!("/apis/gateway.networking.k8s.io/{version}/namespaces/{namespace}/{resource}"),
        None => format!("/apis/gateway.networking.k8s.io/{version}/{resource}"),
    }
}

fn build_core_resource_path(namespace: Option<&str>, resource: &str) -> String {
    match namespace {
        Some(namespace) => format!("/api/v1/namespaces/{namespace}/{resource}"),
        None => format!("/api/v1/{resource}"),
    }
}

fn build_core_cluster_resource_path(resource: &str) -> String {
    format!("/api/v1/{resource}")
}

fn build_resource_status_path(resource: &str, namespace: &str, name: &str) -> String {
    format!("/apis/gateway.networking.k8s.io/v1/namespaces/{namespace}/{resource}/{name}/status")
}

fn build_cluster_resource_status_path(resource: &str, name: &str) -> String {
    format!("/apis/gateway.networking.k8s.io/v1/{resource}/{name}/status")
}

fn build_snapshot_collection_path(namespace: &str) -> String {
    format!("/apis/{SNAPSHOT_API_GROUP}/{SNAPSHOT_API_VERSION}/namespaces/{namespace}/{SNAPSHOT_RESOURCE}")
}

fn build_snapshot_item_path(namespace: &str, name: &str) -> String {
    format!("/apis/{SNAPSHOT_API_GROUP}/{SNAPSHOT_API_VERSION}/namespaces/{namespace}/{SNAPSHOT_RESOURCE}/{name}")
}

fn build_snapshot_status_path(namespace: &str, name: &str) -> String {
    format!(
        "/apis/{SNAPSHOT_API_GROUP}/{SNAPSHOT_API_VERSION}/namespaces/{namespace}/{SNAPSHOT_RESOURCE}/{name}/status"
    )
}

fn build_watch_path(path: &str) -> String {
    format!("{path}?watch=true&allowWatchBookmarks=true&timeoutSeconds={WATCH_TIMEOUT_SECONDS}")
}

fn hash_gateway_runtime(runtime: &GatewayRuntime) -> Result<u64, DynError> {
    let mut listeners = runtime.listeners.clone();
    listeners.sort_by(|left, right| left.port.cmp(&right.port).then_with(|| left.name.cmp(&right.name)));
    let payload = serde_json::to_vec(&(
        listeners,
        &runtime.http_routes_v1,
        &runtime.route_diagnostics,
        &runtime.gateway_listener_statuses,
        &runtime.gateway_class_statuses,
    ))?;
    let mut hasher = DefaultHasher::new();
    payload.hash(&mut hasher);
    Ok(hasher.finish())
}

fn format_checksum(checksum: u64) -> String {
    format!("{checksum:016x}")
}

fn parse_k8s_items<T>(resource: &str, items: &[Value]) -> Result<Vec<T>, DynError>
where
    T: for<'de> Deserialize<'de>,
{
    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            serde_json::from_value(item.clone())
                .map_err(|err| format!("failed to parse item #{index} in {resource}: {err}").into())
        })
        .collect()
}

fn extract_route_parent_statuses(route_raw: &Value) -> Vec<Value> {
    route_raw
        .get("status")
        .and_then(|status| status.get("parents"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn merge_route_parent_statuses(controller_name: &str, existing: Vec<Value>, owned: Vec<Value>) -> Vec<Value> {
    let mut merged = existing
        .into_iter()
        .filter(|parent_status| {
            parent_status
                .get("controllerName")
                .and_then(Value::as_str)
                .map(|value| value != controller_name)
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();
    merged.extend(owned);
    merged
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_path() {
        assert_eq!(
            build_resource_path(Some("demo"), "httproutes"),
            "/apis/gateway.networking.k8s.io/v1/namespaces/demo/httproutes"
        );
        assert_eq!(build_resource_path(None, "gateways"), "/apis/gateway.networking.k8s.io/v1/gateways");
        assert_eq!(build_cluster_resource_path("gatewayclasses"), "/apis/gateway.networking.k8s.io/v1/gatewayclasses");
        assert_eq!(
            build_resource_status_path("gateways", "demo", "edge"),
            "/apis/gateway.networking.k8s.io/v1/namespaces/demo/gateways/edge/status"
        );
        assert_eq!(
            build_cluster_resource_status_path("gatewayclasses", "example"),
            "/apis/gateway.networking.k8s.io/v1/gatewayclasses/example/status"
        );
        assert_eq!(
            build_snapshot_collection_path("demo"),
            "/apis/hyperway.arloor.dev/v1alpha1/namespaces/demo/routesnapshots"
        );
        assert_eq!(
            build_snapshot_item_path("demo", "default"),
            "/apis/hyperway.arloor.dev/v1alpha1/namespaces/demo/routesnapshots/default"
        );
        assert_eq!(
            build_snapshot_status_path("demo", "default"),
            "/apis/hyperway.arloor.dev/v1alpha1/namespaces/demo/routesnapshots/default/status"
        );
        assert_eq!(
            build_watch_path("/apis/gateway.networking.k8s.io/v1/gateways"),
            "/apis/gateway.networking.k8s.io/v1/gateways?watch=true&allowWatchBookmarks=true&timeoutSeconds=300"
        );
    }
}
