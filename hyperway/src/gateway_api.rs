use crate::DynError;
use crate::gateway_runtime::{
    GatewayClassStatusV1, GatewayListenerConfig, GatewayListenerStatusV1, GatewayListenerTlsConfig, GatewayRuntime,
    GatewaySecretRef, HttpHeaderMatchV1, HttpHeaderModifierV1, HttpHeaderMutationV1, HttpPathMatchTypeV1,
    HttpPathMatchV1, HttpPathModifierTypeV1, HttpPathModifierV1, HttpQueryParamMatchV1, HttpRequestMirrorV1,
    HttpRequestRedirectV1, HttpRetryPolicyV1, HttpRouteMatchV1, HttpRouteRuleV1, HttpStringMatchTypeV1,
    HttpUrlRewriteV1, RouteGroupKindV1, RouteParentDiagnosticV1, WeightedBackendRefV1,
};
use log::{info, warn};
use serde::Deserialize;
use serde_yaml_bw::Value;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Default)]
pub(crate) struct GatewayApiParseOptions {
    pub(crate) controller_name: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ObjectMeta {
    #[serde(default)]
    name: String,
    #[serde(default = "default_namespace")]
    namespace: String,
    #[serde(default)]
    generation: Option<u64>,
    #[serde(default)]
    labels: HashMap<String, String>,
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
    #[serde(default)]
    allowed_routes: Option<AllowedRoutes>,
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
struct AllowedRoutes {
    #[serde(default)]
    namespaces: Option<AllowedRouteNamespaces>,
    #[serde(default)]
    kinds: Vec<RouteGroupKind>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AllowedRouteNamespaces {
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    selector: Option<LabelSelector>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LabelSelector {
    #[serde(default)]
    match_labels: HashMap<String, String>,
    #[serde(default)]
    match_expressions: Vec<LabelSelectorRequirement>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LabelSelectorRequirement {
    #[serde(default)]
    key: String,
    #[serde(default)]
    operator: String,
    #[serde(default)]
    values: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RouteGroupKind {
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    kind: String,
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
    #[serde(default)]
    port: Option<u16>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpRouteRule {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    matches: Vec<HttpRouteMatch>,
    #[serde(default)]
    filters: Vec<HttpRouteFilter>,
    #[serde(default)]
    backend_refs: Vec<HttpBackendRef>,
    #[serde(default)]
    timeouts: Option<HttpRouteTimeouts>,
    #[serde(default)]
    retry: Option<HttpRouteRetry>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpRouteMatch {
    #[serde(default)]
    path: Option<HttpPathMatch>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    headers: Vec<HttpStringMatch>,
    #[serde(default)]
    query_params: Vec<HttpStringMatch>,
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
struct HttpStringMatch {
    #[serde(rename = "type")]
    #[serde(default)]
    match_type: Option<String>,
    #[serde(default)]
    name: String,
    #[serde(default)]
    value: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpRouteFilter {
    #[serde(rename = "type")]
    #[serde(default)]
    filter_type: String,
    #[serde(default)]
    request_header_modifier: Option<HttpHeaderModifier>,
    #[serde(default)]
    response_header_modifier: Option<HttpHeaderModifier>,
    #[serde(default)]
    request_redirect: Option<HttpRequestRedirect>,
    #[serde(default)]
    url_rewrite: Option<HttpUrlRewrite>,
    #[serde(default)]
    request_mirror: Option<HttpRequestMirror>,
    #[serde(default)]
    extension_ref: Option<LocalObjectReference>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpHeaderModifier {
    #[serde(default)]
    add: Vec<HttpHeaderMutation>,
    #[serde(default)]
    set: Vec<HttpHeaderMutation>,
    #[serde(default)]
    remove: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpHeaderMutation {
    #[serde(default)]
    name: String,
    #[serde(default)]
    value: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpRequestRedirect {
    #[serde(default)]
    scheme: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    status_code: Option<u16>,
    #[serde(default)]
    path: Option<HttpPathModifier>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpUrlRewrite {
    #[serde(default)]
    hostname: Option<String>,
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
struct HttpRequestMirror {
    #[serde(default)]
    backend_ref: Option<HttpBackendRef>,
    #[serde(default)]
    percent: Option<u8>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LocalObjectReference {
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    name: String,
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
    #[serde(default)]
    weight: Option<u16>,
    #[serde(default)]
    filters: Vec<HttpRouteFilter>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpRouteTimeouts {
    #[serde(default)]
    request: Option<String>,
    #[serde(default)]
    backend_request: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpRouteRetry {
    #[serde(default)]
    attempts: Option<u16>,
    #[serde(default)]
    codes: Vec<u16>,
    #[serde(default)]
    backoff: Option<String>,
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
    #[serde(default)]
    parameters_ref: Option<Value>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NamespaceResource {
    metadata: ObjectMeta,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServiceResource {
    metadata: ObjectMeta,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReferenceGrant {
    metadata: ObjectMeta,
    #[serde(default)]
    spec: ReferenceGrantSpec,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReferenceGrantSpec {
    #[serde(default)]
    from: Vec<ReferenceGrantFrom>,
    #[serde(default)]
    to: Vec<ReferenceGrantTo>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReferenceGrantFrom {
    #[serde(default)]
    group: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    namespace: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReferenceGrantTo {
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Clone)]
struct ListenerBinding {
    gateway_namespace: String,
    gateway_name: String,
    listener_name: String,
    listener_port: u16,
    listener_hostname: Option<String>,
    allowed_routes: Option<AllowedRoutes>,
    supports_http_route: bool,
}

struct CompiledRule {
    matches: Vec<HttpRouteMatchV1>,
    request_header_modifier: Option<HttpHeaderModifierV1>,
    response_header_modifier: Option<HttpHeaderModifierV1>,
    request_redirect: Option<HttpRequestRedirectV1>,
    url_rewrite: Option<HttpUrlRewriteV1>,
    request_mirrors: Vec<HttpRequestMirrorV1>,
    backends: Vec<WeightedBackendRefV1>,
    request_timeout_ms: Option<u64>,
    backend_request_timeout_ms: Option<u64>,
    retry: Option<HttpRetryPolicyV1>,
    resolved_refs_ok: bool,
    accepted: bool,
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
    let mut namespace_labels = HashMap::<String, HashMap<String, String>>::new();
    let mut services = HashSet::<String>::new();
    let mut reference_grants = Vec::<ReferenceGrant>::new();

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
            "Namespace" => {
                let namespace: NamespaceResource = serde_yaml_bw::from_value(value)?;
                if namespace.metadata.name.is_empty() {
                    continue;
                }
                namespace_labels.insert(namespace.metadata.name.clone(), namespace.metadata.labels.clone());
            }
            "Service" => {
                let service: ServiceResource = serde_yaml_bw::from_value(value)?;
                if service.metadata.name.is_empty() {
                    continue;
                }
                services.insert(gateway_key(&service.metadata.namespace, &service.metadata.name));
            }
            "ReferenceGrant" => {
                let grant: ReferenceGrant = serde_yaml_bw::from_value(value)?;
                if grant.metadata.namespace.trim().is_empty() {
                    continue;
                }
                reference_grants.push(grant);
            }
            _ => {}
        }
    }

    let mut gateway_class_statuses = Vec::<GatewayClassStatusV1>::new();
    let controller_name = options.controller_name.as_deref();
    let owned_gateway_classes = gateway_classes
        .iter()
        .filter_map(|(name, gateway_class)| {
            let owned = match controller_name {
                Some(target) => gateway_class.spec.controller_name == target,
                None => true,
            };
            if !owned {
                return None;
            }
            let mut supported_features = vec![
                "HTTPRouteCore".to_string(),
                "HTTPRouteExtended".to_string(),
                "GatewayListenerAllowedRoutes".to_string(),
            ];
            if gateway_class.spec.parameters_ref.is_some() {
                supported_features.push("GatewayClassParametersRef".to_string());
            }
            if gateway_class.spec.description.is_some() {
                supported_features.push("GatewayClassDescription".to_string());
            }
            gateway_class_statuses.push(GatewayClassStatusV1 {
                name: name.clone(),
                accepted: true,
                accepted_reason: "Accepted".to_string(),
                accepted_message: "GatewayClass is accepted by hyperway controller".to_string(),
                supported_features,
                observed_generation: gateway_class.metadata.generation,
            });
            Some(name.clone())
        })
        .collect::<HashSet<_>>();

    let mut owned_gateways = HashMap::<String, Gateway>::new();
    for (key, gateway) in gateways {
        let Some(gateway_class_name) = gateway.spec.gateway_class_name.as_deref() else {
            warn!("skip Gateway {key} because spec.gatewayClassName is empty");
            continue;
        };
        let Some(_gateway_class) = gateway_classes.get(gateway_class_name) else {
            warn!("skip Gateway {key} because GatewayClass {gateway_class_name} is not found");
            continue;
        };
        if !owned_gateway_classes.contains(gateway_class_name) {
            if let Some(target) = controller_name {
                warn!("skip Gateway {key}: GatewayClass controllerName does not match {target}");
            }
            continue;
        }
        owned_gateways.insert(key, gateway);
    }

    let mut listeners = Vec::<GatewayListenerConfig>::new();
    let mut gateway_listener_statuses = Vec::<GatewayListenerStatusV1>::new();
    let mut listener_bindings_by_gateway = HashMap::<String, Vec<ListenerBinding>>::new();

    for gateway in owned_gateways.values() {
        let gateway_key = gateway_key(&gateway.metadata.namespace, &gateway.metadata.name);
        let mut listener_bindings = Vec::<ListenerBinding>::new();

        for (listener_index, listener) in gateway.spec.listeners.iter().enumerate() {
            let listener_name = if listener.name.trim().is_empty() {
                format!("listener-{}", listener_index + 1)
            } else {
                listener.name.clone()
            };
            let status_key = GatewayListenerStatusV1 {
                gateway_namespace: gateway.metadata.namespace.clone(),
                gateway_name: gateway.metadata.name.clone(),
                listener_name: listener_name.clone(),
                attached_routes: 0,
                supported_kinds: vec![RouteGroupKindV1 {
                    group: Some("gateway.networking.k8s.io".to_string()),
                    kind: "HTTPRoute".to_string(),
                }],
                accepted: false,
                accepted_reason: "Invalid".to_string(),
                accepted_message: "listener is invalid".to_string(),
                observed_generation: gateway.metadata.generation,
            };

            let Some(port) = listener.port else {
                gateway_listener_statuses.push(GatewayListenerStatusV1 {
                    accepted_message: "listener.port is empty".to_string(),
                    ..status_key
                });
                continue;
            };

            if port == 0 {
                gateway_listener_statuses.push(GatewayListenerStatusV1 {
                    accepted_message: "listener.port must be greater than 0".to_string(),
                    ..status_key
                });
                continue;
            }

            let protocol = listener.protocol.as_deref().unwrap_or("HTTP");
            let supports_http_route = matches!(protocol, "HTTP" | "HTTPS");
            if !supports_http_route {
                gateway_listener_statuses.push(GatewayListenerStatusV1 {
                    accepted_reason: "UnsupportedProtocol".to_string(),
                    accepted_message: format!("listener protocol {protocol} does not support HTTPRoute"),
                    ..status_key
                });
                continue;
            }

            let tls = match protocol {
                "HTTP" => None,
                "HTTPS" => Some(parse_listener_tls(listener, gateway)),
                _ => None,
            };
            let listener_hostname = listener.hostname.as_deref().and_then(normalize_hostname);

            listeners.push(GatewayListenerConfig {
                name: format!("{}/{}/{}", gateway.metadata.namespace, gateway.metadata.name, listener_name),
                port,
                hostname: listener_hostname.clone(),
                tls,
            });

            listener_bindings.push(ListenerBinding {
                gateway_namespace: gateway.metadata.namespace.clone(),
                gateway_name: gateway.metadata.name.clone(),
                listener_name: listener_name.clone(),
                listener_port: port,
                listener_hostname,
                allowed_routes: listener.allowed_routes.clone(),
                supports_http_route,
            });

            gateway_listener_statuses.push(GatewayListenerStatusV1 {
                accepted: true,
                accepted_reason: "Accepted".to_string(),
                accepted_message: "listener is accepted".to_string(),
                ..status_key
            });
        }

        listener_bindings_by_gateway.insert(gateway_key, listener_bindings);
    }

    resolve_listener_port_conflicts(&mut listeners, &mut gateway_listener_statuses, &mut listener_bindings_by_gateway);

    listeners.sort_by(|left, right| left.port.cmp(&right.port).then_with(|| left.name.cmp(&right.name)));
    listeners.dedup();

    let mut http_routes_v1 = Vec::<HttpRouteRuleV1>::new();
    let mut route_diagnostics = Vec::<RouteParentDiagnosticV1>::new();
    let mut listener_attached_routes = HashMap::<String, HashSet<String>>::new();

    for route in routes {
        let route_namespace = route.metadata.namespace.clone();
        let route_name = route.metadata.name.clone();
        let route_key_value = gateway_key(&route_namespace, &route_name);

        let parent_refs = if route.spec.parent_refs.is_empty() {
            owned_gateways
                .values()
                .filter(|gateway| gateway.metadata.namespace == route_namespace)
                .map(|gateway| ParentRef {
                    group: Some("gateway.networking.k8s.io".to_string()),
                    kind: Some("Gateway".to_string()),
                    name: gateway.metadata.name.clone(),
                    namespace: Some(gateway.metadata.namespace.clone()),
                    section_name: None,
                    port: None,
                })
                .collect::<Vec<_>>()
        } else {
            route.spec.parent_refs.clone()
        };

        for parent_ref in parent_refs {
            if !is_gateway_parent_ref(&parent_ref) {
                continue;
            }

            let parent_namespace = parent_ref.namespace.clone().unwrap_or_else(|| route_namespace.clone());
            let parent_key = gateway_key(&parent_namespace, &parent_ref.name);
            let Some(_gateway) = owned_gateways.get(&parent_key) else {
                route_diagnostics.push(RouteParentDiagnosticV1 {
                    route_namespace: route_namespace.clone(),
                    route_name: route_name.clone(),
                    parent_group: parent_ref
                        .group
                        .clone()
                        .unwrap_or_else(|| "gateway.networking.k8s.io".to_string()),
                    parent_kind: parent_ref.kind.clone().unwrap_or_else(|| "Gateway".to_string()),
                    parent_name: parent_ref.name.clone(),
                    parent_namespace: Some(parent_namespace),
                    parent_section_name: parent_ref.section_name.clone(),
                    parent_port: parent_ref.port,
                    accepted: false,
                    accepted_reason: "ParentNotFound".to_string(),
                    accepted_message: "referenced Gateway is not owned by this controller".to_string(),
                    resolved_refs: false,
                    resolved_refs_reason: "ParentNotFound".to_string(),
                    resolved_refs_message: "referenced Gateway is not found".to_string(),
                    observed_generation: route.metadata.generation,
                });
                continue;
            };

            let bindings = listener_bindings_by_gateway
                .get(&parent_key)
                .cloned()
                .unwrap_or_default();

            let mut matched_listener = false;
            let mut attached = false;
            let mut resolved_refs = true;
            let mut last_reject_reason = "NoMatchingListener".to_string();
            let mut last_reject_msg = "no listener selected by parentRef".to_string();

            for binding in bindings.iter() {
                if let Some(section_name) = parent_ref.section_name.as_ref()
                    && section_name != &binding.listener_name
                {
                    continue;
                }
                if let Some(port) = parent_ref.port
                    && port != binding.listener_port
                {
                    continue;
                }
                matched_listener = true;

                if !binding.supports_http_route {
                    last_reject_reason = "UnsupportedProtocol".to_string();
                    last_reject_msg = "listener protocol does not support HTTPRoute".to_string();
                    continue;
                }

                if !listener_allows_httproute_kind(binding.allowed_routes.as_ref()) {
                    last_reject_reason = "NotAllowedByListeners".to_string();
                    last_reject_msg = "listener.allowedRoutes.kinds does not include HTTPRoute".to_string();
                    continue;
                }

                if !listener_allows_namespace(
                    binding.allowed_routes.as_ref(),
                    &route_namespace,
                    &binding.gateway_namespace,
                    &namespace_labels,
                ) {
                    last_reject_reason = "NotAllowedByListeners".to_string();
                    last_reject_msg = "listener.allowedRoutes.namespaces rejects this route namespace".to_string();
                    continue;
                }

                let bound_hostnames =
                    resolve_route_hostnames_for_listener(&route.spec.hostnames, binding.listener_hostname.as_deref());
                if bound_hostnames.is_empty() {
                    last_reject_reason = "NoMatchingListenerHostname".to_string();
                    last_reject_msg = "route hostnames do not overlap with listener hostname".to_string();
                    continue;
                }

                let mut listener_attached = false;
                let mut listener_resolved_refs = true;

                for (rule_index, rule) in route.spec.rules.iter().enumerate() {
                    let compiled_rule =
                        compile_http_route_rule(&route, rule, &reference_grants, &services, !services.is_empty());
                    if !compiled_rule.accepted {
                        listener_resolved_refs = false;
                        continue;
                    }

                    if !compiled_rule.resolved_refs_ok {
                        listener_resolved_refs = false;
                    }

                    let route_rule_name = rule.name.as_ref().and_then(|value| {
                        let value = value.trim();
                        if value.is_empty() {
                            None
                        } else {
                            Some(value.to_string())
                        }
                    });

                    let rule_id = format!(
                        "{}/{}/{}:{}:{}:{}",
                        route_namespace,
                        route_name,
                        rule_index,
                        binding.gateway_namespace,
                        binding.gateway_name,
                        binding.listener_name
                    );

                    let runtime_rule = HttpRouteRuleV1 {
                        id: rule_id,
                        route_namespace: route_namespace.clone(),
                        route_name: route_name.clone(),
                        route_rule_name,
                        gateway_namespace: binding.gateway_namespace.clone(),
                        gateway_name: binding.gateway_name.clone(),
                        listener_name: binding.listener_name.clone(),
                        listener_port: binding.listener_port,
                        hostnames: bound_hostnames.clone(),
                        matches: compiled_rule.matches.clone(),
                        request_header_modifier: compiled_rule.request_header_modifier.clone(),
                        response_header_modifier: compiled_rule.response_header_modifier.clone(),
                        request_redirect: compiled_rule.request_redirect.clone(),
                        url_rewrite: compiled_rule.url_rewrite.clone(),
                        request_mirrors: compiled_rule.request_mirrors.clone(),
                        backends: compiled_rule.backends.clone(),
                        request_timeout_ms: compiled_rule.request_timeout_ms,
                        backend_request_timeout_ms: compiled_rule.backend_request_timeout_ms,
                        retry: compiled_rule.retry.clone(),
                    };
                    http_routes_v1.push(runtime_rule);

                    listener_attached = true;
                }

                if listener_attached {
                    attached = true;
                    let listener_key =
                        listener_status_key(&binding.gateway_namespace, &binding.gateway_name, &binding.listener_name);
                    listener_attached_routes
                        .entry(listener_key)
                        .or_default()
                        .insert(route_key_value.clone());
                }
                if !listener_resolved_refs {
                    resolved_refs = false;
                }
            }

            if !matched_listener {
                route_diagnostics.push(RouteParentDiagnosticV1 {
                    route_namespace: route_namespace.clone(),
                    route_name: route_name.clone(),
                    parent_group: parent_ref
                        .group
                        .clone()
                        .unwrap_or_else(|| "gateway.networking.k8s.io".to_string()),
                    parent_kind: parent_ref.kind.clone().unwrap_or_else(|| "Gateway".to_string()),
                    parent_name: parent_ref.name.clone(),
                    parent_namespace: Some(parent_namespace),
                    parent_section_name: parent_ref.section_name.clone(),
                    parent_port: parent_ref.port,
                    accepted: false,
                    accepted_reason: "NoMatchingListener".to_string(),
                    accepted_message: "no listener selected by parentRef.sectionName/port".to_string(),
                    resolved_refs: false,
                    resolved_refs_reason: "NoMatchingListener".to_string(),
                    resolved_refs_message: "cannot resolve refs when no listener is selected".to_string(),
                    observed_generation: route.metadata.generation,
                });
                continue;
            }

            route_diagnostics.push(RouteParentDiagnosticV1 {
                route_namespace: route_namespace.clone(),
                route_name: route_name.clone(),
                parent_group: parent_ref
                    .group
                    .clone()
                    .unwrap_or_else(|| "gateway.networking.k8s.io".to_string()),
                parent_kind: parent_ref.kind.clone().unwrap_or_else(|| "Gateway".to_string()),
                parent_name: parent_ref.name.clone(),
                parent_namespace: Some(parent_namespace),
                parent_section_name: parent_ref.section_name.clone(),
                parent_port: parent_ref.port,
                accepted: attached,
                accepted_reason: if attached {
                    "Accepted".to_string()
                } else {
                    last_reject_reason.clone()
                },
                accepted_message: if attached {
                    "HTTPRoute has been accepted by hyperway controller".to_string()
                } else {
                    last_reject_msg.clone()
                },
                resolved_refs,
                resolved_refs_reason: if resolved_refs {
                    "ResolvedRefs".to_string()
                } else {
                    "RefNotPermitted".to_string()
                },
                resolved_refs_message: if resolved_refs {
                    "all references are resolved by hyperway controller".to_string()
                } else {
                    "one or more refs are invalid, unsupported, or not permitted".to_string()
                },
                observed_generation: route.metadata.generation,
            });
        }
    }

    for listener_status in &mut gateway_listener_statuses {
        let listener_key = listener_status_key(
            &listener_status.gateway_namespace,
            &listener_status.gateway_name,
            &listener_status.listener_name,
        );
        listener_status.attached_routes = listener_attached_routes
            .get(&listener_key)
            .map(|set| set.len() as u64)
            .unwrap_or(0);
    }

    info!(
        "parsed Gateway API resources: gateways={}, listeners={}, route_rules={}",
        owned_gateways.len(),
        listeners.len(),
        http_routes_v1.len()
    );

    Ok(GatewayRuntime {
        listeners,
        http_routes_v1,
        route_diagnostics,
        gateway_listener_statuses,
        gateway_class_statuses,
    })
}

fn compile_http_route_rule(
    route: &HttpRoute, rule: &HttpRouteRule, reference_grants: &[ReferenceGrant], services: &HashSet<String>,
    service_inventory_available: bool,
) -> CompiledRule {
    let matches = compile_route_matches(route, &rule.matches);

    let mut request_header_modifier = None;
    let mut response_header_modifier = None;
    let mut request_redirect = None;
    let mut url_rewrite = None;
    let mut request_mirrors = Vec::<HttpRequestMirrorV1>::new();
    let mut accepted = true;

    for filter in &rule.filters {
        match filter.filter_type.as_str() {
            "RequestHeaderModifier" => {
                request_header_modifier = filter
                    .request_header_modifier
                    .as_ref()
                    .map(compile_header_modifier)
                    .or_else(|| Some(HttpHeaderModifierV1::default()));
            }
            "ResponseHeaderModifier" => {
                response_header_modifier = filter
                    .response_header_modifier
                    .as_ref()
                    .map(compile_header_modifier)
                    .or_else(|| Some(HttpHeaderModifierV1::default()));
            }
            "RequestRedirect" => {
                request_redirect = filter.request_redirect.as_ref().map(compile_request_redirect);
            }
            "URLRewrite" => {
                url_rewrite = filter.url_rewrite.as_ref().map(compile_url_rewrite);
            }
            "RequestMirror" => {
                let Some(mirror) = filter.request_mirror.as_ref() else {
                    accepted = false;
                    continue;
                };
                let Some(backend_ref) = mirror.backend_ref.as_ref() else {
                    accepted = false;
                    continue;
                };
                match compile_backend_ref(route, backend_ref, reference_grants, services, service_inventory_available) {
                    Ok(backend) => request_mirrors.push(HttpRequestMirrorV1 {
                        backend,
                        fraction_percent: mirror.percent,
                    }),
                    Err(err) => {
                        accepted = false;
                        warn!(
                            "HTTPRoute {}/{} has invalid RequestMirror backendRef: {}",
                            route.metadata.namespace, route.metadata.name, err
                        );
                    }
                }
            }
            "ExtensionRef" => {
                let extension = filter.extension_ref.as_ref().map(|value| {
                    let group = value.group.clone().unwrap_or_default();
                    let kind = value.kind.clone().unwrap_or_default();
                    format!("{group}/{kind}/{}", value.name)
                });
                accepted = false;
                match extension {
                    Some(value) if !value.ends_with('/') => warn!(
                        "HTTPRoute {}/{} uses unsupported ExtensionRef filter {}",
                        route.metadata.namespace, route.metadata.name, value
                    ),
                    _ => warn!(
                        "HTTPRoute {}/{} uses unsupported ExtensionRef filter",
                        route.metadata.namespace, route.metadata.name
                    ),
                }
            }
            unknown => {
                accepted = false;
                warn!(
                    "HTTPRoute {}/{} uses unsupported filter type: {}",
                    route.metadata.namespace, route.metadata.name, unknown
                );
            }
        }
    }

    if request_redirect.is_some() && url_rewrite.is_some() {
        accepted = false;
        warn!(
            "HTTPRoute {}/{} has invalid rule: RequestRedirect and URLRewrite cannot be configured together",
            route.metadata.namespace, route.metadata.name
        );
    }

    let mut backends = Vec::<WeightedBackendRefV1>::new();
    let mut resolved_refs_ok = true;

    for backend in &rule.backend_refs {
        match compile_backend_ref(route, backend, reference_grants, services, service_inventory_available) {
            Ok(backend) => backends.push(backend),
            Err(err) => {
                resolved_refs_ok = false;
                warn!("HTTPRoute {}/{} backendRef is invalid: {}", route.metadata.namespace, route.metadata.name, err);
            }
        }
    }

    if request_redirect.is_none() && backends.is_empty() {
        resolved_refs_ok = false;
        accepted = false;
        warn!("HTTPRoute {}/{} has no valid backendRefs in rule", route.metadata.namespace, route.metadata.name);
    }

    let retry = compile_retry_policy(rule.retry.as_ref());
    let request_timeout_ms = rule
        .timeouts
        .as_ref()
        .and_then(|timeouts| timeouts.request.as_deref())
        .and_then(parse_duration_ms);
    let backend_request_timeout_ms = rule
        .timeouts
        .as_ref()
        .and_then(|timeouts| timeouts.backend_request.as_deref())
        .and_then(parse_duration_ms);

    CompiledRule {
        matches,
        request_header_modifier,
        response_header_modifier,
        request_redirect,
        url_rewrite,
        request_mirrors,
        backends,
        request_timeout_ms,
        backend_request_timeout_ms,
        retry,
        resolved_refs_ok,
        accepted,
    }
}

fn compile_route_matches(route: &HttpRoute, matches: &[HttpRouteMatch]) -> Vec<HttpRouteMatchV1> {
    if matches.is_empty() {
        return vec![HttpRouteMatchV1::default()];
    }

    let mut compiled = Vec::<HttpRouteMatchV1>::new();
    for route_match in matches {
        let path = match route_match.path.as_ref() {
            Some(path_match) => match compile_path_match(route, path_match) {
                Some(path) => Some(path),
                None => continue,
            },
            None => None,
        };

        let method = route_match
            .method
            .as_ref()
            .map(|value| value.trim().to_ascii_uppercase());
        let headers = route_match
            .headers
            .iter()
            .filter_map(compile_header_match)
            .collect::<Vec<_>>();
        let query_params = route_match
            .query_params
            .iter()
            .filter_map(compile_query_match)
            .collect::<Vec<_>>();

        compiled.push(HttpRouteMatchV1 {
            path,
            method,
            headers,
            query_params,
        });
    }

    if compiled.is_empty() {
        warn!(
            "HTTPRoute {}/{} has no valid matches, fallback to default match",
            route.metadata.namespace, route.metadata.name
        );
        return vec![HttpRouteMatchV1::default()];
    }

    compiled
}

fn compile_path_match(route: &HttpRoute, path_match: &HttpPathMatch) -> Option<HttpPathMatchV1> {
    let mut value = path_match.value.clone().unwrap_or_else(|| "/".to_string());
    if value.trim().is_empty() {
        value = "/".to_string();
    }
    if !value.starts_with('/') {
        value = format!("/{value}");
    }

    let match_type = match path_match.match_type.as_deref().unwrap_or("PathPrefix") {
        "PathPrefix" => HttpPathMatchTypeV1::PathPrefix,
        "Exact" => HttpPathMatchTypeV1::Exact,
        "RegularExpression" => HttpPathMatchTypeV1::RegularExpression,
        unknown => {
            warn!(
                "HTTPRoute {}/{} path.type={} is unsupported, skip this match",
                route.metadata.namespace, route.metadata.name, unknown
            );
            return None;
        }
    };

    Some(HttpPathMatchV1 { match_type, value })
}

fn compile_header_match(item: &HttpStringMatch) -> Option<HttpHeaderMatchV1> {
    let name = item.name.trim().to_string();
    if name.is_empty() {
        return None;
    }
    let value = item.value.trim().to_string();
    let match_type = match item.match_type.as_deref().unwrap_or("Exact") {
        "Exact" => HttpStringMatchTypeV1::Exact,
        "RegularExpression" => HttpStringMatchTypeV1::RegularExpression,
        _ => HttpStringMatchTypeV1::Exact,
    };

    Some(HttpHeaderMatchV1 {
        name,
        value,
        match_type,
    })
}

fn compile_query_match(item: &HttpStringMatch) -> Option<HttpQueryParamMatchV1> {
    let name = item.name.trim().to_string();
    if name.is_empty() {
        return None;
    }
    let value = item.value.trim().to_string();
    let match_type = match item.match_type.as_deref().unwrap_or("Exact") {
        "Exact" => HttpStringMatchTypeV1::Exact,
        "RegularExpression" => HttpStringMatchTypeV1::RegularExpression,
        _ => HttpStringMatchTypeV1::Exact,
    };
    Some(HttpQueryParamMatchV1 {
        name,
        value,
        match_type,
    })
}

fn compile_header_modifier(modifier: &HttpHeaderModifier) -> HttpHeaderModifierV1 {
    let add = modifier
        .add
        .iter()
        .filter_map(|header| {
            let name = header.name.trim();
            if name.is_empty() {
                return None;
            }
            Some(HttpHeaderMutationV1 {
                name: name.to_string(),
                value: header.value.clone(),
            })
        })
        .collect::<Vec<_>>();
    let set = modifier
        .set
        .iter()
        .filter_map(|header| {
            let name = header.name.trim();
            if name.is_empty() {
                return None;
            }
            Some(HttpHeaderMutationV1 {
                name: name.to_string(),
                value: header.value.clone(),
            })
        })
        .collect::<Vec<_>>();
    let remove = modifier
        .remove
        .iter()
        .filter_map(|name| {
            let name = name.trim();
            if name.is_empty() { None } else { Some(name.to_string()) }
        })
        .collect::<Vec<_>>();

    HttpHeaderModifierV1 { add, set, remove }
}

fn compile_request_redirect(redirect: &HttpRequestRedirect) -> HttpRequestRedirectV1 {
    HttpRequestRedirectV1 {
        scheme: redirect.scheme.clone(),
        hostname: redirect.hostname.as_deref().and_then(normalize_hostname),
        port: redirect.port,
        status_code: redirect.status_code,
        path: redirect.path.as_ref().and_then(compile_path_modifier),
    }
}

fn compile_url_rewrite(rewrite: &HttpUrlRewrite) -> HttpUrlRewriteV1 {
    HttpUrlRewriteV1 {
        hostname: rewrite.hostname.as_deref().and_then(normalize_hostname),
        path: rewrite.path.as_ref().and_then(compile_path_modifier),
    }
}

fn compile_path_modifier(path: &HttpPathModifier) -> Option<HttpPathModifierV1> {
    let modifier_type = match path.modifier_type.as_str() {
        "ReplacePrefixMatch" => HttpPathModifierTypeV1::ReplacePrefixMatch,
        "ReplaceFullPath" => HttpPathModifierTypeV1::ReplaceFullPath,
        _ => return None,
    };

    Some(HttpPathModifierV1 {
        modifier_type,
        replace_prefix_match: path.replace_prefix_match.as_ref().map(|path| normalize_path(path)),
        replace_full_path: path.replace_full_path.as_ref().map(|path| normalize_path(path)),
    })
}

fn compile_retry_policy(retry: Option<&HttpRouteRetry>) -> Option<HttpRetryPolicyV1> {
    let retry = retry?;
    let attempts = retry.attempts.unwrap_or(0);
    if attempts == 0 {
        return None;
    }

    Some(HttpRetryPolicyV1 {
        attempts,
        codes: retry.codes.clone(),
        backoff_ms: retry.backoff.as_deref().and_then(parse_duration_ms),
    })
}

fn compile_backend_ref(
    route: &HttpRoute, backend: &HttpBackendRef, reference_grants: &[ReferenceGrant], services: &HashSet<String>,
    service_inventory_available: bool,
) -> Result<WeightedBackendRefV1, String> {
    for filter in &backend.filters {
        if filter.filter_type == "ExtensionRef" {
            return Err("HTTPBackendRef.filters.ExtensionRef is not supported".to_string());
        }
    }

    let group = backend.group.as_deref().unwrap_or_default();
    let kind = backend.kind.as_deref().unwrap_or("Service");
    if !group.is_empty() || kind != "Service" {
        return Err(format!("only core Service backend is supported: got group={group:?}, kind={kind}"));
    }

    if backend.name.trim().is_empty() {
        return Err("backendRef.name is empty".to_string());
    }

    let Some(port) = backend.port else {
        return Err(format!("backendRef {} missing port", backend.name));
    };

    let namespace = backend
        .namespace
        .clone()
        .unwrap_or_else(|| route.metadata.namespace.clone());

    if namespace != route.metadata.namespace
        && !is_reference_allowed(
            reference_grants,
            &route.metadata.namespace,
            "gateway.networking.k8s.io",
            "HTTPRoute",
            &namespace,
            "",
            "Service",
            &backend.name,
        )
    {
        return Err(format!(
            "cross-namespace backendRef {}/{} is not permitted by ReferenceGrant",
            namespace, backend.name
        ));
    }

    if service_inventory_available {
        let key = gateway_key(&namespace, &backend.name);
        if !services.contains(&key) {
            return Err(format!("backend Service {key} does not exist"));
        }
    }

    Ok(WeightedBackendRefV1 {
        namespace,
        name: backend.name.clone(),
        port,
        weight: backend.weight.unwrap_or(1),
    })
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

    GatewayListenerTlsConfig {
        certificate_refs,
        cert_pem: None,
        key_pem: None,
    }
}

fn resolve_listener_port_conflicts(
    listeners: &mut Vec<GatewayListenerConfig>, gateway_listener_statuses: &mut [GatewayListenerStatusV1],
    listener_bindings_by_gateway: &mut HashMap<String, Vec<ListenerBinding>>,
) {
    let mut listeners_by_port = HashMap::<u16, Vec<GatewayListenerConfig>>::new();
    for listener in listeners.iter() {
        listeners_by_port
            .entry(listener.port)
            .or_default()
            .push(listener.clone());
    }

    let mut conflicted_listener_keys = HashSet::<String>::new();
    for (port, listeners_on_port) in listeners_by_port {
        let plain_listeners = listeners_on_port
            .iter()
            .filter(|listener| listener.tls.is_none())
            .map(|listener| listener.name.clone())
            .collect::<Vec<_>>();
        let tls_listeners = listeners_on_port
            .iter()
            .filter(|listener| listener.tls.is_some())
            .cloned()
            .collect::<Vec<_>>();

        if !plain_listeners.is_empty() && !tls_listeners.is_empty() {
            let names = plain_listeners
                .iter()
                .cloned()
                .chain(tls_listeners.iter().map(|listener| listener.name.clone()))
                .collect::<Vec<_>>()
                .join(",");
            warn!(
                "port conflict on {}: HTTP and HTTPS listeners share the same port and are rejected: {}",
                port, names
            );
            conflicted_listener_keys.extend(plain_listeners);
            conflicted_listener_keys.extend(tls_listeners.into_iter().map(|listener| listener.name));
            continue;
        }
    }

    if conflicted_listener_keys.is_empty() {
        return;
    }

    for status in gateway_listener_statuses {
        let listener_key = listener_status_key(&status.gateway_namespace, &status.gateway_name, &status.listener_name);
        if conflicted_listener_keys.contains(&listener_key) {
            status.accepted = false;
            status.accepted_reason = "PortConflict".to_string();
            status.accepted_message = "listener conflicts with other listeners on the same port".to_string();
        }
    }

    listeners.retain(|listener| !conflicted_listener_keys.contains(&listener.name));
    for bindings in listener_bindings_by_gateway.values_mut() {
        bindings.retain(|binding| !conflicted_listener_keys.contains(&binding_listener_key(binding)));
    }
}

fn binding_listener_key(binding: &ListenerBinding) -> String {
    format!("{}/{}/{}", binding.gateway_namespace, binding.gateway_name, binding.listener_name)
}

fn listener_allows_httproute_kind(allowed_routes: Option<&AllowedRoutes>) -> bool {
    let Some(allowed_routes) = allowed_routes else {
        return true;
    };
    if allowed_routes.kinds.is_empty() {
        return true;
    }
    allowed_routes.kinds.iter().any(|kind| {
        let group = kind.group.as_deref().unwrap_or("gateway.networking.k8s.io");
        kind.kind == "HTTPRoute" && group == "gateway.networking.k8s.io"
    })
}

fn listener_allows_namespace(
    allowed_routes: Option<&AllowedRoutes>, route_namespace: &str, gateway_namespace: &str,
    namespace_labels: &HashMap<String, HashMap<String, String>>,
) -> bool {
    let Some(allowed_routes) = allowed_routes else {
        return route_namespace == gateway_namespace;
    };
    let Some(namespaces) = allowed_routes.namespaces.as_ref() else {
        return route_namespace == gateway_namespace;
    };

    match namespaces.from.as_deref().unwrap_or("Same") {
        "Same" => route_namespace == gateway_namespace,
        "All" => true,
        "Selector" => {
            let Some(selector) = namespaces.selector.as_ref() else {
                return false;
            };
            let Some(labels) = namespace_labels.get(route_namespace) else {
                return false;
            };
            match_label_selector(selector, labels)
        }
        _ => false,
    }
}

fn match_label_selector(selector: &LabelSelector, labels: &HashMap<String, String>) -> bool {
    for (key, value) in &selector.match_labels {
        if labels.get(key) != Some(value) {
            return false;
        }
    }

    for expression in &selector.match_expressions {
        let key = expression.key.as_str();
        let exists = labels.contains_key(key);
        let value = labels.get(key);
        match expression.operator.as_str() {
            "In" => {
                if !exists {
                    return false;
                }
                if let Some(value) = value {
                    if !expression.values.iter().any(|candidate| candidate == value) {
                        return false;
                    }
                }
            }
            "NotIn" => {
                if !exists {
                    continue;
                }
                if let Some(value) = value
                    && expression.values.iter().any(|candidate| candidate == value)
                {
                    return false;
                }
            }
            "Exists" => {
                if !exists {
                    return false;
                }
            }
            "DoesNotExist" => {
                if exists {
                    return false;
                }
            }
            _ => return false,
        }
    }

    true
}

fn resolve_route_hostnames_for_listener(route_hostnames: &[String], listener_hostname: Option<&str>) -> Vec<String> {
    let route_patterns = normalize_hosts(route_hostnames);
    let listener_pattern = listener_hostname.and_then(normalize_hostname);

    if route_patterns.is_empty() {
        return match listener_pattern {
            Some(listener) => vec![listener],
            None => vec!["*".to_string()],
        };
    }

    let Some(listener_pattern) = listener_pattern else {
        return route_patterns;
    };

    route_patterns
        .into_iter()
        .filter(|route_pattern| hostname_patterns_overlap(route_pattern, &listener_pattern))
        .collect::<Vec<_>>()
}

fn hostname_patterns_overlap(left: &str, right: &str) -> bool {
    if left == right || left == "*" || right == "*" {
        return true;
    }
    if hostname_matches(left, right) || hostname_matches(right, left) {
        return true;
    }

    let left_suffix = left.strip_prefix("*.");
    let right_suffix = right.strip_prefix("*.");
    match (left_suffix, right_suffix) {
        (Some(left_suffix), Some(right_suffix)) => {
            left_suffix == right_suffix
                || left_suffix.ends_with(&format!(".{right_suffix}"))
                || right_suffix.ends_with(&format!(".{left_suffix}"))
        }
        _ => false,
    }
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
    pattern == host
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

fn parse_duration_ms(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    let (number, unit) = if let Some(number) = value.strip_suffix("ms") {
        (number, "ms")
    } else if let Some(number) = value.strip_suffix('s') {
        (number, "s")
    } else if let Some(number) = value.strip_suffix('m') {
        (number, "m")
    } else if let Some(number) = value.strip_suffix('h') {
        (number, "h")
    } else {
        return None;
    };

    let number = number.trim().parse::<u64>().ok()?;
    let factor = match unit {
        "ms" => 1,
        "s" => 1000,
        "m" => 60 * 1000,
        "h" => 60 * 60 * 1000,
        _ => return None,
    };
    number.checked_mul(factor)
}

#[allow(clippy::too_many_arguments)]
fn is_reference_allowed(
    reference_grants: &[ReferenceGrant], from_namespace: &str, from_group: &str, from_kind: &str, to_namespace: &str,
    to_group: &str, to_kind: &str, to_name: &str,
) -> bool {
    reference_grants.iter().any(|grant| {
        if grant.metadata.namespace != to_namespace {
            return false;
        }

        let from_allowed = grant
            .spec
            .from
            .iter()
            .any(|from| from.group == from_group && from.kind == from_kind && from.namespace == from_namespace);
        if !from_allowed {
            return false;
        }

        grant.spec.to.iter().any(|to| {
            let group = to.group.as_deref().unwrap_or_default();
            if group != to_group || to.kind != to_kind {
                return false;
            }
            match to.name.as_deref() {
                Some(name) => name == to_name,
                None => true,
            }
        })
    })
}

fn is_gateway_parent_ref(parent_ref: &ParentRef) -> bool {
    let kind = parent_ref.kind.as_deref().unwrap_or("Gateway");
    let group = parent_ref.group.as_deref().unwrap_or("gateway.networking.k8s.io");
    kind == "Gateway" && group == "gateway.networking.k8s.io" && !parent_ref.name.is_empty()
}

fn gateway_key(namespace: &str, name: &str) -> String {
    format!("{namespace}/{name}")
}

fn listener_status_key(gateway_namespace: &str, gateway_name: &str, listener_name: &str) -> String {
    format!("{gateway_namespace}/{gateway_name}/{listener_name}")
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
  gatewayClassName: example
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
        assert_eq!(runtime.http_routes_v1.len(), 1);
        assert_eq!(runtime.http_routes_v1[0].listener_port, 80);
        assert_eq!(runtime.http_routes_v1[0].hostnames, vec!["app.example.com".to_string()]);
        assert_eq!(runtime.http_routes_v1[0].matches.len(), 1);
        let path = runtime.http_routes_v1[0].matches[0].path.as_ref();
        assert!(path.is_some());
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
        assert_eq!(runtime.http_routes_v1.len(), 1);
        assert_eq!(runtime.http_routes_v1[0].route_name, "good-route");
        assert_eq!(runtime.http_routes_v1[0].hostnames, vec!["good.example.com".to_string()]);
        assert_eq!(runtime.listeners.len(), 1);
        assert_eq!(runtime.gateway_class_statuses.len(), 1);
        assert_eq!(runtime.gateway_class_statuses[0].name, "owned");
    }

    #[test]
    fn parse_httproute_exact_match_and_full_path_rewrite() {
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
spec:
  gatewayClassName: example
  listeners:
    - name: http
      protocol: HTTP
      port: 80
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: exact-rewrite
spec:
  parentRefs:
    - name: edge
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
        assert_eq!(runtime.http_routes_v1.len(), 1);
        let route = &runtime.http_routes_v1[0];
        assert_eq!(route.hostnames, vec!["exact.example.com".to_string()]);
        let path = route.matches[0].path.as_ref();
        assert!(path.is_some());
        let rewrite = route.url_rewrite.as_ref();
        assert!(rewrite.is_some());
    }

    #[test]
    fn parse_listener_tls_refs() {
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
  gatewayClassName: example
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

    #[test]
    fn route_match_method_header_query_is_parsed() {
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
spec:
  gatewayClassName: example
  listeners:
    - name: http
      protocol: HTTP
      port: 80
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: matched
spec:
  parentRefs:
    - name: edge
  rules:
    - matches:
        - method: GET
          path:
            type: PathPrefix
            value: /api
          headers:
            - name: x-env
              value: prod
          queryParams:
            - name: ver
              value: v1
      backendRefs:
        - name: demo
          port: 8080
"#;
        let runtime = match parse_gateway_api_runtime_from_str(config) {
            Ok(runtime) => runtime,
            Err(err) => panic!("parse should succeed: {err}"),
        };
        assert_eq!(runtime.http_routes_v1.len(), 1);
        let route = &runtime.http_routes_v1[0];
        assert_eq!(route.matches.len(), 1);
        assert_eq!(route.matches[0].method.as_deref(), Some("GET"));
        assert_eq!(route.matches[0].headers.len(), 1);
        assert_eq!(route.matches[0].query_params.len(), 1);
    }

    #[test]
    fn cross_namespace_backend_needs_reference_grant() {
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
  namespace: app
spec:
  gatewayClassName: example
  listeners:
    - name: http
      protocol: HTTP
      port: 80
      allowedRoutes:
        namespaces:
          from: All
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: app
  namespace: app
spec:
  parentRefs:
    - name: edge
  rules:
    - backendRefs:
        - name: other-svc
          namespace: other
          port: 8080
"#;
        let runtime = match parse_gateway_api_runtime_from_str(config) {
            Ok(runtime) => runtime,
            Err(err) => panic!("parse should succeed: {err}"),
        };
        assert!(runtime.http_routes_v1.is_empty());
        assert_eq!(runtime.route_diagnostics.len(), 1);
        assert!(!runtime.route_diagnostics[0].resolved_refs);
    }

    #[test]
    fn parse_duration_supports_ms_s_m_h() {
        assert_eq!(parse_duration_ms("10ms"), Some(10));
        assert_eq!(parse_duration_ms("2s"), Some(2000));
        assert_eq!(parse_duration_ms("3m"), Some(180000));
        assert_eq!(parse_duration_ms("1h"), Some(3600000));
        assert_eq!(parse_duration_ms("1"), None);
    }

    #[test]
    fn regex_path_match_type_is_preserved() {
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
spec:
  gatewayClassName: example
  listeners:
    - name: http
      protocol: HTTP
      port: 80
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: regex-route
spec:
  parentRefs:
    - name: edge
  rules:
    - matches:
        - path:
            type: RegularExpression
            value: "^/v[0-9]+/api$"
      backendRefs:
        - name: svc
          port: 8080
"#;
        let runtime = match parse_gateway_api_runtime_from_str(config) {
            Ok(runtime) => runtime,
            Err(err) => panic!("parse should succeed: {err}"),
        };
        assert_eq!(runtime.http_routes_v1.len(), 1);
        let path = runtime.http_routes_v1[0].matches[0].path.as_ref();
        let path = match path {
            Some(path) => path,
            None => panic!("path should exist"),
        };
        assert_eq!(path.match_type, HttpPathMatchTypeV1::RegularExpression);
    }

    #[test]
    fn reference_grant_allows_cross_namespace_backend() {
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
  namespace: app
spec:
  gatewayClassName: example
  listeners:
    - name: http
      protocol: HTTP
      port: 80
      allowedRoutes:
        namespaces:
          from: All
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: app
  namespace: app
spec:
  parentRefs:
    - name: edge
  rules:
    - backendRefs:
        - name: other-svc
          namespace: other
          port: 8080
---
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-app
  namespace: other
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      namespace: app
  to:
    - group: ""
      kind: Service
      name: other-svc
"#;
        let runtime = match parse_gateway_api_runtime_from_str(config) {
            Ok(runtime) => runtime,
            Err(err) => panic!("parse should succeed: {err}"),
        };
        assert_eq!(runtime.http_routes_v1.len(), 1);
        assert!(runtime.route_diagnostics[0].resolved_refs);
    }

    #[test]
    fn mixed_http_https_on_same_port_is_rejected_with_listener_status() {
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
  gatewayClassName: example
  listeners:
    - name: http
      protocol: HTTP
      port: 8443
    - name: https
      protocol: HTTPS
      port: 8443
      tls:
        certificateRefs:
          - name: edge-cert
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
    - backendRefs:
        - name: app
          port: 8080
"#;
        let runtime = match parse_gateway_api_runtime_from_str(config) {
            Ok(runtime) => runtime,
            Err(err) => panic!("parse should succeed: {err}"),
        };
        assert!(runtime.listeners.is_empty());
        assert_eq!(runtime.gateway_listener_statuses.len(), 2);
        for status in &runtime.gateway_listener_statuses {
            assert!(!status.accepted);
            assert_eq!(status.accepted_reason, "PortConflict");
        }
        assert_eq!(runtime.route_diagnostics.len(), 1);
        assert_eq!(runtime.route_diagnostics[0].accepted_reason, "NoMatchingListener");
    }

    #[test]
    fn same_port_http_listeners_remain_accepted() {
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
  gatewayClassName: example
  listeners:
    - name: web-a
      protocol: HTTP
      port: 80
      hostname: a.example.com
    - name: web-b
      protocol: HTTP
      port: 80
      hostname: b.example.com
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: app-a
  namespace: demo
spec:
  parentRefs:
    - name: edge
      sectionName: web-a
  rules:
    - backendRefs:
        - name: app-a
          port: 8080
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: app-b
  namespace: demo
spec:
  parentRefs:
    - name: edge
      sectionName: web-b
  rules:
    - backendRefs:
        - name: app-b
          port: 8080
"#;
        let runtime = match parse_gateway_api_runtime_from_str(config) {
            Ok(runtime) => runtime,
            Err(err) => panic!("parse should succeed: {err}"),
        };
        assert_eq!(runtime.listeners.len(), 2);
        assert_eq!(runtime.http_routes_v1.len(), 2);
        for status in &runtime.gateway_listener_statuses {
            let key = listener_status_key(&status.gateway_namespace, &status.gateway_name, &status.listener_name);
            if key == "demo/edge/web-a" || key == "demo/edge/web-b" {
                assert!(status.accepted);
            }
        }
    }

    #[test]
    fn same_port_https_with_different_cert_refs_remain_accepted() {
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
  gatewayClassName: example
  listeners:
    - name: https-a
      protocol: HTTPS
      port: 443
      hostname: a.example.com
      tls:
        certificateRefs:
          - name: cert-a
    - name: https-b
      protocol: HTTPS
      port: 443
      hostname: b.example.com
      tls:
        certificateRefs:
          - name: cert-b
"#;
        let runtime = match parse_gateway_api_runtime_from_str(config) {
            Ok(runtime) => runtime,
            Err(err) => panic!("parse should succeed: {err}"),
        };
        assert_eq!(runtime.listeners.len(), 2);
        assert_eq!(runtime.gateway_listener_statuses.len(), 2);
        for status in &runtime.gateway_listener_statuses {
            if status.listener_name == "https-a" || status.listener_name == "https-b" {
                assert!(status.accepted);
                assert_eq!(status.accepted_reason, "Accepted");
            }
        }
    }

    #[test]
    fn regex_helper_works() {
        let regex = match regex::Regex::new("^/v[0-9]+/api$") {
            Ok(regex) => regex,
            Err(err) => panic!("regex should compile: {err}"),
        };
        assert!(regex.is_match("/v2/api"));
        assert!(!regex.is_match("/v2/api/extra"));
    }
}
