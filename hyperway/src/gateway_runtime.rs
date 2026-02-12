use crate::location::LocationConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct GatewayRuntime {
    #[serde(default)]
    pub(crate) locations: HashMap<String, Vec<LocationConfig>>,
    #[serde(default)]
    pub(crate) listeners: Vec<GatewayListenerConfig>,
    #[serde(default)]
    pub(crate) http_routes_v1: Vec<HttpRouteRuleV1>,
    #[serde(default)]
    pub(crate) route_diagnostics: Vec<RouteParentDiagnosticV1>,
    #[serde(default)]
    pub(crate) gateway_listener_statuses: Vec<GatewayListenerStatusV1>,
    #[serde(default)]
    pub(crate) gateway_class_statuses: Vec<GatewayClassStatusV1>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct GatewayListenerConfig {
    pub(crate) name: String,
    pub(crate) port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) tls: Option<GatewayListenerTlsConfig>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GatewayListenerTlsConfig {
    #[serde(default)]
    pub(crate) certificate_refs: Vec<GatewaySecretRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cert_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) key_pem: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) struct GatewaySecretRef {
    pub(crate) namespace: String,
    pub(crate) name: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HttpRouteRuleV1 {
    pub(crate) id: String,
    pub(crate) route_namespace: String,
    pub(crate) route_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) route_rule_name: Option<String>,
    pub(crate) gateway_namespace: String,
    pub(crate) gateway_name: String,
    pub(crate) listener_name: String,
    pub(crate) listener_port: u16,
    #[serde(default)]
    pub(crate) hostnames: Vec<String>,
    #[serde(default)]
    pub(crate) matches: Vec<HttpRouteMatchV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) request_header_modifier: Option<HttpHeaderModifierV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) response_header_modifier: Option<HttpHeaderModifierV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) request_redirect: Option<HttpRequestRedirectV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) url_rewrite: Option<HttpUrlRewriteV1>,
    #[serde(default)]
    pub(crate) request_mirrors: Vec<HttpRequestMirrorV1>,
    #[serde(default)]
    pub(crate) backends: Vec<WeightedBackendRefV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) request_timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) backend_request_timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) retry: Option<HttpRetryPolicyV1>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HttpRouteMatchV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) path: Option<HttpPathMatchV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) method: Option<String>,
    #[serde(default)]
    pub(crate) headers: Vec<HttpHeaderMatchV1>,
    #[serde(default)]
    pub(crate) query_params: Vec<HttpQueryParamMatchV1>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HttpPathMatchV1 {
    pub(crate) match_type: HttpPathMatchTypeV1,
    pub(crate) value: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum HttpPathMatchTypeV1 {
    Exact,
    PathPrefix,
    RegularExpression,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HttpHeaderMatchV1 {
    pub(crate) name: String,
    pub(crate) value: String,
    pub(crate) match_type: HttpStringMatchTypeV1,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HttpQueryParamMatchV1 {
    pub(crate) name: String,
    pub(crate) value: String,
    pub(crate) match_type: HttpStringMatchTypeV1,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum HttpStringMatchTypeV1 {
    Exact,
    RegularExpression,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HttpHeaderModifierV1 {
    #[serde(default)]
    pub(crate) add: Vec<HttpHeaderMutationV1>,
    #[serde(default)]
    pub(crate) set: Vec<HttpHeaderMutationV1>,
    #[serde(default)]
    pub(crate) remove: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HttpHeaderMutationV1 {
    pub(crate) name: String,
    pub(crate) value: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HttpRequestRedirectV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) status_code: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) path: Option<HttpPathModifierV1>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HttpUrlRewriteV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) path: Option<HttpPathModifierV1>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HttpPathModifierV1 {
    pub(crate) modifier_type: HttpPathModifierTypeV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) replace_prefix_match: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) replace_full_path: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum HttpPathModifierTypeV1 {
    ReplacePrefixMatch,
    ReplaceFullPath,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HttpRequestMirrorV1 {
    pub(crate) backend: WeightedBackendRefV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) fraction_percent: Option<u8>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WeightedBackendRefV1 {
    pub(crate) namespace: String,
    pub(crate) name: String,
    pub(crate) port: u16,
    #[serde(default = "default_backend_weight")]
    pub(crate) weight: u16,
}

fn default_backend_weight() -> u16 {
    1
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HttpRetryPolicyV1 {
    pub(crate) attempts: u16,
    #[serde(default)]
    pub(crate) codes: Vec<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) backoff_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RouteParentDiagnosticV1 {
    pub(crate) route_namespace: String,
    pub(crate) route_name: String,
    pub(crate) parent_group: String,
    pub(crate) parent_kind: String,
    pub(crate) parent_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) parent_namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) parent_section_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) parent_port: Option<u16>,
    pub(crate) accepted: bool,
    pub(crate) accepted_reason: String,
    pub(crate) accepted_message: String,
    pub(crate) resolved_refs: bool,
    pub(crate) resolved_refs_reason: String,
    pub(crate) resolved_refs_message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) observed_generation: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GatewayListenerStatusV1 {
    pub(crate) gateway_namespace: String,
    pub(crate) gateway_name: String,
    pub(crate) listener_name: String,
    pub(crate) attached_routes: u64,
    #[serde(default)]
    pub(crate) supported_kinds: Vec<RouteGroupKindV1>,
    #[serde(default)]
    pub(crate) accepted: bool,
    #[serde(default)]
    pub(crate) accepted_reason: String,
    #[serde(default)]
    pub(crate) accepted_message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) observed_generation: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GatewayClassStatusV1 {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) accepted: bool,
    #[serde(default)]
    pub(crate) accepted_reason: String,
    #[serde(default)]
    pub(crate) accepted_message: String,
    #[serde(default)]
    pub(crate) supported_features: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) observed_generation: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RouteGroupKindV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) group: Option<String>,
    pub(crate) kind: String,
}
