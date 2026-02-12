use crate::location::LocationConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct GatewayRuntime {
    #[serde(default)]
    pub(crate) locations: HashMap<String, Vec<LocationConfig>>,
    #[serde(default)]
    pub(crate) listeners: Vec<GatewayListenerConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct GatewayListenerConfig {
    pub(crate) name: String,
    pub(crate) port: u16,
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
