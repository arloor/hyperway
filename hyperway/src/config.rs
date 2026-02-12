use clap::Parser;
use log::info;
use std::time::Duration;

use crate::gateway_api::{GatewayApiParseOptions, parse_gateway_api_runtime};
use crate::gateway_runtime::GatewayRuntime;
use crate::{BUILD_TIME, DynError, IDLE_TIMEOUT};

#[derive(Parser)]
#[command(author, version = None, about, long_about = None)]
pub struct Param {
    #[arg(long, value_name = "LOG_DIR", default_value = "/tmp")]
    pub log_dir: String,
    #[arg(long, value_name = "LOG_FILE", default_value = "proxy.log")]
    pub log_file: String,
    #[arg(
        long,
        value_name = "FILE_PATH",
        help = r#"Gateway API 配置文件（支持 GatewayClass/Gateway/HTTPRoute 多文档 YAML）"#
    )]
    gateway_api_config_file: Option<String>,
    #[arg(
        long,
        help = r#"启用从 Kubernetes API 同步 Gateway/HTTPRoute 并热更新路由和监听端口（仅支持集群内）"#
    )]
    gateway_api_k8s_sync: bool,
    #[arg(
        long,
        value_name = "NAMESPACE",
        help = r#"Kubernetes 命名空间。不设置则拉取全部命名空间"#
    )]
    gateway_api_k8s_namespace: Option<String>,
    #[arg(
        long,
        value_name = "SECONDS",
        default_value = "30",
        help = r#"Kubernetes Gateway API 拉取周期"#
    )]
    gateway_api_k8s_poll_seconds: u64,
    #[arg(
        long,
        value_name = "CONTROLLER_NAME",
        default_value = "hyperway.arloor.dev/gateway-controller",
        help = r#"仅处理 controllerName 匹配的 GatewayClass"#
    )]
    gateway_api_k8s_controller_name: String,
    #[arg(long, value_name = "NAME", help = r#"从 RouteSnapshot CRD 同步路由的资源名"#)]
    gateway_api_snapshot_name: Option<String>,
    #[arg(
        long,
        value_name = "NAMESPACE",
        default_value = "default",
        help = r#"RouteSnapshot CRD 所在命名空间"#
    )]
    gateway_api_snapshot_namespace: String,
    #[arg(
        long,
        value_name = "SECONDS",
        default_value = "5",
        help = r#"读取 RouteSnapshot CRD 的轮询周期"#
    )]
    gateway_api_snapshot_poll_seconds: u64,
}

pub(crate) struct Config {
    pub(crate) initial_runtime: GatewayRuntime,
    pub(crate) gateway_api_k8s_sync: Option<GatewayApiK8sSyncConfig>,
    pub(crate) gateway_api_snapshot_sync: Option<GatewayApiSnapshotSyncConfig>,
}

#[derive(Clone)]
pub(crate) struct GatewayApiK8sSyncConfig {
    pub(crate) namespace: Option<String>,
    pub(crate) poll_interval: Duration,
    pub(crate) controller_name: String,
}

#[derive(Clone)]
pub(crate) struct GatewayApiSnapshotSyncConfig {
    pub(crate) namespace: String,
    pub(crate) name: String,
    pub(crate) poll_interval: Duration,
}

impl TryFrom<Param> for Config {
    type Error = DynError;

    fn try_from(param: Param) -> Result<Self, Self::Error> {
        let initial_runtime = match param.gateway_api_config_file.as_deref() {
            Some(path) => parse_gateway_api_runtime(
                path,
                &GatewayApiParseOptions {
                    controller_name: Some(param.gateway_api_k8s_controller_name.clone()),
                },
            )?,
            None => GatewayRuntime::default(),
        };

        let gateway_api_k8s_sync = if param.gateway_api_k8s_sync {
            if param.gateway_api_k8s_poll_seconds == 0 {
                return Err("gateway_api_k8s_poll_seconds must be greater than 0".into());
            }
            Some(GatewayApiK8sSyncConfig {
                namespace: param.gateway_api_k8s_namespace,
                poll_interval: Duration::from_secs(param.gateway_api_k8s_poll_seconds),
                controller_name: param.gateway_api_k8s_controller_name,
            })
        } else {
            None
        };

        let gateway_api_snapshot_sync = if let Some(name) = param.gateway_api_snapshot_name {
            if param.gateway_api_snapshot_poll_seconds == 0 {
                return Err("gateway_api_snapshot_poll_seconds must be greater than 0".into());
            }
            Some(GatewayApiSnapshotSyncConfig {
                namespace: param.gateway_api_snapshot_namespace,
                name,
                poll_interval: Duration::from_secs(param.gateway_api_snapshot_poll_seconds),
            })
        } else {
            None
        };

        if gateway_api_k8s_sync.is_some() && gateway_api_snapshot_sync.is_some() {
            return Err("gateway_api_k8s_sync and gateway_api_snapshot_name are mutually exclusive".into());
        }

        Ok(Self {
            initial_runtime,
            gateway_api_k8s_sync,
            gateway_api_snapshot_sync,
        })
    }
}

pub(crate) fn load_config(param: Param) -> Result<Config, DynError> {
    info!("build time: {}", BUILD_TIME);
    #[cfg(all(feature = "ring", not(feature = "aws_lc_rs")))]
    {
        info!("use ring as default crypto provider");
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    }
    #[cfg(all(feature = "aws_lc_rs", not(feature = "ring")))]
    {
        info!("use aws_lc_rs as default crypto provider");
        let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
    let config = Config::try_from(param)?;
    log_config(&config);
    info!("auto close connection after idle for {IDLE_TIMEOUT:?}");
    Ok(config)
}

fn log_config(config: &Config) {
    info!(
        "gateway runtime loaded: listeners={}, host entries={}",
        config.initial_runtime.listeners.len(),
        config.initial_runtime.locations.len()
    );
    if let Some(sync_config) = &config.gateway_api_k8s_sync {
        info!(
            "gateway api k8s sync enabled: namespace={:?}, interval={:?}, controller={}",
            sync_config.namespace, sync_config.poll_interval, sync_config.controller_name
        );
    }
    if let Some(sync_config) = &config.gateway_api_snapshot_sync {
        info!(
            "gateway api snapshot sync enabled: {}/{} interval={:?}",
            sync_config.namespace, sync_config.name, sync_config.poll_interval
        );
    }
}
