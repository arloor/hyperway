#![deny(warnings)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

use clap::Parser as _;
use hyperway::{DynError, spawn_gateway_controller_snapshot_process};
use std::time::Duration;

#[derive(clap::Parser)]
#[command(author, version = None, about, long_about = None)]
struct Param {
    #[arg(long, value_name = "LOG_DIR", default_value = "/tmp")]
    log_dir: String,
    #[arg(long, value_name = "LOG_FILE", default_value = "gateway-controller.log")]
    log_file: String,
    #[arg(
        long,
        value_name = "NAME",
        help = r#"gateway-controller 输出到 RouteSnapshot CRD 的资源名"#
    )]
    gateway_api_snapshot_name: String,
    #[arg(
        long,
        value_name = "NAMESPACE",
        default_value = "default",
        help = r#"RouteSnapshot CRD 所在命名空间"#
    )]
    gateway_api_snapshot_namespace: String,
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
}

fn main() -> Result<(), DynError> {
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let _guard = runtime.enter();

    let param = Param::parse();
    if let Err(log_init_error) = log_x::init_log(&param.log_dir, &param.log_file, "info") {
        return Err(format!("init log error:{log_init_error}").into());
    }
    if param.gateway_api_k8s_poll_seconds == 0 {
        return Err("gateway_api_k8s_poll_seconds must be greater than 0".into());
    }

    spawn_gateway_controller_snapshot_process(
        param.gateway_api_snapshot_namespace,
        param.gateway_api_snapshot_name,
        param.gateway_api_k8s_namespace,
        Duration::from_secs(param.gateway_api_k8s_poll_seconds),
        param.gateway_api_k8s_controller_name,
    );

    runtime.block_on(async {
        tokio::signal::ctrl_c()
            .await
            .map_err(|err| -> DynError { format!("listen ctrl-c failed: {err}").into() })?;
        log::info!("received ctrl-c, gateway-controller exits");
        Ok::<(), DynError>(())
    })
}
