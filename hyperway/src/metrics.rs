use prometheus_client::metrics::counter::Counter;
use prometheus_client::registry::Registry;
use std::sync::LazyLock;

pub static METRICS: LazyLock<Metrics> = LazyLock::new(|| {
    let mut registry = Registry::default();

    let reverse_proxy_requests = Counter::default();
    registry.register(
        "reverse_proxy_requests_total",
        "Number of reverse proxy requests routed by Gateway API",
        reverse_proxy_requests.clone(),
    );

    let listener_reconcile_total = Counter::default();
    registry.register(
        "gateway_listener_reconcile_total",
        "Number of Gateway listener reconcile loops",
        listener_reconcile_total.clone(),
    );

    Metrics {
        registry,
        reverse_proxy_requests,
        listener_reconcile_total,
    }
});

pub struct Metrics {
    pub registry: Registry,
    pub reverse_proxy_requests: Counter,
    pub listener_reconcile_total: Counter,
}
