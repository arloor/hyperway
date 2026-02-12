use crate::metrics::METRICS;
use axum::extract::MatchedPath;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Router, http::StatusCode};
use prometheus_client::encoding::text::encode;
use std::fmt::Display;
use std::time::Duration;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

pub(crate) fn build_router() -> Router {
    Router::new()
        .route("/healthz", get(|| async { (StatusCode::OK, "ok") }))
        .route("/metrics", get(serve_metrics))
        .fallback(get(|| async { (StatusCode::NOT_FOUND, "not found") }))
        .layer((
            TraceLayer::new_for_http().make_span_with(make_span).on_failure(()),
            CorsLayer::permissive(),
            TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, Duration::from_secs(30)),
            CompressionLayer::new(),
        ))
}

fn make_span(req: &http::Request<axum::body::Body>) -> tracing::Span {
    let method = req.method();
    let path = req.uri().path();
    let matched_path = req.extensions().get::<MatchedPath>().map(|value| value.as_str());
    tracing::debug_span!("recv request", %method, %path, matched_path)
}

pub(crate) const AXUM_PATHS: [&str; 2] = ["/healthz", "/metrics"];

async fn serve_metrics() -> Result<(StatusCode, String), AppProxyError> {
    let mut buffer = String::new();
    encode(&mut buffer, &METRICS.registry).map_err(AppProxyError::new)?;
    Ok((StatusCode::OK, buffer))
}

#[derive(Debug)]
pub struct AppProxyError(anyhow::Error);

impl Display for AppProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl IntoResponse for AppProxyError {
    fn into_response(self) -> Response {
        let err = self.0;
        tracing::error!(%err, "error");
        (StatusCode::INTERNAL_SERVER_ERROR, format!("internal server error: {err}")).into_response()
    }
}

impl<E> From<E> for AppProxyError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

impl AppProxyError {
    pub fn new<T: std::error::Error + Send + Sync + 'static>(err: T) -> Self {
        use anyhow::anyhow;
        Self(anyhow!(err))
    }
}
