use std::fmt::{Display, Formatter};
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use axum::extract::Request;
use axum_bootstrap::InterceptResult;
use http::header::LOCATION;
use http_body_util::{BodyExt as _, combinators::BoxBody};
use hyper::body::{Bytes, Incoming};
use hyper::{Response, Version};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use log::{debug, warn};

use crate::axum_handler::{self, AppProxyError};
use crate::config::Config;
use crate::gateway_runtime::{GatewayListenerConfig, GatewayRuntime};
use crate::location::{
    LocationConfig, LocationSpecs, build_location_specs, build_upstream_req, find_location_configs_for_host,
    normalize302,
};
use crate::metrics::METRICS;

#[allow(dead_code)]
pub(crate) enum InterceptResultAdapter {
    Drop,
    Return(Response<BoxBody<Bytes, io::Error>>),
    Continue(Request<Incoming>),
}

impl From<InterceptResultAdapter> for InterceptResult<AppProxyError> {
    fn from(value: InterceptResultAdapter) -> Self {
        match value {
            InterceptResultAdapter::Drop => InterceptResult::Drop,
            InterceptResultAdapter::Return(resp) => {
                let (parts, body) = resp.into_parts();
                InterceptResult::Return(Response::from_parts(parts, axum::body::Body::new(body)))
            }
            InterceptResultAdapter::Continue(req) => InterceptResult::Continue(req),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct GatewayRuntimeApplyStats {
    pub(crate) location_count: usize,
    pub(crate) listener_count: usize,
}

#[derive(Clone)]
struct RuntimeState {
    location_specs: LocationSpecs,
    listeners: Vec<GatewayListenerConfig>,
}

pub struct ProxyHandler {
    runtime: Arc<RwLock<RuntimeState>>,
    reverse_proxy_client: legacy::Client<
        HttpsConnector<HttpConnector>,
        http_body_util::combinators::BoxBody<axum::body::Bytes, std::io::Error>,
    >,
}

impl ProxyHandler {
    pub fn new(config: Arc<Config>) -> Result<Self, crate::DynError> {
        let location_specs = build_location_specs(config.initial_runtime.locations.clone())?;
        let listeners = normalize_listeners(config.initial_runtime.listeners.clone());
        Ok(Self {
            runtime: Arc::new(RwLock::new(RuntimeState {
                location_specs,
                listeners,
            })),
            reverse_proxy_client: build_hyper_legacy_client(),
        })
    }

    pub fn replace_gateway_runtime(
        &self, runtime: GatewayRuntime,
    ) -> Result<GatewayRuntimeApplyStats, crate::DynError> {
        let location_specs = build_location_specs(runtime.locations)?;
        let listeners = normalize_listeners(runtime.listeners);
        let location_count: usize = location_specs.locations.values().map(std::vec::Vec::len).sum();
        let listener_count = listeners.len();
        let mut guard = self
            .runtime
            .write()
            .map_err(|_| io::Error::other("runtime lock poisoned"))?;
        *guard = RuntimeState {
            location_specs,
            listeners,
        };
        Ok(GatewayRuntimeApplyStats {
            location_count,
            listener_count,
        })
    }

    pub fn current_listeners(&self) -> Result<Vec<GatewayListenerConfig>, crate::DynError> {
        let guard = self
            .runtime
            .read()
            .map_err(|_| io::Error::other("runtime lock poisoned"))?;
        Ok(guard.listeners.clone())
    }

    fn normalize_redirect_response(
        &self, original_scheme_host_port: &SchemeHostPort, resp_headers: &mut http::HeaderMap,
    ) -> Result<(), io::Error> {
        let guard = self
            .runtime
            .read()
            .map_err(|_| io::Error::other("runtime lock poisoned"))?;
        normalize302(original_scheme_host_port, resp_headers, &guard.location_specs.redirect_bachpaths)
    }

    pub async fn handle(
        &self, req: Request<Incoming>, client_socket_addr: SocketAddr, default_scheme: &'static str,
    ) -> Result<InterceptResultAdapter, io::Error> {
        if axum_handler::AXUM_PATHS.contains(&req.uri().path()) {
            return Ok(InterceptResultAdapter::Continue(req));
        }

        let (original_scheme_host_port, req_domain) = extract_scheme_host_port(&req, default_scheme)?;
        let selected = {
            let guard = self
                .runtime
                .read()
                .map_err(|_| io::Error::other("runtime lock poisoned"))?;
            let maybe_host_configs = find_location_configs_for_host(&guard.location_specs.locations, &req_domain.0);
            maybe_host_configs
                .and_then(|configs| configs.iter().find(|config| config.matches_path(req.uri().path())))
                .cloned()
        };

        let Some(LocationConfig::ReverseProxy { location, upstream, .. }) = selected else {
            return Ok(InterceptResultAdapter::Continue(req));
        };

        METRICS.reverse_proxy_requests.inc();

        let mut request = req;
        let is_websocket = is_websocket_upgrade(&request);
        if is_websocket {
            debug!("[reverse] websocket {} => {}{}", client_socket_addr, original_scheme_host_port, location);
            let client_upgrade = hyper::upgrade::on(&mut request);
            let upstream_req = build_upstream_req(&location, &upstream, request, &original_scheme_host_port)?;
            let upstream_req = box_request_body(upstream_req);
            let mut upstream_resp = self
                .reverse_proxy_client
                .request(upstream_req)
                .await
                .map_err(|err| io::Error::new(ErrorKind::InvalidData, err))?;
            if upstream_resp.status() != http::StatusCode::SWITCHING_PROTOCOLS {
                return Ok(InterceptResultAdapter::Return(map_response_body(upstream_resp)));
            }
            let upstream_upgrade = hyper::upgrade::on(&mut upstream_resp);
            spawn_websocket_tunnel(client_upgrade, upstream_upgrade, "reverse");
            return Ok(InterceptResultAdapter::Return(map_response_body(upstream_resp)));
        }

        let upstream_req = build_upstream_req(&location, &upstream, request, &original_scheme_host_port)?;
        let upstream_req = box_request_body(upstream_req);
        let mut resp = self
            .reverse_proxy_client
            .request(upstream_req)
            .await
            .map_err(|err| io::Error::new(ErrorKind::InvalidData, err))?;

        if resp.status().is_redirection() && resp.headers().contains_key(LOCATION) {
            self.normalize_redirect_response(&original_scheme_host_port, resp.headers_mut())?;
        }

        Ok(InterceptResultAdapter::Return(map_response_body(resp)))
    }
}

fn normalize_listeners(mut listeners: Vec<GatewayListenerConfig>) -> Vec<GatewayListenerConfig> {
    listeners.retain(|listener| listener.port != 0 && !listener.name.trim().is_empty());
    listeners.sort_by(|left, right| left.port.cmp(&right.port).then_with(|| left.name.cmp(&right.name)));
    listeners.dedup();
    listeners
}

fn box_request_body(req: Request<Incoming>) -> Request<BoxBody<Bytes, io::Error>> {
    req.map(|body| body.map_err(|err| io::Error::new(ErrorKind::InvalidData, err)).boxed())
}

fn map_response_body(resp: Response<Incoming>) -> Response<BoxBody<Bytes, io::Error>> {
    resp.map(|body| body.map_err(|err| io::Error::new(ErrorKind::InvalidData, err)).boxed())
}

fn build_hyper_legacy_client() -> legacy::Client<
    hyper_rustls::HttpsConnector<HttpConnector>,
    http_body_util::combinators::BoxBody<axum::body::Bytes, std::io::Error>,
> {
    let mut http_connector = HttpConnector::new();
    http_connector.enforce_http(false);

    #[cfg(debug_assertions)]
    let https_connector = {
        warn!("debug mode: TLS certificate verification is disabled for upstream requests");
        use tokio_rustls::rustls::ClientConfig;
        use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
        use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
        use tokio_rustls::rustls::{DigitallySignedStruct, SignatureScheme};

        #[derive(Debug)]
        struct NoVerifier;
        impl ServerCertVerifier for NoVerifier {
            fn verify_server_cert(
                &self, _end_entity: &CertificateDer<'_>, _intermediates: &[CertificateDer<'_>],
                _server_name: &ServerName<'_>, _ocsp_response: &[u8], _now: UnixTime,
            ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                vec![
                    SignatureScheme::RSA_PKCS1_SHA256,
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                    SignatureScheme::RSA_PSS_SHA256,
                    SignatureScheme::ED25519,
                ]
            }
        }

        let tls_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();

        HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_all_versions()
            .wrap_connector(http_connector)
    };

    #[cfg(not(debug_assertions))]
    let https_connector = HttpsConnectorBuilder::new()
        .with_platform_verifier()
        .https_or_http()
        .enable_all_versions()
        .wrap_connector(http_connector);

    legacy::Client::builder(TokioExecutor::new()).build(https_connector)
}

#[derive(Clone, Debug)]
pub(crate) struct SchemeHostPort {
    pub(crate) scheme: String,
    pub(crate) host: String,
    pub(crate) port: Option<u16>,
}

impl Display for SchemeHostPort {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.port {
            Some(port) => write!(f, "{}://{}:{}", self.scheme, self.host, port),
            None => write!(f, "{}://{}", self.scheme, self.host),
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct RequestDomain(String);

fn extract_scheme_host_port(
    req: &Request<Incoming>, default_scheme: &str,
) -> io::Result<(SchemeHostPort, RequestDomain)> {
    let uri = req.uri();
    let scheme = uri.scheme_str().unwrap_or(default_scheme);
    if req.version() == Version::HTTP_2 {
        let host_in_url = uri
            .host()
            .ok_or(io::Error::new(ErrorKind::InvalidData, "authority is absent in HTTP/2"))?
            .to_string();
        let host_in_header = req
            .headers()
            .get(http::header::HOST)
            .and_then(|host| host.to_str().ok())
            .and_then(|host_str| host_str.split(':').next())
            .map(str::to_string);
        Ok((
            SchemeHostPort {
                scheme: scheme.to_owned(),
                host: host_in_url.clone(),
                port: uri.port_u16(),
            },
            RequestDomain(host_in_header.unwrap_or(host_in_url)),
        ))
    } else {
        let host_header = req
            .headers()
            .get(http::header::HOST)
            .ok_or(io::Error::new(ErrorKind::InvalidData, "Host header is absent in HTTP/1.1"))?
            .to_str()
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        let mut split = host_header.split(':');
        let host = split
            .next()
            .ok_or(io::Error::new(ErrorKind::InvalidData, "host not in header"))?
            .to_string();
        let port = match split.next() {
            Some(port) => Some(
                port.parse::<u16>()
                    .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?,
            ),
            None => None,
        };
        Ok((
            SchemeHostPort {
                scheme: scheme.to_owned(),
                host: host.clone(),
                port,
            },
            RequestDomain(host),
        ))
    }
}

fn is_websocket_upgrade(req: &Request<Incoming>) -> bool {
    req.headers()
        .get(http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

fn spawn_websocket_tunnel(
    client_upgrade: hyper::upgrade::OnUpgrade, upstream_upgrade: hyper::upgrade::OnUpgrade, scenario: &'static str,
) {
    tokio::spawn(async move {
        match (client_upgrade.await, upstream_upgrade.await) {
            (Ok(client_upgraded), Ok(upstream_upgraded)) => {
                let mut client_io = TokioIo::new(client_upgraded);
                let mut upstream_io = TokioIo::new(upstream_upgraded);
                if let Err(err) = tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io).await {
                    warn!("[{scenario}] websocket tunnel error: {err}");
                }
            }
            (Err(err), _) => warn!("[{scenario}] websocket client upgrade error: {err}"),
            (_, Err(err)) => warn!("[{scenario}] websocket upstream upgrade error: {err}"),
        }
    });
}
