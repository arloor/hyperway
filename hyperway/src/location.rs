use http::header::LOCATION;
use http::{HeaderName, HeaderValue, Request, Uri, header};
use hyper::body::Incoming;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::str::FromStr;

#[derive(Clone)]
pub(crate) struct RedirectBackpaths {
    pub(crate) redirect_url: String,
    pub(crate) host: String,
    pub(crate) location: String,
}

pub(crate) const DEFAULT_HOST: &str = "default_host";

#[derive(Serialize, Deserialize, Eq, PartialEq, Copy, Clone, Debug, Ord, PartialOrd)]
pub(crate) enum LocationPathMatch {
    #[serde(rename = "PREFIX")]
    Prefix,
    #[serde(rename = "EXACT")]
    Exact,
}

fn default_location_path_match() -> LocationPathMatch {
    LocationPathMatch::Prefix
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug)]
#[serde(untagged)]
pub(crate) enum LocationConfig {
    ReverseProxy {
        #[serde(default = "root")]
        location: String,
        #[serde(default = "default_location_path_match")]
        match_type: LocationPathMatch,
        upstream: Upstream,
    },
}

impl std::cmp::PartialOrd for LocationConfig {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for LocationConfig {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let location_order = self.location().cmp(other.location()).reverse();
        if location_order != std::cmp::Ordering::Equal {
            return location_order;
        }
        self.path_match().cmp(&other.path_match()).reverse()
    }
}

impl LocationConfig {
    pub(crate) fn location(&self) -> &str {
        match self {
            LocationConfig::ReverseProxy { location, .. } => location,
        }
    }

    pub(crate) fn path_match(&self) -> LocationPathMatch {
        match self {
            LocationConfig::ReverseProxy { match_type, .. } => *match_type,
        }
    }

    pub(crate) fn matches_path(&self, path: &str) -> bool {
        match self.path_match() {
            LocationPathMatch::Prefix => path.starts_with(self.location()),
            LocationPathMatch::Exact => path == self.location(),
        }
    }
}

pub(crate) fn build_upstream_req(
    location: &str, upstream: &Upstream, req: Request<Incoming>,
    original_scheme_host_port: &crate::proxy::SchemeHostPort,
) -> io::Result<Request<Incoming>> {
    let method = req.method().clone();
    let path_and_query = match req.uri().path_and_query() {
        Some(path_and_query) => path_and_query.as_str(),
        None => "",
    };
    let upstream_url = upstream.url_base.clone() + &path_and_query[location.len()..];
    let upstream_uri = upstream_url
        .parse::<Uri>()
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;

    let mut builder = Request::builder()
        .method(method)
        .uri(upstream_uri)
        .version(match upstream.version {
            Version::H1 => http::Version::HTTP_11,
            Version::H2 => http::Version::HTTP_2,
            Version::Auto => {
                if upstream.url_base.starts_with("https:") {
                    req.version()
                } else {
                    http::Version::HTTP_11
                }
            }
        });
    let header_map = match builder.headers_mut() {
        Some(header_map) => header_map,
        None => {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "new_req.headers_mut() is None, check URL/method/version",
            ));
        }
    };
    for ele in req.headers() {
        if ele.0 != header::HOST {
            header_map.append(ele.0.clone(), ele.1.clone());
        }
    }

    if let Some(ref headers) = upstream.headers {
        for (key, value) in headers {
            if value.is_empty() || key.is_empty() {
                warn!("skip empty header value for key: {}", key);
                continue;
            }
            let mut header_value = value.clone();
            if value == "#{host}" {
                if let Some(port) = original_scheme_host_port.port {
                    header_value = format!("{}:{port}", original_scheme_host_port.host);
                } else {
                    header_value = original_scheme_host_port.host.clone();
                }
            }
            if let Some(old_value) = header_map.insert(
                HeaderName::from_str(key).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?,
                HeaderValue::from_str(&header_value).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?,
            ) {
                info!("override header {} from {old_value:?} to: {}", key, value);
            }
        }
    }
    builder
        .body(req.into_body())
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
}

pub(crate) fn normalize302(
    original_scheme_host_port: &crate::proxy::SchemeHostPort, resp_headers: &mut http::HeaderMap,
    redirect_bachpaths: &[RedirectBackpaths],
) -> Result<(), io::Error> {
    let redirect_url = resp_headers
        .get_mut(LOCATION)
        .ok_or(io::Error::new(ErrorKind::InvalidData, "LOCATION absent when 30x"))?
        .to_str()
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?
        .parse::<Uri>()
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    if redirect_url.scheme_str().is_none() {
        info!("normalize302: redirect_url is relative, don't touch it");
        return Ok(());
    }
    if let Some(replacement) =
        lookup_replacement(original_scheme_host_port, redirect_url.to_string(), redirect_bachpaths)
    {
        let origin = resp_headers.insert(
            LOCATION,
            HeaderValue::from_str(replacement.as_str()).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?,
        );
        info!("normalize302: result is [{replacement}], before is [{origin:?}]");
    };
    Ok(())
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug)]
pub(crate) struct Upstream {
    pub(crate) url_base: String,
    #[serde(default = "default_version")]
    pub(crate) version: Version,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) headers: Option<HashMap<String, String>>,
}

fn default_version() -> Version {
    Version::Auto
}

fn root() -> String {
    "/".to_owned()
}

#[derive(PartialEq, PartialOrd, Copy, Clone, Eq, Ord, Hash, Serialize, Deserialize, Debug)]
pub(crate) enum Version {
    #[serde(rename = "H1")]
    H1,
    #[serde(rename = "H2")]
    H2,
    #[serde(rename = "AUTO")]
    Auto,
}

fn lookup_replacement(
    origin_scheme_host_port: &crate::proxy::SchemeHostPort, absolute_redirect_url: String,
    redirect_bachpaths: &[RedirectBackpaths],
) -> Option<String> {
    for backpath in redirect_bachpaths.iter() {
        if absolute_redirect_url.starts_with(backpath.redirect_url.as_str()) {
            info!(
                "redirect back path for {}** is http(s)://{}:port{}**",
                backpath.redirect_url, backpath.host, backpath.location,
            );
            let host = match backpath.host.as_str() {
                DEFAULT_HOST => &origin_scheme_host_port.host,
                other => other,
            };
            let port_part = if let Some(port) = origin_scheme_host_port.port {
                format!(":{port}")
            } else {
                String::new()
            };
            return Some(
                origin_scheme_host_port.scheme.to_owned()
                    + "://"
                    + host
                    + &port_part
                    + &backpath.location
                    + &absolute_redirect_url[backpath.redirect_url.len()..],
            );
        }
    }
    None
}

#[derive(Clone)]
pub(crate) struct LocationSpecs {
    pub(crate) locations: HashMap<String, Vec<LocationConfig>>,
    pub(crate) redirect_bachpaths: Vec<RedirectBackpaths>,
}

pub(crate) fn find_location_configs_for_host<'a>(
    locations: &'a HashMap<String, Vec<LocationConfig>>, host: &str,
) -> Option<&'a Vec<LocationConfig>> {
    if let Some(exact_match) = locations.get(host) {
        return Some(exact_match);
    }

    let wildcard_match = locations
        .iter()
        .filter_map(|(pattern, configs)| wildcard_priority(pattern, host).map(|priority| (priority, configs)))
        .max_by_key(|(priority, _)| *priority)
        .map(|(_, configs)| configs);
    wildcard_match.or_else(|| locations.get(DEFAULT_HOST))
}

fn wildcard_priority(pattern: &str, host: &str) -> Option<usize> {
    if pattern == "*" {
        return Some(0);
    }
    let suffix = pattern.strip_prefix("*.")?;
    let required_suffix = format!(".{suffix}");
    if host.len() <= required_suffix.len() {
        return None;
    }
    if !host.ends_with(&required_suffix) {
        return None;
    }
    Some(suffix.len())
}

pub(crate) fn build_location_specs(
    mut locations: HashMap<String, Vec<LocationConfig>>,
) -> Result<LocationSpecs, crate::DynError> {
    locations
        .iter_mut()
        .for_each(|(_, location_configs)| location_configs.sort());
    info!("parsed location specs: \n{}", serde_yaml_bw::to_string(&locations)?);
    for ele in &mut locations {
        for location_config in ele.1 {
            if !location_config.location().starts_with('/') {
                return Err("location should start with '/'".into());
            }

            let LocationConfig::ReverseProxy {
                location,
                match_type,
                upstream,
            } = location_config;
            match upstream.url_base.parse::<Uri>() {
                Ok(upstream_url_base) => {
                    if upstream_url_base.scheme().is_none() {
                        return Err(
                            format!("wrong upstream_url_base: {} --- scheme is empty", upstream.url_base).into()
                        );
                    }
                    if upstream_url_base.authority().is_none() {
                        return Err(
                            format!("wrong upstream_url_base: {} --- authority is empty", upstream.url_base).into()
                        );
                    }
                    if upstream_url_base.query().is_some() {
                        return Err(
                            format!("wrong upstream_url_base: {} --- query is not empty", upstream.url_base).into()
                        );
                    }
                    if location.ends_with('/')
                        && upstream_url_base.path() == "/"
                        && !upstream.url_base.ends_with('/')
                        && *match_type == LocationPathMatch::Prefix
                    {
                        upstream.url_base = upstream_url_base.to_string();
                    }
                }
                Err(e) => return Err(format!("parse upstream upstream_url_base error:{e}").into()),
            }
        }
    }

    let mut redirect_bachpaths = Vec::<RedirectBackpaths>::new();
    for (host, location_configs) in &locations {
        for location_config in location_configs {
            let LocationConfig::ReverseProxy { location, upstream, .. } = location_config;
            redirect_bachpaths.push(RedirectBackpaths {
                redirect_url: upstream.url_base.clone(),
                host: host.clone(),
                location: location.clone(),
            });
        }
    }
    redirect_bachpaths.sort_by(|a, b| a.redirect_url.cmp(&b.redirect_url).reverse());
    for ele in redirect_bachpaths.iter() {
        info!("find redirect back path for: {}**", ele.redirect_url);
    }
    Ok(LocationSpecs {
        locations,
        redirect_bachpaths,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_host_match_prefers_more_specific_suffix() {
        let mut locations = HashMap::<String, Vec<LocationConfig>>::new();
        locations.insert(
            "*.example.com".to_string(),
            vec![LocationConfig::ReverseProxy {
                location: "/a".to_string(),
                match_type: LocationPathMatch::Prefix,
                upstream: Upstream {
                    url_base: "http://example.com/a".to_string(),
                    version: Version::Auto,
                    headers: None,
                },
            }],
        );
        locations.insert(
            "*.svc.example.com".to_string(),
            vec![LocationConfig::ReverseProxy {
                location: "/b".to_string(),
                match_type: LocationPathMatch::Prefix,
                upstream: Upstream {
                    url_base: "http://example.com/b".to_string(),
                    version: Version::Auto,
                    headers: None,
                },
            }],
        );
        locations.insert(DEFAULT_HOST.to_string(), vec![]);
        let matched = find_location_configs_for_host(&locations, "api.svc.example.com");
        let location = matched
            .and_then(|configs| configs.first())
            .map(LocationConfig::location);
        assert_eq!(location, Some("/b"));
    }

    #[test]
    fn exact_and_prefix_path_match() {
        let exact = LocationConfig::ReverseProxy {
            location: "/foo".to_string(),
            match_type: LocationPathMatch::Exact,
            upstream: Upstream {
                url_base: "http://example.com/foo".to_string(),
                version: Version::Auto,
                headers: None,
            },
        };
        assert!(exact.matches_path("/foo"));
        assert!(!exact.matches_path("/foo/bar"));

        let prefix = LocationConfig::ReverseProxy {
            location: "/foo".to_string(),
            match_type: LocationPathMatch::Prefix,
            upstream: Upstream {
                url_base: "http://example.com/foo".to_string(),
                version: Version::Auto,
                headers: None,
            },
        };
        assert!(prefix.matches_path("/foo/bar"));
    }

    #[test]
    fn normalize302_replaces_default_host() {
        let origin = crate::proxy::SchemeHostPort {
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            port: Some(8443),
        };
        let mut headers = http::HeaderMap::new();
        headers.insert(LOCATION, HeaderValue::from_static("http://backend.default.svc.cluster.local:80/login"));
        let redirect_paths = vec![RedirectBackpaths {
            redirect_url: "http://backend.default.svc.cluster.local:80".to_string(),
            host: DEFAULT_HOST.to_string(),
            location: "/api".to_string(),
        }];
        assert!(normalize302(&origin, &mut headers, &redirect_paths).is_ok());
        let replaced = headers
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        assert_eq!(replaced, "https://example.com:8443/api/login");
    }
}
