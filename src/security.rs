//! HTTP security: headers, CORS, client address handling and admin auth.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::PasswordVerifier;
use argon2::{Argon2, PasswordHasher};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, REFERRER_POLICY,
    WWW_AUTHENTICATE, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::routes::AppState;

pub const X_FRAGMENT: HeaderName = HeaderName::from_static("x-fragment");
pub const X_COMMENT_ID: HeaderName = HeaderName::from_static("x-comment-id");
pub const X_COMMENT_STATUS: HeaderName = HeaderName::from_static("x-comment-status");
pub const SEC_FETCH_SITE: HeaderName = HeaderName::from_static("sec-fetch-site");

#[derive(Debug, Clone, Copy)]
pub struct ClientIp(pub Option<IpAddr>);

/// Resolve the client address once per request. Behind the proxy the rightmost
/// `X-Forwarded-For` entry is the one appended by the trusted proxy, so it is
/// the only value a client cannot forge. Without a proxy the socket address is
/// used instead.
pub async fn client_ip_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let ip = resolve_client_ip(&state.cfg, request.headers(), request.extensions());
    request.extensions_mut().insert(ClientIp(ip));
    next.run(request).await
}

fn resolve_client_ip(
    config: &crate::config::Config,
    headers: &HeaderMap,
    extensions: &axum::http::Extensions,
) -> Option<IpAddr> {
    if config.trust_proxy {
        if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(last) = value
                .rsplit(',')
                .map(str::trim)
                .find(|part| !part.is_empty())
            {
                if let Ok(ip) = last.parse() {
                    return Some(ip);
                }
            }
        }
        if let Some(value) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            if let Ok(ip) = value.trim().parse() {
                return Some(ip);
            }
        }
    }
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip())
}

pub async fn security_headers_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    for (name, value) in state.security_headers.iter() {
        headers.insert(name, value.clone());
    }
    headers
        .entry(CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    response
}

/// Headers built once at startup. The CSP allows the blog stylesheet from
/// `SITE_ORIGIN` while keeping scripts disabled entirely.
pub fn build_security_headers(config: &crate::config::Config) -> HeaderMap {
    let site = &config.site_origin;
    let csp = format!(
        "default-src 'none'; style-src 'self' {site}; img-src 'self' {site} data:; \
         font-src 'self' {site}; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    );
    let csp = HeaderValue::from_str(&csp).unwrap_or_else(|_| {
        HeaderValue::from_static(
            "default-src 'none'; style-src 'self'; img-src 'self' data:; \
             form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        )
    });

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_SECURITY_POLICY, csp);
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        HeaderName::from_static("x-robots-tag"),
        HeaderValue::from_static("noindex, nofollow"),
    );
    headers
}

/// Exact-origin CORS for `/embed` and `/comment`. `X-Fragment` is a request
/// header; the comment id and status are exposed back to the blog.
pub fn cors_layer(config: &crate::config::Config) -> CorsLayer {
    let origin = HeaderValue::from_str(&config.site_origin).unwrap_or_else(|_| {
        tracing::warn!("SITE_ORIGIN is not a valid header value; CORS will reject every origin");
        HeaderValue::from_static("https://invalid.invalid")
    });
    CorsLayer::new()
        .allow_origin(AllowOrigin::list([origin]))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([CONTENT_TYPE, X_FRAGMENT])
        .expose_headers([X_COMMENT_ID, X_COMMENT_STATUS])
        .max_age(Duration::from_secs(600))
}

/// HTTP Basic for the admin routes. The password is checked with argon2id off
/// the async executor; a wrong username still pays the hashing cost so timing
/// does not reveal which half was wrong.
pub async fn admin_auth_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let authorized = match basic_credentials(request.headers().get(AUTHORIZATION)) {
        Some((user, password)) => verify_admin(&state, user, password).await,
        None => false,
    };
    if !authorized {
        let mut response = (
            StatusCode::UNAUTHORIZED,
            [(CONTENT_TYPE, "text/plain; charset=utf-8")],
            "authentication required",
        )
            .into_response();
        response.headers_mut().insert(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"comments\", charset=\"UTF-8\""),
        );
        return response;
    }
    next.run(request).await
}

async fn verify_admin(state: &AppState, user: String, password: String) -> bool {
    if user.len() > 128 || password.len() > 1024 {
        return false;
    }
    let hash = Arc::clone(&state.cfg);
    let expected_user = state.cfg.admin_user.clone();
    let joined = tokio::task::spawn_blocking(move || {
        let Ok(parsed) = PasswordHash::new(&hash.admin_password_hash) else {
            return false;
        };
        let password_ok = Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
        // Digest then compare in constant time so length differences do not
        // leak through an early exit.
        let user_ok: bool = Sha256::digest(user.as_bytes())
            .ct_eq(&Sha256::digest(expected_user.as_bytes()))
            .into();
        password_ok & user_ok
    })
    .await;
    match joined {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(%error, "admin auth task failed");
            false
        }
    }
}

fn basic_credentials(header: Option<&HeaderValue>) -> Option<(String, String)> {
    let value = header?.to_str().ok()?;
    let (scheme, encoded) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let encoded = encoded.trim();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (user, password) = decoded.split_once(':')?;
    Some((user.to_owned(), password.to_owned()))
}

/// Login pages are HTML forms posted with Basic credentials cached by the
/// browser, which makes them reachable from another site. Cross-site POSTs are
/// rejected here in addition to the signed action token; `Sec-Fetch-Site` is
/// ignored when absent so curl and older clients still work.
pub fn admin_post_allowed(headers: &HeaderMap) -> bool {
    match headers
        .get(SEC_FETCH_SITE)
        .and_then(|value| value.to_str().ok())
    {
        None | Some("same-origin") | Some("none") => true,
        Some(_) => false,
    }
}

/// Generate a PHC string for `hash-password`.
pub fn hash_admin_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_credentials() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("admin:pa:ss");
        let header = HeaderValue::from_str(&format!("Basic {encoded}")).unwrap();
        assert_eq!(
            basic_credentials(Some(&header)),
            Some(("admin".to_owned(), "pa:ss".to_owned()))
        );
    }

    #[test]
    fn accepts_any_scheme_case() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("admin:pw");
        for scheme in ["Basic", "basic", "BASIC"] {
            let header = HeaderValue::from_str(&format!("{scheme} {encoded}")).unwrap();
            assert_eq!(
                basic_credentials(Some(&header)),
                Some(("admin".to_owned(), "pw".to_owned()))
            );
        }
    }

    #[test]
    fn rejects_malformed_basic_headers() {
        assert_eq!(basic_credentials(None), None);
        assert_eq!(
            basic_credentials(Some(&HeaderValue::from_static("Bearer abc"))),
            None
        );
        assert_eq!(
            basic_credentials(Some(&HeaderValue::from_static("Basic !!!"))),
            None
        );
    }
}
