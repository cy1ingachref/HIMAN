//! HTTP API authentication.
//!
//! Every `/api/v1/*` endpoint except `/health` requires a bearer token. The
//! token is a pre-shared secret from `HIMAN_API_TOKEN`; without it the API is
//! completely open, which means anyone who can reach the port can dispatch
//! tool calls to every enrolled device.
//!
//! The comparison is constant-time so a wrong token cannot be found by timing.
//! The token itself is never logged.

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

/// The shared API token.
#[derive(Debug, Clone)]
pub struct ApiToken(pub String);

impl ApiToken {
    /// Load from `HIMAN_API_TOKEN`.
    ///
    /// `Ok(None)` when the variable is unset. An empty value is treated as
    /// unset, because an empty token would make every request with an empty
    /// header valid.
    pub fn from_env() -> Option<Self> {
        std::env::var("HIMAN_API_TOKEN")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .map(Self)
    }

    /// Whether the presented headers carry this token.
    ///
    /// Constant-time comparison: the length is checked first (which leaks
    /// length only), then the bytes are compared without early exit.
    pub fn matches(&self, headers: &HeaderMap) -> bool {
        let Some(value) = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        else {
            return false;
        };
        let Some(presented) = value.strip_prefix("Bearer ") else {
            return false;
        };
        constant_time_eq(presented.as_bytes(), self.0.as_bytes())
    }
}

/// Compare two byte strings without early exit.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Axum middleware that rejects requests without a valid bearer token.
///
/// `health` is exempt so a load balancer can probe without a token.
pub async fn require_token(
    State(token): State<ApiToken>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if !token.matches(&headers) {
        tracing::warn!(path = %request.uri().path(), "rejected API request without a valid token");
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_a_correct_token() {
        let token = ApiToken("secret".into());
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer secret".parse().unwrap());
        assert!(token.matches(&headers));
    }

    #[test]
    fn rejects_a_missing_header() {
        let token = ApiToken("secret".into());
        assert!(!token.matches(&HeaderMap::new()));
    }

    #[test]
    fn rejects_a_wrong_token() {
        let token = ApiToken("secret".into());
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer wrong".parse().unwrap());
        assert!(!token.matches(&headers));
    }

    #[test]
    fn rejects_a_missing_bearer_prefix() {
        let token = ApiToken("secret".into());
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "secret".parse().unwrap());
        assert!(!token.matches(&headers));
    }

    #[test]
    fn rejects_an_empty_token() {
        let token = ApiToken("secret".into());
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer ".parse().unwrap());
        assert!(!token.matches(&headers));
    }

    #[test]
    fn from_env_ignores_an_empty_value() {
        std::env::set_var("HIMAN_API_TOKEN", "   ");
        assert!(ApiToken::from_env().is_none());
        std::env::remove_var("HIMAN_API_TOKEN");
    }

    #[test]
    fn constant_time_eq_detects_a_difference() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
