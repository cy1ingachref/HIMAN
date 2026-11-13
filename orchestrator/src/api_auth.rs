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
    /// Build from an explicit value, treating empty as absent.
    ///
    /// Tests use this instead of mutating the process environment.
    pub fn from_raw(value: &str) -> Option<Self> {
        if value.trim().is_empty() {
            None
        } else {
            Some(Self(value.to_owned()))
        }
    }

    /// Load from `HIMAN_API_TOKEN`.
    ///
    /// `Ok(None)` when the variable is unset. An empty value is treated as
    /// unset, because an empty token would make every request with an empty
    /// header valid.
    pub fn from_env() -> Option<Self> {
        std::env::var("HIMAN_API_TOKEN")
            .ok()
            .as_deref()
            .and_then(Self::from_raw)
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
        tokens_equal(presented, &self.0)
    }
}

/// Compare two tokens without leaking length or content through timing.
///
/// Both sides are hashed to a fixed-size SHA-256 digest before comparison, so
/// the equality check is over equal-length values and the token length is never
/// observable from the comparison time.
pub fn tokens_equal(a: &str, b: &str) -> bool {
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;

    let da = Sha256::digest(a.as_bytes());
    let db = Sha256::digest(b.as_bytes());

    // `subtle` compares in constant time regardless of where the inputs differ.
    da.ct_eq(&db).into()
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
        // Passed explicitly rather than via set_var, so the test is hermetic
        // and does not mutate process-wide state.
        assert!(ApiToken::from_raw("   ").is_none());
    }

    #[test]
    fn tokens_equal_detects_a_difference() {
        assert!(tokens_equal("abc", "abc"));
        assert!(!tokens_equal("abc", "abd"));
        // Length alone must not be observable: different lengths compare false
        // without a length early-exit.
        assert!(!tokens_equal("abc", "abcd"));
        assert!(!tokens_equal("", "x"));
        assert!(tokens_equal("", ""));
    }
}
