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
/// Failed attempts are throttled per source IP and per presented token
/// (RT-17): the constant-time compare stops timing attacks, not online
/// guessing.
pub async fn require_token(
    State((token, limiter)): State<(ApiToken, std::sync::Arc<RateLimiter>)>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    // The source IP, when the server supplies it (it does in production
    // via into_make_service_with_connect_info). Without it the per-token
    // limit still applies.
    let ip = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip());
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");

    if limiter.is_locked(ip, presented) {
        tracing::warn!(path = %request.uri().path(), "API request refused: source is locked out after repeated failures");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed attempts; locked out",
        )
            .into_response();
    }

    if !token.matches(&headers) {
        tracing::warn!(path = %request.uri().path(), "rejected API request without a valid token");
        limiter.record_failure_opt(ip, presented);
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    limiter.record_success(ip, presented);
    next.run(request).await
}

/// Maximum tracked sources/tokens. Bounded so a spray of distinct IPs
/// cannot grow memory without limit (RT-17). When full, the oldest entry
/// is evicted — an attacker can churn entries but never exceed the cap.
pub const MAX_TRACKED: usize = 4096;

/// Failures allowed per source/token before a lockout.
const MAX_FAILURES: u32 = 10;
/// How long a lockout lasts.
const LOCKOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// A failure older than this no longer counts toward the limit.
const FAILURE_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Default)]
struct Entry {
    failures: u32,
    first_failure: Option<std::time::Instant>,
    locked_until: Option<std::time::Instant>,
}

/// Bounded per-IP and per-token failure tracker.
///
/// Two maps (source IP, presented token), each capped at `MAX_TRACKED`.
/// The token map is keyed by a SHA-256 digest, never the raw guess, so a
/// wrong token is not retained in memory or logs.
pub struct RateLimiter {
    by_ip: std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, Entry>>,
    by_token: std::sync::Mutex<std::collections::HashMap<[u8; 32], Entry>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            by_ip: std::sync::Mutex::new(std::collections::HashMap::new()),
            by_token: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn token_key(token: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(token.as_bytes()).into()
    }

    fn locked(entry: &Entry, now: std::time::Instant) -> bool {
        entry.locked_until.map(|t| now < t).unwrap_or(false)
    }

    /// Whether this source or this presented token is locked out.
    pub fn is_locked(&self, ip: Option<std::net::IpAddr>, token: &str) -> bool {
        let now = std::time::Instant::now();
        if let Some(ip) = ip {
            let map = self.by_ip.lock().expect("ip map");
            if let Some(e) = map.get(&ip) {
                if Self::locked(e, now) {
                    return true;
                }
            }
        }
        if !token.is_empty() {
            let map = self.by_token.lock().expect("token map");
            if let Some(e) = map.get(&Self::token_key(token)) {
                if Self::locked(e, now) {
                    return true;
                }
            }
        }
        false
    }

    fn bump<K: std::hash::Hash + Eq + Clone>(
        map: &mut std::collections::HashMap<K, Entry>,
        key: K,
    ) {
        let now = std::time::Instant::now();
        // Evict expired entries first; if still full, drop the oldest.
        if map.len() >= MAX_TRACKED && !map.contains_key(&key) {
            map.retain(|_, e| {
                e.locked_until.map(|t| now < t).unwrap_or(false)
                    || e.first_failure
                        .map(|t| now.duration_since(t) < FAILURE_WINDOW)
                        .unwrap_or(false)
            });
            if map.len() >= MAX_TRACKED {
                if let Some(oldest) = map
                    .iter()
                    .min_by_key(|(_, e)| e.first_failure.unwrap_or(now))
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&oldest);
                }
            }
        }
        let e = map.entry(key).or_default();
        match e.first_failure {
            Some(t) if now.duration_since(t) >= FAILURE_WINDOW => {
                e.failures = 1;
                e.first_failure = Some(now);
            }
            None => {
                e.failures = 1;
                e.first_failure = Some(now);
            }
            Some(_) => e.failures += 1,
        }
        if e.failures >= MAX_FAILURES {
            e.locked_until = Some(now + LOCKOUT);
        }
    }

    /// Record a failed attempt for a source IP and a presented token.
    pub fn record_failure(&self, ip: std::net::IpAddr, token: &str) {
        Self::bump(&mut self.by_ip.lock().expect("ip map"), ip);
        if !token.is_empty() {
            Self::bump(
                &mut self.by_token.lock().expect("token map"),
                Self::token_key(token),
            );
        }
    }

    fn record_failure_opt(&self, ip: Option<std::net::IpAddr>, token: &str) {
        if let Some(ip) = ip {
            self.record_failure(ip, token);
        } else if !token.is_empty() {
            Self::bump(
                &mut self.by_token.lock().expect("token map"),
                Self::token_key(token),
            );
        }
    }

    /// A successful auth clears the source's and token's failure state.
    fn record_success(&self, ip: Option<std::net::IpAddr>, token: &str) {
        if let Some(ip) = ip {
            self.by_ip.lock().expect("ip map").remove(&ip);
        }
        if !token.is_empty() {
            self.by_token
                .lock()
                .expect("token map")
                .remove(&Self::token_key(token));
        }
    }

    /// Total tracked entries across both maps (for the bounded-memory test).
    pub fn entries(&self) -> usize {
        self.by_ip.lock().expect("ip map").len() + self.by_token.lock().expect("token map").len()
    }
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
