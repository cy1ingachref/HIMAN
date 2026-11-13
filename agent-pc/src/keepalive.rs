//! Agent keepalive: send a signed Ping at an interval below the orchestrator's
//! idle timeout, and treat a missing Pong as a reason to reconnect.
//!
//! Without keepalive, a healthy agent that has nothing to say is
//! indistinguishable from a dead socket. The orchestrator closes idle
//! connections, so a quiet agent would be dropped even though it is working.

use std::time::Duration;

/// The default keepalive interval.
///
/// Well below the orchestrator's 300s idle timeout: three missed pings fit
/// inside one idle window, so a single lost packet does not force a reconnect.
pub const DEFAULT_INTERVAL_SECS: u64 = 60;

/// The default number of unanswered pings tolerated before reconnecting.
pub const DEFAULT_MISS_LIMIT: u32 = 2;

/// Parse `HIMAN_KEEPALIVE_SECS`.
///
/// Returns `None` for a missing or unparseable value so the caller can fall
/// back to [`default_interval`] and log why.
pub fn parse_interval(raw: Option<&str>) -> Option<Duration> {
    let raw = raw?;
    let secs: u64 = raw.trim().parse().ok()?;
    if secs == 0 {
        return None;
    }
    Some(Duration::from_secs(secs))
}

/// The default interval.
pub fn default_interval() -> Duration {
    Duration::from_secs(DEFAULT_INTERVAL_SECS)
}

/// Resolve the configured interval, preferring the environment.
pub fn configured_interval() -> (Duration, bool) {
    match parse_interval(std::env::var("HIMAN_KEEPALIVE_SECS").ok().as_deref()) {
        Some(d) => (d, true),
        None => (default_interval(), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_valid_interval() {
        assert_eq!(parse_interval(Some("30")), Some(Duration::from_secs(30)));
    }

    #[test]
    fn rejects_zero() {
        // A zero interval would spin the loop and flood the orchestrator.
        assert_eq!(parse_interval(Some("0")), None);
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse_interval(Some("soon")), None);
        assert_eq!(parse_interval(Some("")), None);
        assert_eq!(parse_interval(None), None);
    }

    #[test]
    fn default_is_below_the_idle_timeout() {
        assert!(default_interval() < Duration::from_secs(300));
    }
}
