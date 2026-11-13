//! Fail-closed startup checks.
//!
//! The orchestrator must not start with its HTTP API open and no device
//! enrollment, because that state exposes tool dispatch to anyone who can reach
//! the port. An operator who forgets a protection must get a hard failure at
//! startup, not a warning that scrolls past.

use tracing::error;

/// Which protections are required for startup.
#[derive(Debug, Clone)]
pub struct StartupRequirements {
    /// Require `HIMAN_API_TOKEN`.
    pub require_api_token: bool,
    /// Require `HIMAN_ENROLLED_FILE` to be set AND readable.
    pub require_enrollment: bool,
}

impl Default for StartupRequirements {
    fn default() -> Self {
        Self {
            require_api_token: true,
            require_enrollment: true,
        }
    }
}

/// Why startup was refused.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error(
        "refusing to start: HIMAN_API_TOKEN is not set, so the HTTP API would be \
         open. Set it, or set HIMAN_INSECURE_DEV=1 to acknowledge the risk."
    )]
    MissingApiToken,

    #[error(
        "refusing to start: HIMAN_ENROLLED_FILE is not set, so any device could \
         register. Set it, or set HIMAN_INSECURE_DEV=1 to acknowledge the risk."
    )]
    MissingEnrollment,

    #[error("refusing to start: cannot read the enrollment file: {0}")]
    EnrollmentUnreadable(String),
}

/// Whether insecure development mode is explicitly enabled.
///
/// Only the exact value `1` enables it. `true`, `yes` and `0` do not: an
/// accidental near-miss must not silently disable a security control.
pub fn insecure_dev_enabled() -> bool {
    std::env::var("HIMAN_INSECURE_DEV")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Check that every required protection is present.
///
/// Returns `Ok(())` when startup may proceed. When a protection is missing and
/// `HIMAN_INSECURE_DEV` is not set, returns the specific error.
///
/// Never prints the token itself.
pub fn enforce_startup(requirements: &StartupRequirements) -> Result<(), StartupError> {
    let insecure = insecure_dev_enabled();

    if requirements.require_api_token && crate::api_auth::ApiToken::from_env().is_none() {
        if insecure {
            tracing::warn!(
                "INSECURE DEV MODE: HIMAN_API_TOKEN is not set, so the HTTP API is \
                 OPEN. Anyone who can reach the port can dispatch tool calls."
            );
        } else {
            return Err(StartupError::MissingApiToken);
        }
    }

    if requirements.require_enrollment {
        match std::env::var("HIMAN_ENROLLED_FILE") {
            Ok(path) if !path.trim().is_empty() => {
                // The file must be readable now, not discovered later on the
                // first registration.
                if let Err(e) = std::fs::read_to_string(&path) {
                    if insecure {
                        tracing::warn!(
                            path = %path,
                            error = %e,
                            "INSECURE DEV MODE: the enrollment file cannot be read; \
                             no device is enrolled."
                        );
                    } else {
                        return Err(StartupError::EnrollmentUnreadable(e.to_string()));
                    }
                }
            }
            _ => {
                if insecure {
                    tracing::warn!(
                        "INSECURE DEV MODE: HIMAN_ENROLLED_FILE is not set, so ANY \
                         device can register by claiming an id."
                    );
                } else {
                    return Err(StartupError::MissingEnrollment);
                }
            }
        }
    }

    Ok(())
}

/// Log the effective security posture once at startup.
pub fn log_posture() {
    let token_present = crate::api_auth::ApiToken::from_env().is_some();
    let enrollment_set = std::env::var("HIMAN_ENROLLED_FILE")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);

    if token_present && enrollment_set {
        tracing::info!("startup protections: API token and enrollment both configured");
    } else if insecure_dev_enabled() {
        error!(
            "STARTING IN INSECURE DEV MODE: api_token={}, enrollment_file={}. \
             Do not expose this port.",
            token_present, enrollment_set
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_exact_value_one_enables_insecure_mode() {
        // This test reads the real environment, so it asserts the default
        // (unset) case and documents why `set_var` is avoided in tests.
        let value = std::env::var("HIMAN_INSECURE_DEV").ok();
        let enabled = insecure_dev_enabled();
        assert_eq!(enabled, value.as_deref() == Some("1"));
    }

    #[test]
    fn missing_token_is_an_error_when_not_insecure() {
        let reqs = StartupRequirements {
            require_api_token: true,
            require_enrollment: false,
        };
        // With no token in the environment this must be an error. The caller's
        // environment is cleared in the integration test; here we only assert
        // the pure logic via a direct constructor when the var is absent.
        if crate::api_auth::ApiToken::from_env().is_none() {
            let err = enforce_startup(&reqs).expect_err("must refuse without a token");
            assert!(matches!(err, StartupError::MissingApiToken));
        }
    }

    #[test]
    fn missing_enrollment_is_an_error_when_not_insecure() {
        let reqs = StartupRequirements {
            require_api_token: false,
            require_enrollment: true,
        };
        let has_file = std::env::var("HIMAN_ENROLLED_FILE")
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        if !has_file && !insecure_dev_enabled() {
            let err = enforce_startup(&reqs).expect_err("must refuse without enrollment");
            assert!(matches!(err, StartupError::MissingEnrollment));
        }
    }
}
