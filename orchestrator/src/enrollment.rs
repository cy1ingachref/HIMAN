//! Device enrollment: the orchestrator's list of devices it will accept.
//!
//! Enrollment is what stops an identity takeover. Without it, any client that
//! can produce a valid signature can claim any device id, including one that
//! is already connected.
//!
//! The file is a JSON map of device id to base64 verifying key:
//!
//! ```json
//! {"pc-1": "b64publickey==", "phone-1": "b64publickey=="}
//! ```
//!
//! The file lives outside the repository and is gitignored. It contains public
//! keys only, so a leaked file does not compromise a device — but it does
//! reveal which devices are enrolled, so treat it as sensitive metadata.

use std::collections::HashMap;
use std::path::Path;

use himan_proto::DeviceId;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// The enrollment file: device id -> base64 verifying key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentFile(HashMap<String, String>);

impl EnrollmentFile {
    /// Load from a path. Returns an error if the file is missing or malformed.
    pub fn load(path: &Path) -> Result<Self, EnrollmentError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| EnrollmentError::Io(format!("{}: {e}", path.display())))?;
        serde_json::from_str(&text)
            .map(Self)
            .map_err(|e| EnrollmentError::Parse(e.to_string()))
    }

    /// The enrolled key for a device, if any.
    pub fn key_for(&self, device: &DeviceId) -> Option<&str> {
        self.0.get(device.as_str()).map(|s| s.as_str())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EnrollmentError {
    #[error("cannot read enrollment file: {0}")]
    Io(String),
    #[error("invalid enrollment file: {0}")]
    Parse(String),
}

/// Outcome of checking a Hello against the enrollment list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentDecision {
    /// The device is enrolled and its key matches.
    Enrolled,
    /// The device id is not in the enrollment file.
    UnknownDevice,
    /// The device is enrolled but the Hello key does not match.
    KeyMismatch,
}

/// Check a Hello's device id and key against the enrollment list.
///
/// No key material is logged: only the device id and the decision.
pub fn check_enrollment(
    enrollment: Option<&EnrollmentFile>,
    device: &DeviceId,
    hello_key_b64: &str,
) -> EnrollmentDecision {
    let Some(file) = enrollment else {
        // No enrollment file configured: Phase 1 behaviour is to accept any
        // validly signed Hello. This is insecure and is logged as such.
        warn!(
            device = %device,
            "no enrollment file configured: accepting any validly signed Hello"
        );
        return EnrollmentDecision::Enrolled;
    };

    match file.key_for(device) {
        None => {
            warn!(device = %device, "rejected: device is not enrolled");
            EnrollmentDecision::UnknownDevice
        }
        Some(enrolled) if enrolled != hello_key_b64 => {
            warn!(device = %device, "rejected: Hello key does not match enrolled key");
            EnrollmentDecision::KeyMismatch
        }
        Some(_) => EnrollmentDecision::Enrolled,
    }
}

/// Load the enrollment file from `HIMAN_ENROLLED_FILE`.
///
/// `Ok(None)` when the variable is unset. An empty path is treated as unset.
pub fn load_from_env() -> Result<Option<EnrollmentFile>, EnrollmentError> {
    let Some(path) = std::env::var("HIMAN_ENROLLED_FILE").ok() else {
        return Ok(None);
    };
    if path.trim().is_empty() {
        return Ok(None);
    }
    let file = EnrollmentFile::load(Path::new(&path))?;
    info!(
        path = %path,
        devices = file.len(),
        "loaded device enrollment"
    );
    Ok(Some(file))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_file(contents: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        f.write_all(contents.as_bytes()).expect("write");
        f.flush().expect("flush");
        f
    }

    #[test]
    fn loads_a_valid_file() {
        let f = temp_file(r#"{"pc-1":"a2V5QQ=="}"#);
        let loaded = EnrollmentFile::load(f.path()).expect("load");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.key_for(&DeviceId::new("pc-1")), Some("a2V5QQ=="));
    }

    #[test]
    fn rejects_malformed_json() {
        let f = temp_file("not json");
        assert!(EnrollmentFile::load(f.path()).is_err());
    }

    #[test]
    fn rejects_a_missing_file() {
        assert!(EnrollmentFile::load(Path::new("/nonexistent/enrolled.json")).is_err());
    }

    #[test]
    fn enrolled_key_matches() {
        let f = temp_file(r#"{"pc-1":"a2V5QQ=="}"#);
        let file = EnrollmentFile::load(f.path()).unwrap();
        assert_eq!(
            check_enrollment(Some(&file), &DeviceId::new("pc-1"), "a2V5QQ=="),
            EnrollmentDecision::Enrolled
        );
    }

    #[test]
    fn unknown_device_is_rejected() {
        let f = temp_file(r#"{"pc-1":"a2V5QQ=="}"#);
        let file = EnrollmentFile::load(f.path()).unwrap();
        assert_eq!(
            check_enrollment(Some(&file), &DeviceId::new("phone-1"), "a2V5QQ=="),
            EnrollmentDecision::UnknownDevice
        );
    }

    #[test]
    fn key_mismatch_is_rejected() {
        let f = temp_file(r#"{"pc-1":"a2V5QQ=="}"#);
        let file = EnrollmentFile::load(f.path()).unwrap();
        assert_eq!(
            check_enrollment(Some(&file), &DeviceId::new("pc-1"), "b3RoZXI="),
            EnrollmentDecision::KeyMismatch
        );
    }

    #[test]
    fn no_file_accepts_anything() {
        assert_eq!(
            check_enrollment(None, &DeviceId::new("pc-1"), "anything"),
            EnrollmentDecision::Enrolled
        );
    }
}
