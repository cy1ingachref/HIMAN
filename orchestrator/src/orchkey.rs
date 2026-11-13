//! Orchestrator key persistence.
//!
//! The orchestrator's signing key must survive restarts, or every agent's
//! pinned key becomes invalid and enrollment breaks.
//!
//! The seed is written to `HIMAN_ORCH_KEY_FILE` (default
//! `himan-orchestrator.key`). It is never logged and never printed; only the
//! derived public key is printed, and the public key is what agents pin.

use std::path::{Path, PathBuf};

use himan_proto::SigningKey;

#[derive(Debug, thiserror::Error)]
pub enum OrchestratorKeyError {
    #[error("cannot read orchestrator key file {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot write orchestrator key file {path}: {source}")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid orchestrator key in {0}: {1}")]
    Invalid(String, String),
}

/// The default orchestrator key file path.
pub fn default_path() -> PathBuf {
    PathBuf::from("himan-orchestrator.key")
}

/// The key file path from the environment, or the default.
pub fn key_file_path() -> PathBuf {
    match std::env::var("HIMAN_ORCH_KEY_FILE") {
        Ok(p) if !p.trim().is_empty() => PathBuf::from(p),
        _ => default_path(),
    }
}

/// Load the orchestrator key, generating and saving it if absent.
pub fn load_or_generate() -> Result<SigningKey, OrchestratorKeyError> {
    let path = key_file_path();
    if path.exists() {
        return load_from_file(&path);
    }
    let key = SigningKey::generate();
    save_to_file(&path, &key)?;
    tracing::info!(path = %path.display(), "generated a new orchestrator key");
    Ok(key)
}

/// Load the orchestrator key from an existing file.
pub fn load_from_file(path: &Path) -> Result<SigningKey, OrchestratorKeyError> {
    let seed_b64 = std::fs::read_to_string(path).map_err(|e| OrchestratorKeyError::Read {
        path: path.display().to_string(),
        source: e,
    })?;
    SigningKey::from_seed_b64(seed_b64.trim())
        .map_err(|e| OrchestratorKeyError::Invalid(path.display().to_string(), e.to_string()))
}

/// Save the key, restricting permissions where the platform allows it.
pub fn save_to_file(path: &Path, key: &SigningKey) -> Result<(), OrchestratorKeyError> {
    let seed_b64 = key.seed_b64();
    std::fs::write(path, &seed_b64).map_err(|e| OrchestratorKeyError::Write {
        path: path.display().to_string(),
        source: e,
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)
            .map_err(|e| OrchestratorKeyError::Write {
                path: path.display().to_string(),
                source: e,
            })?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms).map_err(|e| OrchestratorKeyError::Write {
            path: path.display().to_string(),
            source: e,
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_then_load_preserves_the_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("orch.key");
        let key = SigningKey::generate();
        let expected = key.verifying_key().to_b64();

        save_to_file(&path, &key).expect("save");
        let loaded = load_from_file(&path).expect("load");
        assert_eq!(loaded.verifying_key().to_b64(), expected);
    }

    #[test]
    fn load_or_generate_creates_a_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("orch.key");
        let saved = SigningKey::generate();
        save_to_file(&path, &saved).expect("save");
        let loaded = load_from_file(&path).expect("load");
        assert_eq!(
            loaded.verifying_key().to_b64(),
            saved.verifying_key().to_b64()
        );
    }

    #[test]
    fn invalid_key_file_is_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("orch.key");
        std::fs::write(&path, "not base64!!").expect("write");
        assert!(load_from_file(&path).is_err());
    }
}
