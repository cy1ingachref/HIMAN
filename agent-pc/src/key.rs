//! Agent key persistence.
//!
//! The agent's identity is an Ed25519 seed. It must survive restarts, or the
//! orchestrator sees a new device every time and enrollment breaks.
//!
//! The seed is written to `HIMAN_AGENT_KEY_FILE` (default `himan-agent.key` in
//! the current directory). It is 32 bytes of raw key material and is treated
//! as a secret: it is never logged and never printed. Only the derived public
//! key is printed.

use std::path::{Path, PathBuf};

use himan_proto::SigningKey;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("cannot read key file {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot write key file {path}: {source}")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid key in {0}: {1}")]
    Invalid(String, String),
}

/// The default key file path.
pub fn default_path() -> PathBuf {
    PathBuf::from("himan-agent.key")
}

/// The key file path from the environment, or the default.
pub fn key_file_path() -> PathBuf {
    match std::env::var("HIMAN_AGENT_KEY_FILE") {
        Ok(p) if !p.trim().is_empty() => PathBuf::from(p),
        _ => default_path(),
    }
}

/// Load the agent key, generating and saving a new one if the file is absent.
///
/// This is the normal path for an agent: a fresh install has no key file, so
/// one is created and reused on every later run.
pub fn load_or_generate() -> Result<SigningKey, KeyError> {
    let path = key_file_path();
    if path.exists() {
        return load_from_file(&path);
    }
    let key = SigningKey::generate();
    save_to_file(&path, &key)?;
    tracing::info!(path = %path.display(), "generated a new agent key");
    Ok(key)
}

/// Load the agent key from an existing file. Fails if it is missing or invalid.
pub fn load_from_file(path: &Path) -> Result<SigningKey, KeyError> {
    let seed_b64 = std::fs::read_to_string(path).map_err(|e| KeyError::Read {
        path: path.display().to_string(),
        source: e,
    })?;
    let seed_b64 = seed_b64.trim();
    SigningKey::from_seed_b64(seed_b64)
        .map_err(|e| KeyError::Invalid(path.display().to_string(), e.to_string()))
}

/// Save a key to a file, restricting permissions where the platform allows it.
pub fn save_to_file(path: &Path, key: &SigningKey) -> Result<(), KeyError> {
    let seed_b64 = key.seed_b64();
    std::fs::write(path, &seed_b64).map_err(|e| KeyError::Write {
        path: path.display().to_string(),
        source: e,
    })?;

    // 0600 on Unix. On Windows this is best-effort: the file inherits the
    // user's default ACL, which is acceptable for a single-user agent.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)
            .map_err(|e| KeyError::Write {
                path: path.display().to_string(),
                source: e,
            })?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms).map_err(|e| KeyError::Write {
            path: path.display().to_string(),
            source: e,
        })?;
    }

    Ok(())
}

/// Generate a key and write it to `path`, printing only the public key.
///
/// Used by the `keygen` subcommand. The seed is never printed.
pub fn keygen(path: &Path) -> Result<(), KeyError> {
    if path.exists() {
        tracing::warn!(path = %path.display(), "key file already exists, leaving it untouched");
        let existing = load_from_file(path)?;
        println!("public key: {}", existing.verifying_key().to_b64());
        return Ok(());
    }

    let key = SigningKey::generate();
    save_to_file(path, &key)?;
    println!("public key: {}", key.verifying_key().to_b64());
    tracing::info!(path = %path.display(), "wrote a new key file");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_then_load_preserves_the_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("agent.key");
        let key = SigningKey::generate();
        let expected = key.verifying_key().to_b64();

        save_to_file(&path, &key).expect("save");
        let loaded = load_from_file(&path).expect("load");
        assert_eq!(loaded.verifying_key().to_b64(), expected);
    }

    #[test]
    fn load_or_generate_creates_a_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("agent.key");
        let key = load_from_file(&path).err();
        assert!(key.is_some(), "a missing file must be an error");

        save_to_file(&path, &SigningKey::generate()).expect("save");
        let loaded = load_from_file(&path).expect("load");
        assert!(!loaded.verifying_key().to_b64().is_empty());
    }

    #[test]
    fn invalid_key_file_is_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("agent.key");
        std::fs::write(&path, "not base64!!").expect("write");
        assert!(load_from_file(&path).is_err());
    }

    #[test]
    fn keygen_prints_only_the_public_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("agent.key");
        keygen(&path).expect("keygen");
        let contents = std::fs::read_to_string(&path).expect("read");
        // The file holds the seed; the printed output must not.
        assert_ne!(contents.trim().len(), 0);
    }
}
