use thiserror::Error;

/// Errors produced by the protocol layer.
#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("signature verification failed: {0}")]
    BadSignature(String),

    #[error("invalid public key: {0}")]
    BadKey(String),

    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("invalid base64: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("invalid hex: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("message rejected by policy: {0}")]
    Policy(String),

    #[error("unknown message kind: {0}")]
    UnknownKind(String),
}

pub type ProtoResult<T> = Result<T, ProtoError>;
