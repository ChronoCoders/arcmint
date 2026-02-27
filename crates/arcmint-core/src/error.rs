use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArcMintError {
    #[error("crypto error: {0}")]
    CryptoError(String),

    #[error("invalid note: {0}")]
    InvalidNote(String),

    #[error("double spend for serial: {serial}")]
    DoubleSpend { serial: String },

    #[error("registry error: {0}")]
    RegistryError(String),

    #[error("signing error: {0}")]
    SigningError(String),

    #[error("invalid proof: {0}")]
    InvalidProof(String),

    #[error("gateway error: {0}")]
    GatewayError(String),

    #[error(transparent)]
    DatabaseError(#[from] sqlx::Error),

    #[error(transparent)]
    SerializationError(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, ArcMintError>;
