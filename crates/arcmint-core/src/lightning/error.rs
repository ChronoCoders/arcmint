use thiserror::Error;

#[derive(Debug, Error)]
pub enum LightningError {
    #[error("invoice creation failed: {0}")]
    InvoiceCreationFailed(String),
    #[error("payment failed: {0}")]
    PaymentFailed(String),
    #[error(
        "insufficient liquidity: required {required_msat} msat, available {available_msat} msat"
    )]
    InsufficientLiquidity {
        required_msat: u64,
        available_msat: u64,
    },
    #[error("lightning node unavailable: {0}")]
    NodeUnavailable(String),
    #[error("stream error: {0}")]
    StreamError(String),
    #[error("authentication error: {0}")]
    AuthError(String),
    #[error("invalid payment request: {0}")]
    InvalidPaymentRequest(String),
}
