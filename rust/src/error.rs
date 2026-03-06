use thiserror::Error;

pub type Result<T> = std::result::Result<T, WebhookVerificationError>;

#[derive(Debug, Error)]
pub enum WebhookVerificationError {
    #[error("Missing required header(s): {0}")]
    MissingHeaders(String),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid timestamp format")]
    InvalidTimestamp,

    #[error("Webhook timestamp is outside the allowed tolerance window")]
    TimestampExpired,

    #[error("Failed to deserialize payload: {0}")]
    DeserializationError(#[from] serde_json::Error),

    #[error("Failed to decode signature: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),
}
