mod error;
mod signer;
mod validator;

pub use error::{Result, WebhookVerificationError};
pub use validator::WebhookValidator;

mod headers {
    pub(crate) const ID: &str = "svix-id";
    pub(crate) const TIMESTAMP: &str = "svix-timestamp";
    pub(crate) const SIGNATURE: &str = "svix-signature";
}
