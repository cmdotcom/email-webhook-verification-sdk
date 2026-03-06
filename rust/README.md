# CM Email Webhook Verification SDK (Rust)

SDK for verifying the authenticity of webhooks sent by CM Email services.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
cm-email-webhook-verification = "1.0"
```

## Usage

```rust
use cm_email_webhook_verification::WebhookValidator;
use std::collections::HashMap;

fn handle_webhook(payload: &str, headers: &HashMap<String, String>) {
    let validator = WebhookValidator::new("your-secret-key");

    match validator.verify::<serde_json::Value>(payload, headers) {
        Ok(data) => {
            println!("Verified webhook: {:?}", data);
            // Process the webhook data
        }
        Err(e) => {
            eprintln!("Webhook verification failed: {}", e);
        }
    }
}
```

## Axum Example

```rust
use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    body::Bytes,
};
use cm_email_webhook_verification::WebhookValidator;
use std::collections::HashMap;

async fn webhook_handler(
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let validator = WebhookValidator::new("your-secret-key");

    let headers_map: HashMap<String, String> = headers
        .iter()
        .filter_map(|(k, v)| {
            Some((k.as_str().to_string(), v.to_str().ok()?.to_string()))
        })
        .collect();

    let payload = String::from_utf8_lossy(&body);

    match validator.verify::<serde_json::Value>(&payload, &headers_map) {
        Ok(_data) => StatusCode::OK,
        Err(_) => StatusCode::UNAUTHORIZED,
    }
}
```

## Custom Tolerance

By default, webhooks are valid for 5 minutes. Customize with:

```rust
// Accept webhooks up to 10 minutes old
let validator = WebhookValidator::with_tolerance("your-secret-key", 600);
```

## Error Handling

```rust
use cm_email_webhook_verification::{WebhookValidator, WebhookVerificationError};

match validator.verify::<MyPayload>(payload, &headers) {
    Ok(data) => { /* success */ }
    Err(WebhookVerificationError::MissingHeaders(h)) => {
        eprintln!("Missing headers: {}", h);
    }
    Err(WebhookVerificationError::InvalidSignature) => {
        eprintln!("Signature mismatch");
    }
    Err(WebhookVerificationError::TimestampExpired) => {
        eprintln!("Webhook too old");
    }
    Err(e) => {
        eprintln!("Other error: {}", e);
    }
}
```

## Security

This SDK uses:
- **HMAC-SHA512** for signature generation
- **Constant-time comparison** to prevent timing attacks
- **Timestamp validation** to prevent replay attacks


