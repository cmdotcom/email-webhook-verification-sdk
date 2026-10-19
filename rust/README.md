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

The `svix-timestamp` header is a Unix timestamp in **milliseconds**. The tolerance you configure is in seconds.

## Replay Protection and Duplicate Events

The timestamp check limits how long a captured webhook stays valid (5 minutes by default). It does not stop an exact copy of a valid webhook from being accepted again inside that window. The signature still prevents anyone without your secret key from changing a webhook. We can also deliver the same event more than once, for example when we retry a delivery.

To make your handler safe, deduplicate on `data.id` from the verified payload:

```rust
use std::collections::HashSet;

// Use a shared store in production, for example a database unique key or Redis SET NX
let mut processed_event_ids: HashSet<String> = HashSet::new();

let data = validator.verify::<serde_json::Value>(payload, &headers)?;
let event_id = data["data"]["id"].as_str().unwrap_or_default().to_string();

if !processed_event_ids.insert(event_id) {
    return Ok(()); // already handled, still respond with 200
}

// Process the event
```

Do not use the `svix-id` header for this. It is the ID of the email message, so all events for one message (for example sent, delivered and bounced) share it, and skipping on it would drop real events. `data.id` is unique per event and stays the same when we retry that event. Events can also arrive out of order, so compare `createdAt` before an older event overwrites newer state.

See [Best practices](https://developers.cm.com/messaging/docs/webhook-verification#best-practices) in the webhook verification docs.

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
- **Timestamp validation** to limit how long a captured webhook stays valid (see [Replay Protection and Duplicate Events](#replay-protection-and-duplicate-events))


