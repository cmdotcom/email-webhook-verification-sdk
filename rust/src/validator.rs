use base64::{engine::general_purpose::STANDARD, Engine};
use serde::de::DeserializeOwned;
use std::collections::HashMap;

use crate::error::{Result, WebhookVerificationError};
use crate::headers;
use crate::signer;

pub struct WebhookValidator {
    secret_key: String,
    tolerance_ms: i64,
}

impl WebhookValidator {
    pub const DEFAULT_TOLERANCE_SECONDS: i64 = 300;

    pub fn new(secret_key: impl Into<String>) -> Self {
        let secret = secret_key.into();
        assert!(!secret.trim().is_empty(), "secret_key cannot be empty");

        Self {
            secret_key: secret,
            tolerance_ms: Self::DEFAULT_TOLERANCE_SECONDS * 1000,
        }
    }

    pub fn with_tolerance(secret_key: impl Into<String>, tolerance_seconds: i64) -> Self {
        let secret = secret_key.into();
        assert!(!secret.trim().is_empty(), "secret_key cannot be empty");

        Self {
            secret_key: secret,
            tolerance_ms: tolerance_seconds * 1000,
        }
    }

    pub fn verify<T: DeserializeOwned>(
        &self,
        payload: &str,
        headers: &HashMap<String, String>,
    ) -> Result<T> {
        let mut missing_headers = Vec::new();

        let id = headers.get(headers::ID);
        let timestamp_str = headers.get(headers::TIMESTAMP);
        let signature = headers.get(headers::SIGNATURE);

        if id.is_none() {
            missing_headers.push(headers::ID);
        }
        if timestamp_str.is_none() {
            missing_headers.push(headers::TIMESTAMP);
        }
        if signature.is_none() {
            missing_headers.push(headers::SIGNATURE);
        }

        if !missing_headers.is_empty() {
            return Err(WebhookVerificationError::MissingHeaders(
                missing_headers.join(", "),
            ));
        }

        let id = id.unwrap();
        let timestamp_str = timestamp_str.unwrap();
        let signature = signature.unwrap();

        let timestamp_ms: i64 = timestamp_str
            .parse()
            .map_err(|_| WebhookVerificationError::InvalidTimestamp)?;

        let current_ms = Self::current_timestamp_ms();
        let diff = (current_ms - timestamp_ms).abs();

        if diff > self.tolerance_ms {
            return Err(WebhookVerificationError::TimestampExpired);
        }

        let signature_payload = format!("{}.{}.{}", id, timestamp_ms, payload);

        let expected_signature = signer::generate_signature(&self.secret_key, &signature_payload);

        let expected_bytes = STANDARD.decode(expected_signature)?;
        let actual_bytes = STANDARD.decode(signature)?;

        if !constant_time_compare(&expected_bytes, &actual_bytes) {
            return Err(WebhookVerificationError::InvalidSignature);
        }

        let result: T = serde_json::from_str(payload)?;
        Ok(result)
    }

    fn current_timestamp_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as i64
    }
}

fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    const TEST_SECRET: &str = "test-secret-key";

    fn current_timestamp_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as i64
    }

    fn create_valid_headers(
        secret: &str,
        payload: &str,
        timestamp_ms: i64,
    ) -> HashMap<String, String> {
        let message_id = "msg-123";
        let signature_payload = format!("{}.{}.{}", message_id, timestamp_ms, payload);
        let signature = signer::generate_signature(secret, &signature_payload);

        let mut headers = HashMap::new();
        headers.insert(headers::ID.to_string(), message_id.to_string());
        headers.insert(headers::TIMESTAMP.to_string(), timestamp_ms.to_string());
        headers.insert(headers::SIGNATURE.to_string(), signature);
        headers
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct TestPayload {
        event: String,
        data: String,
    }

    #[test]
    fn test_verify_valid_webhook() {
        let validator = WebhookValidator::new(TEST_SECRET);
        let payload = r#"{"event":"test","data":"hello"}"#;
        let timestamp_ms = current_timestamp_ms();
        let headers = create_valid_headers(TEST_SECRET, payload, timestamp_ms);

        let result: TestPayload = validator.verify(payload, &headers).unwrap();
        assert_eq!(result.event, "test");
        assert_eq!(result.data, "hello");
    }

    #[test]
    fn test_verify_invalid_signature() {
        let validator = WebhookValidator::new(TEST_SECRET);
        let payload = r#"{"event":"test","data":"hello"}"#;
        let timestamp_ms = current_timestamp_ms();

        let headers = create_valid_headers("wrong-secret", payload, timestamp_ms);

        let result = validator.verify::<TestPayload>(payload, &headers);
        assert!(matches!(
            result,
            Err(WebhookVerificationError::InvalidSignature)
        ));
    }

    #[test]
    fn test_verify_missing_id_header() {
        let validator = WebhookValidator::new(TEST_SECRET);
        let payload = r#"{"event":"test"}"#;

        let mut headers = HashMap::new();
        headers.insert(headers::TIMESTAMP.to_string(), "123456".to_string());
        headers.insert(headers::SIGNATURE.to_string(), "sig".to_string());

        let result = validator.verify::<serde_json::Value>(payload, &headers);
        match result {
            Err(WebhookVerificationError::MissingHeaders(h)) => {
                assert!(h.contains(headers::ID));
            }
            _ => panic!("Expected MissingHeaders error"),
        }
    }

    #[test]
    fn test_verify_missing_timestamp_header() {
        let validator = WebhookValidator::new(TEST_SECRET);
        let payload = r#"{"event":"test"}"#;

        let mut headers = HashMap::new();
        headers.insert(headers::ID.to_string(), "msg-123".to_string());
        headers.insert(headers::SIGNATURE.to_string(), "sig".to_string());

        let result = validator.verify::<serde_json::Value>(payload, &headers);
        match result {
            Err(WebhookVerificationError::MissingHeaders(h)) => {
                assert!(h.contains(headers::TIMESTAMP));
            }
            _ => panic!("Expected MissingHeaders error"),
        }
    }

    #[test]
    fn test_verify_missing_signature_header() {
        let validator = WebhookValidator::new(TEST_SECRET);
        let payload = r#"{"event":"test"}"#;

        let mut headers = HashMap::new();
        headers.insert(headers::ID.to_string(), "msg-123".to_string());
        headers.insert(headers::TIMESTAMP.to_string(), "123456".to_string());

        let result = validator.verify::<serde_json::Value>(payload, &headers);
        match result {
            Err(WebhookVerificationError::MissingHeaders(h)) => {
                assert!(h.contains(headers::SIGNATURE));
            }
            _ => panic!("Expected MissingHeaders error"),
        }
    }

    #[test]
    fn test_verify_missing_multiple_headers() {
        let validator = WebhookValidator::new(TEST_SECRET);
        let payload = r#"{"event":"test"}"#;
        let headers = HashMap::new();

        let result = validator.verify::<serde_json::Value>(payload, &headers);
        match result {
            Err(WebhookVerificationError::MissingHeaders(h)) => {
                assert!(h.contains(headers::ID));
                assert!(h.contains(headers::TIMESTAMP));
                assert!(h.contains(headers::SIGNATURE));
            }
            _ => panic!("Expected MissingHeaders error"),
        }
    }

    #[test]
    fn test_verify_invalid_timestamp_format() {
        let validator = WebhookValidator::new(TEST_SECRET);
        let payload = r#"{"event":"test"}"#;

        let mut headers = HashMap::new();
        headers.insert(headers::ID.to_string(), "msg-123".to_string());
        headers.insert(headers::TIMESTAMP.to_string(), "not-a-number".to_string());
        headers.insert(headers::SIGNATURE.to_string(), "sig".to_string());

        let result = validator.verify::<serde_json::Value>(payload, &headers);
        assert!(matches!(
            result,
            Err(WebhookVerificationError::InvalidTimestamp)
        ));
    }

    #[test]
    fn test_verify_expired_timestamp() {
        let validator = WebhookValidator::new(TEST_SECRET);
        let payload = r#"{"event":"test","data":"hello"}"#;

        let old_timestamp = current_timestamp_ms() - (10 * 60 * 1000);
        let headers = create_valid_headers(TEST_SECRET, payload, old_timestamp);

        let result = validator.verify::<TestPayload>(payload, &headers);
        assert!(matches!(
            result,
            Err(WebhookVerificationError::TimestampExpired)
        ));
    }

    #[test]
    fn test_verify_future_timestamp_within_tolerance() {
        let validator = WebhookValidator::new(TEST_SECRET);
        let payload = r#"{"event":"test","data":"hello"}"#;

        let future_timestamp = current_timestamp_ms() + (2 * 60 * 1000);
        let headers = create_valid_headers(TEST_SECRET, payload, future_timestamp);

        let result: TestPayload = validator.verify(payload, &headers).unwrap();
        assert_eq!(result.event, "test");
    }

    #[test]
    fn test_verify_future_timestamp_outside_tolerance() {
        let validator = WebhookValidator::new(TEST_SECRET);
        let payload = r#"{"event":"test","data":"hello"}"#;

        let future_timestamp = current_timestamp_ms() + (10 * 60 * 1000);
        let headers = create_valid_headers(TEST_SECRET, payload, future_timestamp);

        let result = validator.verify::<TestPayload>(payload, &headers);
        assert!(matches!(
            result,
            Err(WebhookVerificationError::TimestampExpired)
        ));
    }

    #[test]
    fn test_custom_tolerance() {
        let validator = WebhookValidator::with_tolerance(TEST_SECRET, 1);
        let payload = r#"{"event":"test","data":"hello"}"#;

        let old_timestamp = current_timestamp_ms() - 5000;
        let headers = create_valid_headers(TEST_SECRET, payload, old_timestamp);

        let result = validator.verify::<TestPayload>(payload, &headers);
        assert!(matches!(
            result,
            Err(WebhookVerificationError::TimestampExpired)
        ));
    }

    #[test]
    #[should_panic(expected = "secret_key cannot be empty")]
    fn test_empty_secret_key_panics() {
        WebhookValidator::new("");
    }

    #[test]
    #[should_panic(expected = "secret_key cannot be empty")]
    fn test_whitespace_secret_key_panics() {
        WebhookValidator::new("   ");
    }

    #[test]
    fn test_constant_time_compare_equal() {
        let a = vec![1, 2, 3, 4];
        let b = vec![1, 2, 3, 4];
        assert!(constant_time_compare(&a, &b));
    }

    #[test]
    fn test_constant_time_compare_different() {
        let a = vec![1, 2, 3, 4];
        let b = vec![1, 2, 3, 5];
        assert!(!constant_time_compare(&a, &b));
    }

    #[test]
    fn test_constant_time_compare_different_lengths() {
        let a = vec![1, 2, 3];
        let b = vec![1, 2, 3, 4];
        assert!(!constant_time_compare(&a, &b));
    }
}
