use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, Mac};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

pub fn generate_signature(secret: &str, payload: &str) -> String {
    let mut mac =
        HmacSha512::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(payload.as_bytes());
    let result = mac.finalize();
    STANDARD.encode(result.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_signature_deterministic() {
        let sig1 = generate_signature("secret", "payload");
        let sig2 = generate_signature("secret", "payload");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_generate_signature_different_secrets() {
        let sig1 = generate_signature("secret1", "payload");
        let sig2 = generate_signature("secret2", "payload");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_generate_signature_different_payloads() {
        let sig1 = generate_signature("secret", "payload1");
        let sig2 = generate_signature("secret", "payload2");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_generate_signature_is_base64() {
        let sig = generate_signature("secret", "payload");
        assert!(
            STANDARD.decode(sig).is_ok(),
            "Signature should be valid base64"
        );
    }

    #[test]
    fn test_generate_signature_sha512_length() {
        let sig = generate_signature("secret", "payload");
        let decoded = STANDARD.decode(sig).unwrap();
        assert_eq!(decoded.len(), 64, "SHA512 produces 64-byte hash");
    }
}
