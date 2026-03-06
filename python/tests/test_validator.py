import json
import time

import pytest

from cm_email_webhook_verification import (
    InvalidSignatureError,
    MissingHeaderError,
    TimestampExpiredError,
    WebhookValidator,
)
from cm_email_webhook_verification.signer import generate_signature


class TestWebhookValidator:

    def setup_method(self) -> None:
        self.secret_key = "test-secret-key"
        self.validator = WebhookValidator(self.secret_key)

    def _create_valid_headers(self, payload: str) -> dict[str, str]:
        message_id = "msg-123"
        timestamp_ms = int(time.time() * 1000)
        signature_payload = f"{message_id}.{timestamp_ms}.{payload}"
        signature = generate_signature(self.secret_key, signature_payload)

        return {
            "svix-id": message_id,
            "svix-timestamp": str(timestamp_ms),
            "svix-signature": signature,
        }

    def test_verify_valid_webhook(self) -> None:
        payload = json.dumps({"event": "test", "data": {"id": 123}})
        headers = self._create_valid_headers(payload)

        result = self.validator.verify(payload, headers)

        assert result["event"] == "test"
        assert result["data"]["id"] == 123

    def test_verify_invalid_signature(self) -> None:
        payload = json.dumps({"event": "test"})
        headers = self._create_valid_headers(payload)
        headers["svix-signature"] = "invalid-signature"

        with pytest.raises(InvalidSignatureError):
            self.validator.verify(payload, headers)

    def test_verify_missing_headers(self) -> None:
        payload = json.dumps({"event": "test"})

        with pytest.raises(MissingHeaderError):
            self.validator.verify(payload, {})

    def test_verify_missing_single_header(self) -> None:
        payload = json.dumps({"event": "test"})
        headers = self._create_valid_headers(payload)
        del headers["svix-id"]

        with pytest.raises(MissingHeaderError) as exc_info:
            self.validator.verify(payload, headers)

        assert "svix-id" in str(exc_info.value)

    def test_verify_expired_timestamp(self) -> None:
        payload = json.dumps({"event": "test"})
        message_id = "msg-123"
        # Timestamp from 10 minutes ago
        timestamp_ms = int((time.time() - 600) * 1000)
        signature_payload = f"{message_id}.{timestamp_ms}.{payload}"
        signature = generate_signature(self.secret_key, signature_payload)

        headers = {
            "svix-id": message_id,
            "svix-timestamp": str(timestamp_ms),
            "svix-signature": signature,
        }

        with pytest.raises(TimestampExpiredError):
            self.validator.verify(payload, headers)

    def test_verify_future_timestamp_within_tolerance(self) -> None:
        payload = json.dumps({"event": "test"})
        message_id = "msg-123"
        # Timestamp 1 minute in the future
        timestamp_ms = int((time.time() + 60) * 1000)
        signature_payload = f"{message_id}.{timestamp_ms}.{payload}"
        signature = generate_signature(self.secret_key, signature_payload)

        headers = {
            "svix-id": message_id,
            "svix-timestamp": str(timestamp_ms),
            "svix-signature": signature,
        }

        result = self.validator.verify(payload, headers)
        assert result["event"] == "test"

    def test_verify_empty_payload(self) -> None:
        headers = {"svix-id": "123", "svix-timestamp": "123", "svix-signature": "sig"}

        with pytest.raises(ValueError):
            self.validator.verify("", headers)

    def test_verify_none_headers(self) -> None:
        with pytest.raises(ValueError):
            self.validator.verify('{"event": "test"}', None)  # type: ignore

    def test_constructor_empty_secret(self) -> None:
        with pytest.raises(ValueError):
            WebhookValidator("")

    def test_constructor_whitespace_secret(self) -> None:
        with pytest.raises(ValueError):
            WebhookValidator("   ")

    def test_custom_tolerance(self) -> None:
        # Create validator with 1 second tolerance
        validator = WebhookValidator(self.secret_key, tolerance_in_seconds=1)

        payload = json.dumps({"event": "test"})
        message_id = "msg-123"
        # Timestamp from 5 seconds ago
        timestamp_ms = int((time.time() - 5) * 1000)
        signature_payload = f"{message_id}.{timestamp_ms}.{payload}"
        signature = generate_signature(self.secret_key, signature_payload)

        headers = {
            "svix-id": message_id,
            "svix-timestamp": str(timestamp_ms),
            "svix-signature": signature,
        }

        with pytest.raises(TimestampExpiredError):
            validator.verify(payload, headers)

    def test_invalid_timestamp_format(self) -> None:
        payload = json.dumps({"event": "test"})
        headers = {
            "svix-id": "msg-123",
            "svix-timestamp": "not-a-number",
            "svix-signature": "signature",
        }

        with pytest.raises(ValueError) as exc_info:
            self.validator.verify(payload, headers)

        assert "timestamp" in str(exc_info.value).lower()


class TestGenerateSignature:

    def test_generate_signature_deterministic(self) -> None:
        secret = "test-secret"
        payload = "test-payload"

        sig1 = generate_signature(secret, payload)
        sig2 = generate_signature(secret, payload)

        assert sig1 == sig2

    def test_generate_signature_different_secrets(self) -> None:
        payload = "test-payload"

        sig1 = generate_signature("secret1", payload)
        sig2 = generate_signature("secret2", payload)

        assert sig1 != sig2

    def test_generate_signature_different_payloads(self) -> None:
        secret = "test-secret"

        sig1 = generate_signature(secret, "payload1")
        sig2 = generate_signature(secret, "payload2")

        assert sig1 != sig2
