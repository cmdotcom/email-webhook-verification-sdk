import json
import time

import pytest

from cm_email_webhook_verification import (
    InvalidPayloadError,
    InvalidSignatureError,
    InvalidTimestampError,
    MissingHeaderError,
    TimestampExpiredError,
    WebhookValidator,
    WebhookVerificationError,
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

        with pytest.raises(InvalidPayloadError):
            self.validator.verify("", headers)

    def test_verify_none_headers(self) -> None:
        with pytest.raises(MissingHeaderError):
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

        with pytest.raises(InvalidTimestampError) as exc_info:
            self.validator.verify(payload, headers)

        assert "timestamp" in str(exc_info.value).lower()


def _signed(secret_key: str, payload: str, message_id: str = "msg-123") -> dict[str, str]:
    timestamp_ms = int(time.time() * 1000)
    signature = generate_signature(secret_key, f"{message_id}.{timestamp_ms}.{payload}")
    return {
        "svix-id": message_id,
        "svix-timestamp": str(timestamp_ms),
        "svix-signature": signature,
    }


class TestUntrustedInputRaisesVerificationError:
    """Every failure caused by untrusted request data must be a WebhookVerificationError,
    so the documented ``except WebhookVerificationError`` handler can answer 401."""

    secret_key = "test-secret-key"

    def setup_method(self) -> None:
        self.validator = WebhookValidator(self.secret_key)
        self.payload = json.dumps({"event": "test"})

    @pytest.mark.parametrize(
        "mutate",
        [
            pytest.param(lambda sig: sig[:-1] + "\u00e4", id="last-char-non-ascii"),
            pytest.param(lambda sig: "\u00e4" * len(sig), id="all-non-ascii"),
            pytest.param(lambda sig: sig + "\U0001f600", id="emoji-appended"),
            pytest.param(lambda sig: "\u00e4" + sig[1:], id="first-char-non-ascii"),
            pytest.param(lambda sig: sig[:-1] + "\ud800", id="lone-surrogate"),
        ],
    )
    def test_non_ascii_signature_is_invalid_signature(self, mutate) -> None:  # type: ignore[no-untyped-def]
        headers = _signed(self.secret_key, self.payload)
        headers["svix-signature"] = mutate(headers["svix-signature"])

        with pytest.raises(InvalidSignatureError):
            self.validator.verify(self.payload, headers)

    def test_valid_signature_still_verifies(self) -> None:
        headers = _signed(self.secret_key, self.payload)

        assert self.validator.verify(self.payload, headers) == {"event": "test"}

    @pytest.mark.parametrize("bad_signature", ["", "AAAA", "not base64!!", "=" * 88])
    def test_ascii_bad_signatures_are_invalid_signature(self, bad_signature: str) -> None:
        headers = _signed(self.secret_key, self.payload)
        headers["svix-signature"] = bad_signature

        with pytest.raises(WebhookVerificationError):
            self.validator.verify(self.payload, headers)

    @pytest.mark.parametrize("payload", ["", "   ", "\n"])
    def test_empty_payload_is_invalid_payload(self, payload: str) -> None:
        with pytest.raises(InvalidPayloadError):
            self.validator.verify(payload, _signed(self.secret_key, payload))

    def test_none_headers_is_missing_header(self) -> None:
        with pytest.raises(MissingHeaderError):
            self.validator.verify(self.payload, None)  # type: ignore[arg-type]

    @pytest.mark.parametrize("timestamp", ["abc", "12.5", "0x10", "1e3", "12 34"])
    def test_non_numeric_timestamp_is_invalid_timestamp(self, timestamp: str) -> None:
        headers = _signed(self.secret_key, self.payload)
        headers["svix-timestamp"] = timestamp

        with pytest.raises(InvalidTimestampError):
            self.validator.verify(self.payload, headers)

    def test_correctly_signed_non_json_payload_is_invalid_payload(self) -> None:
        payload = "this is not json"

        with pytest.raises(InvalidPayloadError):
            self.validator.verify(payload, _signed(self.secret_key, payload))

    def test_documented_handler_returns_401_for_every_bad_input(self) -> None:
        """Mirrors the README Flask handler: only WebhookVerificationError is caught."""

        def handler(payload: str, headers: dict[str, str]) -> int:
            try:
                self.validator.verify(payload, headers)
                return 200
            except WebhookVerificationError:
                return 401

        good = _signed(self.secret_key, self.payload)
        non_ascii = {**good, "svix-signature": good["svix-signature"][:-1] + "\u00e4"}
        bad_timestamp = {**good, "svix-timestamp": "abc"}

        assert handler(self.payload, good) == 200
        assert handler(self.payload, non_ascii) == 401
        assert handler(self.payload, bad_timestamp) == 401
        assert handler("", good) == 401
        assert handler(self.payload, None) == 401  # type: ignore[arg-type]
        assert handler("not json", _signed(self.secret_key, "not json")) == 401

    def test_new_errors_are_still_value_errors_for_backward_compatibility(self) -> None:
        for exc in (InvalidPayloadError, InvalidTimestampError, MissingHeaderError):
            assert issubclass(exc, ValueError)
            assert issubclass(exc, WebhookVerificationError)


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
