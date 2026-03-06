import hmac
import json
import time
from typing import Any

from cm_email_webhook_verification.exceptions import (
    InvalidSignatureError,
    MissingHeaderError,
    TimestampExpiredError,
)
from cm_email_webhook_verification.signer import generate_signature


class WebhookValidator:
    HEADER_ID = "svix-id"
    HEADER_TIMESTAMP = "svix-timestamp"
    HEADER_SIGNATURE = "svix-signature"

    def __init__(self, secret_key: str, tolerance_in_seconds: int = 300) -> None:
        if not secret_key or not secret_key.strip():
            raise ValueError("secret_key cannot be empty")

        self._secret_key = secret_key
        self._tolerance_ms = tolerance_in_seconds * 1000

    def verify(self, payload: str, headers: dict[str, str]) -> Any:
        if not payload or not payload.strip():
            raise ValueError("payload cannot be empty")

        if headers is None:
            raise ValueError("headers cannot be None")

        message_id = headers.get(self.HEADER_ID)
        timestamp_str = headers.get(self.HEADER_TIMESTAMP)
        signature = headers.get(self.HEADER_SIGNATURE)

        if not message_id or not timestamp_str or not signature:
            missing = []
            if not message_id:
                missing.append(self.HEADER_ID)
            if not timestamp_str:
                missing.append(self.HEADER_TIMESTAMP)
            if not signature:
                missing.append(self.HEADER_SIGNATURE)
            raise MissingHeaderError(f"Missing required headers: {', '.join(missing)}")

        try:
            timestamp_ms = int(timestamp_str)
        except ValueError as e:
            raise ValueError("Invalid timestamp format") from e

        self._validate_timestamp(timestamp_ms)

        signature_payload = f"{message_id}.{timestamp_ms}.{payload}"
        expected_signature = generate_signature(self._secret_key, signature_payload)

        if not hmac.compare_digest(signature, expected_signature):
            raise InvalidSignatureError("Invalid signature")

        return json.loads(payload)

    def _validate_timestamp(self, timestamp_ms: int) -> None:
        current_time_ms = int(time.time() * 1000)
        difference = abs(current_time_ms - timestamp_ms)

        if difference > self._tolerance_ms:
            raise TimestampExpiredError(
                "Webhook timestamp is outside the allowed tolerance window"
            )
