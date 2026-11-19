from typing import Any

from cm_email_webhook_verification.exceptions import (
    InvalidPayloadError,
    InvalidSignatureError,
    InvalidTimestampError,
    MissingHeaderError,
    TimestampExpiredError,
    WebhookVerificationError,
)
from cm_email_webhook_verification.validator import WebhookValidator

__version__ = "1.0.2"
__all__ = [
    "verify",
    "WebhookValidator",
    "WebhookVerificationError",
    "InvalidSignatureError",
    "InvalidPayloadError",
    "InvalidTimestampError",
    "TimestampExpiredError",
    "MissingHeaderError",
]


def verify(secret_key: str, payload: str, headers: dict[str, str]) -> Any:
    return WebhookValidator(secret_key).verify(payload, headers)
