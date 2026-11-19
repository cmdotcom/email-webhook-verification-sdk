class WebhookVerificationError(Exception):
    pass


class InvalidSignatureError(WebhookVerificationError):
    pass


class TimestampExpiredError(WebhookVerificationError):
    pass


class MissingHeaderError(WebhookVerificationError, ValueError):
    pass


class InvalidPayloadError(WebhookVerificationError, ValueError):
    pass


class InvalidTimestampError(WebhookVerificationError, ValueError):
    pass
