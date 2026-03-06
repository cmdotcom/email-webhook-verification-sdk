class WebhookVerificationError(Exception):
    pass


class InvalidSignatureError(WebhookVerificationError):
    pass


class TimestampExpiredError(WebhookVerificationError):
    pass


class MissingHeaderError(WebhookVerificationError):
    pass
