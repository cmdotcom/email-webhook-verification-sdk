namespace CM.Email.WebhookVerification
{
    public class Exceptions
    {
        public class WebhookVerificationException(string message) : Exception(message)
        {
        }

        public class MissingHeadersException(string headers) : WebhookVerificationException($"Missing required header(s): {headers}")
        {
        }

        public class InvalidSignatureException() : WebhookVerificationException("Invalid signature")
        {
        }

        public class InvalidTimestampException() : WebhookVerificationException("Invalid timestamp format")
        {
        }

        public class TimestampExpiredException() : WebhookVerificationException("Webhook timestamp is outside the allowed tolerance window")
        {
        }
    }
}
