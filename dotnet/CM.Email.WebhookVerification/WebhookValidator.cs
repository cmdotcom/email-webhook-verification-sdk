using System.Security.Cryptography;
using System.Text.Json;
using static CM.Email.WebhookVerification.Exceptions;
using System.Diagnostics.CodeAnalysis;

namespace CM.Email.WebhookVerification;

public class WebhookValidator
{
    private readonly string _secretKey;
    private readonly long _toleranceInMilliseconds;

    public WebhookValidator(string secretKey, int toleranceInSeconds = 300)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secretKey);

        _secretKey = secretKey;
        _toleranceInMilliseconds = toleranceInSeconds * 1000L;
    }

    [SuppressMessage("Maintainability", "AV1500:Member or local function contains too many statements", Justification = "")]
    public T? Verify<T>(string payload, IDictionary<string, string> headers)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentException.ThrowIfNullOrWhiteSpace(payload);

        headers.TryGetValue(WebhookHeaders.Id, out var messageId);
        headers.TryGetValue(WebhookHeaders.Timestamp, out var timestampStr);
        headers.TryGetValue(WebhookHeaders.Signature, out var signature);

        ValidateHeaders(messageId!, timestampStr!, signature!);

        if (!long.TryParse(timestampStr, out var timestampMs))
        {
            throw new InvalidTimestampException();
        }

        ValidateTimestamp(timestampMs);

        var signaturePayload = $"{messageId}.{timestampMs}.{payload}";
        var expectedSignature = HmacSigner.Generate(_secretKey, signaturePayload);

        if (!ConstantTimeEquals(signature!, expectedSignature))
        {
            throw new InvalidSignatureException();
        }

        return JsonSerializer.Deserialize<T>(payload);
    }

    [SuppressMessage("Maintainability", "AV1500:Member or local function contains too many statements", Justification = "")]
    [SuppressMessage("Maintainability", "AV1580:Method argument calls a nested method", Justification = "")]
    private static void ValidateHeaders(string messageId, string timestamp, string signature)
    {
        List<string> missingHeaders = [];

        if (string.IsNullOrEmpty(messageId))
        {
            missingHeaders.Add(WebhookHeaders.Id);
        }

        if (string.IsNullOrEmpty(timestamp))
        {
            missingHeaders.Add(WebhookHeaders.Timestamp);
        }

        if (string.IsNullOrEmpty(signature))
        {
            missingHeaders.Add(WebhookHeaders.Signature);
        }

        if (missingHeaders.Count > 0)
        {
            throw new MissingHeadersException(string.Join(", ", missingHeaders));
        }
    }

    private void ValidateTimestamp(long timestampMs)
    {
        var currentTimeMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var difference = Math.Abs(currentTimeMs - timestampMs);

        if (difference > _toleranceInMilliseconds)
        {
            throw new TimestampExpiredException();
        }
    }

    private static bool ConstantTimeEquals(string signature, string expectedSignature)
    {
        var aBytes = Convert.FromBase64String(signature);
        var bBytes = Convert.FromBase64String(expectedSignature);
        return CryptographicOperations.FixedTimeEquals(aBytes, bBytes);
    }
}
