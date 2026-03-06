using System.Text.Json;
using static CM.Email.WebhookVerification.Exceptions;

namespace CM.Email.WebhookVerification.Tests;

public class WebhookValidatorTests
{
    private const string SecretKey = "test-secret-key";
    private readonly WebhookValidator _validator = new(SecretKey);

    private static Dictionary<string, string> CreateValidHeaders(string payload, string secretKey)
    {
        var messageId = "msg-123";
        var timestampMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var signaturePayload = $"{messageId}.{timestampMs}.{payload}";
        var signature = HmacSignerTestHelper.Generate(secretKey, signaturePayload);

        return new Dictionary<string, string>
        {
            ["svix-id"] = messageId,
            ["svix-timestamp"] = timestampMs.ToString(),
            ["svix-signature"] = signature
        };
    }

    [Fact]
    public void Verify_ValidWebhook_ReturnsDeserializedPayload()
    {
        var payload = JsonSerializer.Serialize(new { Event = "test", Data = new { Id = 123 } });
        var headers = CreateValidHeaders(payload, SecretKey);

        var result = _validator.Verify<TestPayload>(payload, headers);

        Assert.NotNull(result);
        Assert.Equal("test", result.Event);
        Assert.Equal(123, result.Data?.Id);
    }

    [Fact]
    public void Verify_InvalidSignature_ThrowsInvalidSignatureException()
    {
        var payload = JsonSerializer.Serialize(new { Event = "test" });
        var headers = CreateValidHeaders(payload, SecretKey);
        headers["svix-signature"] = "aW52YWxpZC1zaWduYXR1cmU="; 

        Assert.Throws<InvalidSignatureException>(() => _validator.Verify<TestPayload>(payload, headers));
    }

    [Fact]
    public void Verify_MissingAllHeaders_ThrowsMissingHeadersException()
    {
        var payload = JsonSerializer.Serialize(new { Event = "test" });
        var headers = new Dictionary<string, string>();

        var exception = Assert.Throws<MissingHeadersException>(() => _validator.Verify<TestPayload>(payload, headers));
        Assert.Contains("svix-id", exception.Message);
        Assert.Contains("svix-timestamp", exception.Message);
        Assert.Contains("svix-signature", exception.Message);
    }

    [Fact]
    public void Verify_MissingSingleHeader_ThrowsMissingHeadersException()
    {
        var payload = JsonSerializer.Serialize(new { Event = "test" });
        var headers = CreateValidHeaders(payload, SecretKey);
        headers.Remove("svix-id");

        var exception = Assert.Throws<MissingHeadersException>(() => _validator.Verify<TestPayload>(payload, headers));
        Assert.Contains("svix-id", exception.Message);
    }

    [Fact]
    public void Verify_ExpiredTimestamp_ThrowsTimestampExpiredException()
    {
        var payload = JsonSerializer.Serialize(new { Event = "test" });
        var messageId = "msg-123";
        var timestampMs = DateTimeOffset.UtcNow.AddMinutes(-10).ToUnixTimeMilliseconds();
        var signaturePayload = $"{messageId}.{timestampMs}.{payload}";
        var signature = HmacSignerTestHelper.Generate(SecretKey, signaturePayload);

        var headers = new Dictionary<string, string>
        {
            ["svix-id"] = messageId,
            ["svix-timestamp"] = timestampMs.ToString(),
            ["svix-signature"] = signature
        };

        Assert.Throws<TimestampExpiredException>(() => _validator.Verify<TestPayload>(payload, headers));
    }

    [Fact]
    public void Verify_FutureTimestampWithinTolerance_Succeeds()
    {
        var payload = JsonSerializer.Serialize(new { Event = "test" });
        var messageId = "msg-123";
        var timestampMs = DateTimeOffset.UtcNow.AddMinutes(1).ToUnixTimeMilliseconds();
        var signaturePayload = $"{messageId}.{timestampMs}.{payload}";
        var signature = HmacSignerTestHelper.Generate(SecretKey, signaturePayload);

        var headers = new Dictionary<string, string>
        {
            ["svix-id"] = messageId,
            ["svix-timestamp"] = timestampMs.ToString(),
            ["svix-signature"] = signature
        };

        var result = _validator.Verify<TestPayload>(payload, headers);

        Assert.NotNull(result);
        Assert.Equal("test", result.Event);
    }

    [Fact]
    public void Verify_EmptyPayload_ThrowsArgumentException()
    {
        var headers = new Dictionary<string, string>
        {
            ["svix-id"] = "123",
            ["svix-timestamp"] = "123",
            ["svix-signature"] = "sig"
        };

        Assert.Throws<ArgumentException>(() => _validator.Verify<TestPayload>("", headers));
    }

    [Fact]
    public void Verify_NullHeaders_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => _validator.Verify<TestPayload>("{}", null!));
    }

    [Fact]
    public void Constructor_EmptySecret_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => new WebhookValidator(""));
    }

    [Fact]
    public void Constructor_WhitespaceSecret_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => new WebhookValidator("   "));
    }

    [Fact]
    public void Verify_CustomTolerance_RespectsToleranceValue()
    {
        var validator = new WebhookValidator(SecretKey, toleranceInSeconds: 1);

        var payload = JsonSerializer.Serialize(new { Event = "test" });
        var messageId = "msg-123";
        var timestampMs = DateTimeOffset.UtcNow.AddSeconds(-5).ToUnixTimeMilliseconds();
        var signaturePayload = $"{messageId}.{timestampMs}.{payload}";
        var signature = HmacSignerTestHelper.Generate(SecretKey, signaturePayload);

        var headers = new Dictionary<string, string>
        {
            ["svix-id"] = messageId,
            ["svix-timestamp"] = timestampMs.ToString(),
            ["svix-signature"] = signature
        };

        Assert.Throws<TimestampExpiredException>(() => validator.Verify<TestPayload>(payload, headers));
    }

    [Fact]
    public void Verify_InvalidTimestampFormat_ThrowsInvalidTimestampException()
    {
        var payload = JsonSerializer.Serialize(new { Event = "test" });
        var headers = new Dictionary<string, string>
        {
            ["svix-id"] = "msg-123",
            ["svix-timestamp"] = "not-a-number",
            ["svix-signature"] = "c2lnbmF0dXJl"
        };

        Assert.Throws<InvalidTimestampException>(() => _validator.Verify<TestPayload>(payload, headers));
    }

    private record TestPayload(string? Event, TestData? Data);
    private record TestData(int Id);
}
