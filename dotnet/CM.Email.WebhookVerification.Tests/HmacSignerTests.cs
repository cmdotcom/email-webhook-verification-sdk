namespace CM.Email.WebhookVerification.Tests;

public class HmacSignerTests
{
    [Fact]
    public void Generate_SameInputs_ReturnsSameSignature()
    {
        var secret = "test-secret-1";
        var payload = "test-payload-1";

        var sig1 = HmacSignerTestHelper.Generate(secret, payload);
        var sig2 = HmacSignerTestHelper.Generate(secret, payload);

        Assert.Equal(sig1, sig2);
    }

    [Fact]
    public void Generate_DifferentSecrets_ReturnsDifferentSignatures()
    {
        var payload = "test-payload";

        var sig1 = HmacSignerTestHelper.Generate("secret1", payload);
        var sig2 = HmacSignerTestHelper.Generate("secret2", payload);

        Assert.NotEqual(sig1, sig2);
    }

    [Fact]
    public void Generate_DifferentPayloads_ReturnsDifferentSignatures()
    {
        var secret = "test-secret";

        var sig1 = HmacSignerTestHelper.Generate(secret, "payload1");
        var sig2 = HmacSignerTestHelper.Generate(secret, "payload2");

        Assert.NotEqual(sig1, sig2);
    }

    [Fact]
    public void Generate_ReturnsBase64String()
    {
        var signature = HmacSignerTestHelper.Generate("secret", "payload");

        var bytes = Convert.FromBase64String(signature);
        Assert.Equal(64, bytes.Length); 
    }
}
