using System.Security.Cryptography;
using System.Text;

namespace CM.Email.WebhookVerification.Tests;

internal static class HmacSignerTestHelper
{
    internal static string Generate(string secret, string signaturePayload)
    {
        var payloadBytes = Encoding.UTF8.GetBytes(signaturePayload);
        var keyBytes = Encoding.UTF8.GetBytes(secret);

        var hashBytes = HMACSHA512.HashData(keyBytes, payloadBytes);
        return Convert.ToBase64String(hashBytes);
    }
}
