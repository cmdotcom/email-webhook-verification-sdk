# CM.Email.WebhookVerification

.NET SDK for verifying CM Email webhook signatures.

## Installation

```bash
dotnet add package CM.Email.WebhookVerification
```

Or via Package Manager Console:

```powershell
Install-Package CM.Email.WebhookVerification
```

## Requirements

- .NET 9.0 or later

## Usage

```csharp
using CM.Email.WebhookVerification;

// Initialize the validator with your secret key
var validator = new WebhookValidator("your-secret-key");

// Or with custom tolerance (default is 300 seconds)
var validator = new WebhookValidator("your-secret-key", toleranceInSeconds: 600);

// Extract headers from the incoming webhook request
var headers = new Dictionary<string, string>
{
    { "svix-id", request.Headers["svix-id"] },
    { "svix-timestamp", request.Headers["svix-timestamp"] },
    { "svix-signature", request.Headers["svix-signature"] }
};

// Get the raw request body
var payload = await new StreamReader(request.Body).ReadToEndAsync();

// Verify and deserialize the webhook payload
try
{
    var webhookData = validator.Verify<YourWebhookModel>(payload, headers);
    // Process the verified webhook data
}
catch (Exceptions.MissingHeadersException ex)
{
    // Required headers are missing
}
catch (Exceptions.InvalidTimestampException)
{
    // Timestamp format is invalid
}
catch (Exceptions.TimestampExpiredException)
{
    // Webhook timestamp is outside the allowed tolerance window
}
catch (Exceptions.InvalidSignatureException)
{
    // Signature verification failed
}
```

## ASP.NET Core Example

```csharp
[HttpPost("webhook")]
public async Task<IActionResult> HandleWebhook()
{
    var validator = new WebhookValidator(Configuration["WebhookSecretKey"]);

    var headers = new Dictionary<string, string>
    {
        { "svix-id", Request.Headers["svix-id"].ToString() },
        { "svix-timestamp", Request.Headers["svix-timestamp"].ToString() },
        { "svix-signature", Request.Headers["svix-signature"].ToString() }
    };

    using var reader = new StreamReader(Request.Body);
    var payload = await reader.ReadToEndAsync();

    try
    {
        var data = validator.Verify<WebhookPayload>(payload, headers);
        // Process webhook
        return Ok();
    }
    catch (Exceptions.WebhookVerificationException)
    {
        return Unauthorized();
    }
}
```

## Exceptions

| Exception | Description |
|-----------|-------------|
| `MissingHeadersException` | One or more required headers (`svix-id`, `svix-timestamp`, `svix-signature`) are missing |
| `InvalidTimestampException` | The timestamp header is not a valid format |
| `TimestampExpiredException` | The webhook timestamp is outside the allowed tolerance window |
| `InvalidSignatureException` | The signature does not match the expected value |

All exceptions inherit from `WebhookVerificationException`.

## License

MIT License - see [LICENSE](../LICENSE) for details.

