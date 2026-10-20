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

## Replay Protection and Duplicate Events

The timestamp check limits how long a captured webhook stays valid (300 seconds by default). It does not stop an exact copy of a valid webhook from being accepted again inside that window. The signature still prevents anyone without your secret key from changing a webhook. We can also deliver the same event more than once, for example when we retry a delivery.

The `svix-timestamp` header is a Unix timestamp in **milliseconds**. The tolerance you configure is in seconds.

To make your handler safe, deduplicate on `data.id` from the verified payload:

```csharp
public record WebhookEvent([property: JsonPropertyName("data")] WebhookEventData Data);
public record WebhookEventData([property: JsonPropertyName("id")] string Id);

// Use a shared store in production, for example a database unique key or Redis SET NX
private static readonly ConcurrentDictionary<string, byte> ProcessedEventIds = new();

var webhookEvent = validator.Verify<WebhookEvent>(payload, headers);

if (!ProcessedEventIds.TryAdd(webhookEvent.Data.Id, 0))
{
    return Ok(); // already handled, still respond with 200
}

// Process the event
```

Do not use the `svix-id` header for this. It is the ID of the email message, so all events for one message (for example sent, delivered and bounced) share it, and skipping on it would drop real events. `data.id` is unique per event and stays the same when we retry that event. Events can also arrive out of order, so compare `createdAt` before an older event overwrites newer state.

See [Best practices](https://developers.cm.com/messaging/docs/webhook-verification#best-practices) in the webhook verification docs.

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

