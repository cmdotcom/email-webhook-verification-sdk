# @cm-email-gateway/email-webhook-verification

Node.js/TypeScript SDK for verifying CM Email webhook signatures.

## Installation

```bash
npm install @cm-email-gateway/email-webhook-verification
```

Or with yarn:

```bash
yarn add @cm-email-gateway/email-webhook-verification
```

## Requirements

- Node.js 16.0.0 or later

## Usage

```typescript
import { WebhookValidator } from '@cm-email-gateway/email-webhook-verification';

// Initialize the validator with your secret key
const validator = new WebhookValidator({
  secretKey: 'your-secret-key',
});

// Or with custom tolerance (default is 300 seconds)
const validator = new WebhookValidator({
  secretKey: 'your-secret-key',
  toleranceInSeconds: 600,
});

// Extract headers from the incoming webhook request
const headers = {
  'svix-id': req.headers['svix-id'],
  'svix-timestamp': req.headers['svix-timestamp'],
  'svix-signature': req.headers['svix-signature'],
};

// Get the raw request body
const payload = req.body; // raw string body

// Verify and parse the webhook payload
try {
  const data = validator.verify<YourWebhookType>(payload, headers);
  // Process the verified webhook data
} catch (error) {
  if (error instanceof MissingHeadersError) {
    // Required headers are missing
  } else if (error instanceof InvalidTimestampError) {
    // Timestamp format is invalid
  } else if (error instanceof TimestampExpiredError) {
    // Webhook timestamp is outside the allowed tolerance window
  } else if (error instanceof InvalidSignatureError) {
    // Signature verification failed
  }
}
```

## Express.js Example

```typescript
import express from 'express';
import { WebhookValidator, WebhookVerificationError } from '@cm-email-gateway/email-webhook-verification';

const app = express();
app.use(express.raw({ type: 'application/json' }));

const validator = new WebhookValidator({
  secretKey: process.env.WEBHOOK_SECRET_KEY!,
});

app.post('/webhook', (req, res) => {
  try {
    const data = validator.verify(req.body.toString(), req.headers);
    // Process webhook
    res.status(200).send('OK');
  } catch (error) {
    if (error instanceof WebhookVerificationError) {
      res.status(401).send('Unauthorized');
    } else {
      res.status(500).send('Internal Server Error');
    }
  }
});
```

## API

### WebhookValidator

#### Constructor Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `secretKey` | `string` | required | Your webhook secret key |
| `toleranceInSeconds` | `number` | `300` | Maximum age of webhook in seconds |

#### Methods

- `verify<T>(payload: string, headers: WebhookHeaders): T` - Verifies the webhook signature and returns the parsed payload

### Errors

| Error | Description |
|-------|-------------|
| `MissingHeadersError` | One or more required headers (`svix-id`, `svix-timestamp`, `svix-signature`) are missing |
| `InvalidTimestampError` | The timestamp header is not a valid format |
| `TimestampExpiredError` | The webhook timestamp is outside the allowed tolerance window |
| `InvalidSignatureError` | The signature does not match the expected value |

All errors extend `WebhookVerificationError`.

## License

MIT License - see [LICENSE](../LICENSE) for details.


