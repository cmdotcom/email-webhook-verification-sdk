# CM Email Webhook Verification - Go SDK

Go SDK for verifying CM Email webhook signatures.

## Installation

```bash
go get github.com/cmdotcom/email-webhook-verification-sdks/go
```

## Requirements

- Go 1.21 or later

## Usage

```go
package main

import (
    "fmt"
    "log"

    webhook "github.com/cmdotcom/email-webhook-verification-sdks/go"
)

func main() {
    // Initialize the validator with your secret key
    validator := webhook.NewWebhookValidator("your-secret-key")

    // Or with custom tolerance (default is 300 seconds)
    validator := webhook.NewWebhookValidatorWithTolerance("your-secret-key", 600)

    // Extract headers from the incoming webhook request
    headers := map[string]string{
        "svix-id":        r.Header.Get("svix-id"),
        "svix-timestamp": r.Header.Get("svix-timestamp"),
        "svix-signature": r.Header.Get("svix-signature"),
    }

    // Get the raw request body
    payload := string(body)

    // Verify and parse the webhook payload
    data, err := validator.Verify(payload, headers)
    if err != nil {
        switch err.(type) {
        case *webhook.MissingHeadersError:
            // Required headers are missing
        case *webhook.InvalidTimestampError:
            // Timestamp format is invalid
        case *webhook.TimestampExpiredError:
            // Webhook timestamp is outside the allowed tolerance window
        case *webhook.InvalidSignatureError:
            // Signature verification failed
        }
        return
    }

    // Process the verified webhook data
    fmt.Println(data)
}
```

## HTTP Handler Example

```go
package main

import (
    "io"
    "net/http"

    webhook "github.com/cmdotcom/email-webhook-verification-sdks/go"
)

var validator = webhook.NewWebhookValidator("your-secret-key")

func webhookHandler(w http.ResponseWriter, r *http.Request) {
    body, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "Failed to read body", http.StatusBadRequest)
        return
    }
    defer r.Body.Close()

    headers := map[string]string{
        "svix-id":        r.Header.Get("svix-id"),
        "svix-timestamp": r.Header.Get("svix-timestamp"),
        "svix-signature": r.Header.Get("svix-signature"),
    }

    data, err := validator.Verify(string(body), headers)
    if err != nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    // Process webhook data
    _ = data

    w.WriteHeader(http.StatusOK)
}

func main() {
    http.HandleFunc("/webhook", webhookHandler)
    http.ListenAndServe(":8080", nil)
}
```

## Unmarshaling to a Struct

```go
type WebhookPayload struct {
    EventType string `json:"event_type"`
    Data      struct {
        ID    string `json:"id"`
        Email string `json:"email"`
    } `json:"data"`
}

func handleWebhook(payload string, headers map[string]string) error {
    var data WebhookPayload
    err := validator.VerifyAndUnmarshal(payload, headers, &data)
    if err != nil {
        return err
    }

    // Use typed data
    fmt.Printf("Event: %s, ID: %s\n", data.EventType, data.Data.ID)
    return nil
}
```

## API

### Functions

- `NewWebhookValidator(secretKey string) *WebhookValidator` - Creates a validator with default tolerance (300 seconds)
- `NewWebhookValidatorWithTolerance(secretKey string, toleranceSeconds int64) *WebhookValidator` - Creates a validator with custom tolerance

### Methods

- `Verify(payload string, headers map[string]string) (map[string]interface{}, error)` - Verifies and returns parsed JSON as map
- `VerifyAndUnmarshal(payload string, headers map[string]string, target interface{}) error` - Verifies and unmarshals to a struct

### Errors

| Error | Description |
|-------|-------------|
| `MissingHeadersError` | One or more required headers (`svix-id`, `svix-timestamp`, `svix-signature`) are missing |
| `InvalidTimestampError` | The timestamp header is not a valid format |
| `TimestampExpiredError` | The webhook timestamp is outside the allowed tolerance window |
| `InvalidSignatureError` | The signature does not match the expected value |

## License

MIT License - see [LICENSE](../LICENSE) for details.
