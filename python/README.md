# CM Email Webhook Verification SDK (Python)

SDK for verifying the authenticity of webhooks sent by CM Email services.

## Installation

```bash
pip install cm-email-webhook-verification
```

## Usage

```python
from cm_email_webhook_verification import WebhookValidator, WebhookVerificationError

# Initialize with your webhook secret key
validator = WebhookValidator("your-secret-key")

# Extract headers and payload from incoming request
headers = {
    "svix-id": request.headers["svix-id"],
    "svix-timestamp": request.headers["svix-timestamp"],
    "svix-signature": request.headers["svix-signature"],
}
payload = request.body.decode("utf-8")

try:
    data = validator.verify(payload, headers)
    # Process verified webhook data
    print(f"Received event: {data}")
except WebhookVerificationError as e:
    # Handle verification failure
    print(f"Webhook verification failed: {e}")
```

## Flask Example

```python
from flask import Flask, request, jsonify
from cm_email_webhook_verification import WebhookValidator, WebhookVerificationError

app = Flask(__name__)
validator = WebhookValidator("your-secret-key")

@app.route("/webhook", methods=["POST"])
def webhook():
    headers = {
        "svix-id": request.headers.get("svix-id"),
        "svix-timestamp": request.headers.get("svix-timestamp"),
        "svix-signature": request.headers.get("svix-signature"),
    }
    payload = request.get_data(as_text=True)

    try:
        data = validator.verify(payload, headers)
        return jsonify({"status": "ok"}), 200
    except WebhookVerificationError:
        return jsonify({"error": "Invalid webhook"}), 401
```

## FastAPI Example

```python
from fastapi import FastAPI, Request, HTTPException
from cm_email_webhook_verification import WebhookValidator, WebhookVerificationError

app = FastAPI()
validator = WebhookValidator("your-secret-key")

@app.post("/webhook")
async def webhook(request: Request):
    headers = {
        "svix-id": request.headers.get("svix-id"),
        "svix-timestamp": request.headers.get("svix-timestamp"),
        "svix-signature": request.headers.get("svix-signature"),
    }
    payload = (await request.body()).decode("utf-8")

    try:
        data = validator.verify(payload, headers)
        return {"status": "ok"}
    except WebhookVerificationError:
        raise HTTPException(status_code=401, detail="Invalid webhook")
```

## Custom Tolerance

By default, webhooks are valid for 5 minutes. You can customize this:

```python
# Accept webhooks up to 10 minutes old
validator = WebhookValidator("your-secret-key", tolerance_in_seconds=600)
```

The `svix-timestamp` header is a Unix timestamp in **milliseconds**. The tolerance you configure is in seconds.

## Replay Protection and Duplicate Events

The timestamp check limits how long a captured webhook stays valid (5 minutes by default). It does not stop an exact copy of a valid webhook from being accepted again inside that window. The signature still prevents anyone without your secret key from changing a webhook. We can also deliver the same event more than once, for example when we retry a delivery.

To make your handler safe, deduplicate on `data.id` from the verified payload:

```python
processed_event_ids = set()  # use a shared store in production, for example a database unique key or Redis SET NX

data = validator.verify(payload, headers)
event_id = data["data"]["id"]

if event_id in processed_event_ids:
    return  # already handled, still respond with 200
processed_event_ids.add(event_id)

# Process the event
```

Do not use the `svix-id` header for this. It is the ID of the email message, so all events for one message (for example sent, delivered and bounced) share it, and skipping on it would drop real events. `data.id` is unique per event and stays the same when we retry that event. Events can also arrive out of order, so compare `createdAt` before an older event overwrites newer state.

See [Best practices](https://developers.cm.com/messaging/docs/webhook-verification#best-practices) in the webhook verification docs.

## Exceptions

| Exception | Description |
|-----------|-------------|
| `WebhookVerificationError` | Base exception for all verification errors |
| `InvalidSignatureError` | Signature does not match |
| `TimestampExpiredError` | Timestamp outside tolerance window |
| `MissingHeaderError` | Required headers missing |

## Security

This SDK uses:
- **HMAC-SHA512** for signature generation
- **Constant-time comparison** to prevent timing attacks
- **Timestamp validation** to limit how long a captured webhook stays valid (see [Replay Protection and Duplicate Events](#replay-protection-and-duplicate-events))

