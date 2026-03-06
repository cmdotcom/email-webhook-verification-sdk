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
- **Timestamp validation** to prevent replay attacks