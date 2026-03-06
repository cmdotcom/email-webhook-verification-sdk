import base64
import hashlib
import hmac


def generate_signature(secret: str, payload: str) -> str:
    key_bytes = secret.encode("utf-8")
    payload_bytes = payload.encode("utf-8")

    signature = hmac.new(key_bytes, payload_bytes, hashlib.sha512)
    return base64.b64encode(signature.digest()).decode("utf-8")
