# Changelog

All notable changes to cm-email-webhook-verification will be documented in this file.

## [1.0.2] - 2026-11-18

### Fixed

- `verify()` raised `TypeError` instead of `InvalidSignatureError` when the `svix-signature` header contained non-ASCII characters, because `hmac.compare_digest` rejects non-ASCII `str` operands. Signatures are now compared as bytes, so such a header is rejected like any other invalid signature
- `verify()` now raises `WebhookVerificationError` subclasses for every failure caused by untrusted input, so the documented `except WebhookVerificationError` handler returns 401 as intended instead of the framework answering 500:
  - empty payload: `InvalidPayloadError` (was a bare `ValueError`)
  - non-numeric `svix-timestamp`: `InvalidTimestampError` (was a bare `ValueError`)
  - `headers` is `None`: `MissingHeaderError` (was a bare `ValueError`)
  - correctly signed payload that is not valid JSON: `InvalidPayloadError` (was `json.JSONDecodeError`)
- `__version__` now matches the package version

### Added

- `InvalidPayloadError` and `InvalidTimestampError`

### Compatibility

- `MissingHeaderError`, `InvalidPayloadError` and `InvalidTimestampError` also subclass `ValueError`, so existing code that catches `ValueError` keeps working

## [1.0.1] - 2026-10-19

### Fixed

- Documentation: the timestamp check limits how long a captured webhook stays valid (default 5 minutes). It does not prevent an exact copy being accepted again inside that window. Corrected the wording in the README and in earlier changelog entries
- Documentation: added "Replay Protection and Duplicate Events" with a deduplication example that uses `data.id`. Do not deduplicate on `svix-id`, which is the email message ID and is shared by all events of a message
- Documentation: `svix-timestamp` is a Unix timestamp in milliseconds
- No code changes

## [1.0.0] - 2026-03-09

### Added

- Initial release of cm-email-webhook-verification SDK
- `WebhookValidator` class for verifying webhook authenticity
- HMAC-SHA512 signature verification matching the CM Email webhook signing service
- Timestamp validation with configurable tolerance window (default: 5 minutes)
- Support for standard webhook headers (`svix-id`, `svix-timestamp`, `svix-signature`)

### Security

- Timestamp tolerance validation to limit how long a captured webhook stays valid
- Constant-time signature comparison to prevent timing attacks
