# Changelog

All notable changes to cm-email-webhook-verification will be documented in this file.

## [1.0.0] - 2026-03-09

### Added

- Initial release of cm-email-webhook-verification SDK
- `WebhookValidator` class for verifying webhook authenticity
- HMAC-SHA512 signature verification matching the CM Email webhook signing service
- Timestamp validation with configurable tolerance window (default: 5 minutes)
- Support for standard webhook headers (`svix-id`, `svix-timestamp`, `svix-signature`)

### Security

- Timestamp tolerance validation to prevent replay attacks
- Constant-time signature comparison to prevent timing attacks
