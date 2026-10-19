# Changelog

All notable changes to @cm-email-gateway/email-webhook-verification will be documented in this file.

## [1.0.3] - 2026-10-19

### Fixed

- Documentation: the timestamp check limits how long a captured webhook stays valid (default 5 minutes). It does not prevent an exact copy being accepted again inside that window. Corrected the wording in the README and in earlier changelog entries
- Documentation: added "Replay Protection and Duplicate Events" with a deduplication example that uses `data.id`. Do not deduplicate on `svix-id`, which is the email message ID and is shared by all events of a message
- Documentation: `svix-timestamp` is a Unix timestamp in milliseconds
- No code changes

## [1.0.2] - 2026-04-01
- vulnerabilities fix

## [1.0.1] - 2026-03-09

### Fixed

- Corrected package name in README documentation

## [1.0.0] - 2026-03-08

### Added

- Initial release of @cm-email-gateway/email-webhook-verification SDK
- `WebhookValidator` class for verifying webhook authenticity
- HMAC-SHA512 signature verification matching the CM Email webhook signing service
- Timestamp validation with configurable tolerance window (default: 5 minutes)
- Support for standard webhook headers (`svix-id`, `svix-timestamp`, `svix-signature`)

### Security

- Timestamp tolerance validation to limit how long a captured webhook stays valid
- Constant-time signature comparison to prevent timing attacks
