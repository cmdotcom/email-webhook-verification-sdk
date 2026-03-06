package webhook

import (
	"fmt"
	"strings"
)

type WebhookVerificationError struct {
	Message string
}

func (e *WebhookVerificationError) Error() string {
	return e.Message
}

type MissingHeadersError struct {
	Headers []string
}

func (e *MissingHeadersError) Error() string {
	return fmt.Sprintf("missing required header(s): %s", strings.Join(e.Headers, ", "))
}

type InvalidSignatureError struct{}

func (e *InvalidSignatureError) Error() string {
	return "invalid signature"
}

type InvalidTimestampError struct{}

func (e *InvalidTimestampError) Error() string {
	return "invalid timestamp format"
}

type TimestampExpiredError struct{}

func (e *TimestampExpiredError) Error() string {
	return "webhook timestamp is outside the allowed tolerance window"
}
