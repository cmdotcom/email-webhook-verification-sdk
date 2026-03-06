package webhook

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type WebhookValidator struct {
	secretKey   string
	toleranceMs int64
}

func NewWebhookValidator(secretKey string) *WebhookValidator {
	return NewWebhookValidatorWithTolerance(secretKey, DefaultToleranceSeconds)
}

func NewWebhookValidatorWithTolerance(secretKey string, toleranceSeconds int64) *WebhookValidator {
	if strings.TrimSpace(secretKey) == "" {
		panic("secretKey cannot be empty")
	}

	return &WebhookValidator{
		secretKey:   secretKey,
		toleranceMs: toleranceSeconds * 1000,
	}
}

func (v *WebhookValidator) Verify(payload string, headers map[string]string) (map[string]interface{}, error) {
	var result map[string]interface{}
	err := v.VerifyAndUnmarshal(payload, headers, &result)
	return result, err
}

func (v *WebhookValidator) VerifyAndUnmarshal(payload string, headers map[string]string, target interface{}) error {
	var missingHeaders []string

	id, hasID := headers[HeaderID]
	timestampStr, hasTimestamp := headers[HeaderTimestamp]
	signature, hasSignature := headers[HeaderSignature]

	if !hasID || id == "" {
		missingHeaders = append(missingHeaders, HeaderID)
	}
	if !hasTimestamp || timestampStr == "" {
		missingHeaders = append(missingHeaders, HeaderTimestamp)
	}
	if !hasSignature || signature == "" {
		missingHeaders = append(missingHeaders, HeaderSignature)
	}

	if len(missingHeaders) > 0 {
		return &MissingHeadersError{Headers: missingHeaders}
	}

	timestampMs, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return &InvalidTimestampError{}
	}

	currentMs := time.Now().UnixMilli()
	diff := currentMs - timestampMs
	if diff < 0 {
		diff = -diff
	}

	if diff > v.toleranceMs {
		return &TimestampExpiredError{}
	}

	signaturePayload := fmt.Sprintf("%s.%d.%s", id, timestampMs, payload)

	expectedSignature := GenerateSignature(v.secretKey, signaturePayload)

	if !constantTimeCompare(expectedSignature, signature) {
		return &InvalidSignatureError{}
	}

	return json.Unmarshal([]byte(payload), target)
}

func constantTimeCompare(a, b string) bool {
	aBytes, errA := base64.StdEncoding.DecodeString(a)
	bBytes, errB := base64.StdEncoding.DecodeString(b)

	if errA != nil || errB != nil {
		return false
	}

	return hmac.Equal(aBytes, bBytes)
}
