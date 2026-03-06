package webhook

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

const testSecret = "test-secret-key"

type TestPayload struct {
	Event string `json:"event"`
	Data  string `json:"data"`
}

func createValidHeaders(secret, payload string, timestampMs int64) map[string]string {
	messageID := "msg-123"
	signaturePayload := fmt.Sprintf("%s.%d.%s", messageID, timestampMs, payload)
	signature := GenerateSignature(secret, signaturePayload)

	return map[string]string{
		HeaderID:        messageID,
		HeaderTimestamp: fmt.Sprintf("%d", timestampMs),
		HeaderSignature: signature,
	}
}

func currentTimestampMs() int64 {
	return time.Now().UnixMilli()
}

func TestNewWebhookValidator(t *testing.T) {
	validator := NewWebhookValidator(testSecret)
	if validator == nil {
		t.Error("Expected validator to be created")
	}
}

func TestNewWebhookValidatorWithTolerance(t *testing.T) {
	validator := NewWebhookValidatorWithTolerance(testSecret, 60)
	if validator == nil {
		t.Error("Expected validator to be created")
	}
}

func TestNewWebhookValidator_EmptySecret_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic for empty secret")
		}
	}()
	NewWebhookValidator("")
}

func TestNewWebhookValidator_WhitespaceSecret_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic for whitespace secret")
		}
	}()
	NewWebhookValidator("   ")
}

func TestVerify_ValidWebhook(t *testing.T) {
	validator := NewWebhookValidator(testSecret)
	payload := `{"event":"test","data":"hello"}`
	timestampMs := currentTimestampMs()
	headers := createValidHeaders(testSecret, payload, timestampMs)

	var result TestPayload
	err := validator.VerifyAndUnmarshal(payload, headers, &result)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if result.Event != "test" {
		t.Errorf("Expected event 'test', got '%s'", result.Event)
	}
	if result.Data != "hello" {
		t.Errorf("Expected data 'hello', got '%s'", result.Data)
	}
}

func TestVerify_InvalidSignature(t *testing.T) {
	validator := NewWebhookValidator(testSecret)
	payload := `{"event":"test","data":"hello"}`
	timestampMs := currentTimestampMs()
	headers := createValidHeaders("wrong-secret", payload, timestampMs)

	var result TestPayload
	err := validator.VerifyAndUnmarshal(payload, headers, &result)

	if _, ok := err.(*InvalidSignatureError); !ok {
		t.Errorf("Expected InvalidSignatureError, got: %v", err)
	}
}

func TestVerify_MissingIDHeader(t *testing.T) {
	validator := NewWebhookValidator(testSecret)
	payload := `{"event":"test"}`
	headers := map[string]string{
		HeaderTimestamp: "123456",
		HeaderSignature: "sig",
	}

	var result map[string]interface{}
	err := validator.VerifyAndUnmarshal(payload, headers, &result)

	if missingErr, ok := err.(*MissingHeadersError); ok {
		found := false
		for _, h := range missingErr.Headers {
			if h == HeaderID {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected missing headers to contain svix-id")
		}
	} else {
		t.Errorf("Expected MissingHeadersError, got: %v", err)
	}
}

func TestVerify_MissingTimestampHeader(t *testing.T) {
	validator := NewWebhookValidator(testSecret)
	payload := `{"event":"test"}`
	headers := map[string]string{
		HeaderID:        "msg-123",
		HeaderSignature: "sig",
	}

	var result map[string]interface{}
	err := validator.VerifyAndUnmarshal(payload, headers, &result)

	if missingErr, ok := err.(*MissingHeadersError); ok {
		found := false
		for _, h := range missingErr.Headers {
			if h == HeaderTimestamp {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected missing headers to contain svix-timestamp")
		}
	} else {
		t.Errorf("Expected MissingHeadersError, got: %v", err)
	}
}

func TestVerify_MissingSignatureHeader(t *testing.T) {
	validator := NewWebhookValidator(testSecret)
	payload := `{"event":"test"}`
	headers := map[string]string{
		HeaderID:        "msg-123",
		HeaderTimestamp: "123456",
	}

	var result map[string]interface{}
	err := validator.VerifyAndUnmarshal(payload, headers, &result)

	if missingErr, ok := err.(*MissingHeadersError); ok {
		found := false
		for _, h := range missingErr.Headers {
			if h == HeaderSignature {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected missing headers to contain svix-signature")
		}
	} else {
		t.Errorf("Expected MissingHeadersError, got: %v", err)
	}
}

func TestVerify_MissingMultipleHeaders(t *testing.T) {
	validator := NewWebhookValidator(testSecret)
	payload := `{"event":"test"}`
	headers := map[string]string{}

	var result map[string]interface{}
	err := validator.VerifyAndUnmarshal(payload, headers, &result)

	if missingErr, ok := err.(*MissingHeadersError); ok {
		if len(missingErr.Headers) != 3 {
			t.Errorf("Expected 3 missing headers, got %d", len(missingErr.Headers))
		}
	} else {
		t.Errorf("Expected MissingHeadersError, got: %v", err)
	}
}

func TestVerify_InvalidTimestampFormat(t *testing.T) {
	validator := NewWebhookValidator(testSecret)
	payload := `{"event":"test"}`
	headers := map[string]string{
		HeaderID:        "msg-123",
		HeaderTimestamp: "not-a-number",
		HeaderSignature: "sig",
	}

	var result map[string]interface{}
	err := validator.VerifyAndUnmarshal(payload, headers, &result)

	if _, ok := err.(*InvalidTimestampError); !ok {
		t.Errorf("Expected InvalidTimestampError, got: %v", err)
	}
}

func TestVerify_ExpiredTimestamp(t *testing.T) {
	validator := NewWebhookValidator(testSecret)
	payload := `{"event":"test","data":"hello"}`

	oldTimestamp := currentTimestampMs() - (10 * 60 * 1000)
	headers := createValidHeaders(testSecret, payload, oldTimestamp)

	var result TestPayload
	err := validator.VerifyAndUnmarshal(payload, headers, &result)

	if _, ok := err.(*TimestampExpiredError); !ok {
		t.Errorf("Expected TimestampExpiredError, got: %v", err)
	}
}

func TestVerify_FutureTimestampWithinTolerance(t *testing.T) {
	validator := NewWebhookValidator(testSecret)
	payload := `{"event":"test","data":"hello"}`

	futureTimestamp := currentTimestampMs() + (2 * 60 * 1000)
	headers := createValidHeaders(testSecret, payload, futureTimestamp)

	var result TestPayload
	err := validator.VerifyAndUnmarshal(payload, headers, &result)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if result.Event != "test" {
		t.Errorf("Expected event 'test', got '%s'", result.Event)
	}
}

func TestVerify_FutureTimestampOutsideTolerance(t *testing.T) {
	validator := NewWebhookValidator(testSecret)
	payload := `{"event":"test","data":"hello"}`

	futureTimestamp := currentTimestampMs() + (10 * 60 * 1000)
	headers := createValidHeaders(testSecret, payload, futureTimestamp)

	var result TestPayload
	err := validator.VerifyAndUnmarshal(payload, headers, &result)

	if _, ok := err.(*TimestampExpiredError); !ok {
		t.Errorf("Expected TimestampExpiredError, got: %v", err)
	}
}

func TestVerify_CustomTolerance(t *testing.T) {
	validator := NewWebhookValidatorWithTolerance(testSecret, 1)
	payload := `{"event":"test","data":"hello"}`

	oldTimestamp := currentTimestampMs() - 5000
	headers := createValidHeaders(testSecret, payload, oldTimestamp)

	var result TestPayload
	err := validator.VerifyAndUnmarshal(payload, headers, &result)

	if _, ok := err.(*TimestampExpiredError); !ok {
		t.Errorf("Expected TimestampExpiredError, got: %v", err)
	}
}

func TestVerify_ReturnsMap(t *testing.T) {
	validator := NewWebhookValidator(testSecret)
	payload := `{"event":"test","data":"hello"}`
	timestampMs := currentTimestampMs()
	headers := createValidHeaders(testSecret, payload, timestampMs)

	result, err := validator.Verify(payload, headers)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if result["event"] != "test" {
		t.Errorf("Expected event 'test', got '%v'", result["event"])
	}
}

func TestConstantTimeCompare_Equal(t *testing.T) {
	sig := GenerateSignature("secret", "payload")
	if !constantTimeCompare(sig, sig) {
		t.Error("Expected equal signatures to match")
	}
}

func TestConstantTimeCompare_Different(t *testing.T) {
	sig1 := GenerateSignature("secret1", "payload")
	sig2 := GenerateSignature("secret2", "payload")
	if constantTimeCompare(sig1, sig2) {
		t.Error("Expected different signatures to not match")
	}
}

func TestConstantTimeCompare_InvalidBase64(t *testing.T) {
	if constantTimeCompare("not-valid-base64!!!", "also-not-valid!!!") {
		t.Error("Expected invalid base64 to return false")
	}
}

func BenchmarkVerify(b *testing.B) {
	validator := NewWebhookValidator(testSecret)
	payload := `{"event":"test","data":"hello"}`
	timestampMs := currentTimestampMs()
	headers := createValidHeaders(testSecret, payload, timestampMs)

	var result TestPayload

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validator.VerifyAndUnmarshal(payload, headers, &result)
	}
}

func TestVerify_ComplexPayload(t *testing.T) {
	validator := NewWebhookValidator(testSecret)

	complexPayload := map[string]interface{}{
		"event": "email.delivered",
		"data": map[string]interface{}{
			"messageId": "abc-123",
			"recipient": "test@example.com",
			"timestamp": 1234567890,
		},
	}

	payloadBytes, _ := json.Marshal(complexPayload)
	payload := string(payloadBytes)
	timestampMs := currentTimestampMs()
	headers := createValidHeaders(testSecret, payload, timestampMs)

	result, err := validator.Verify(payload, headers)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if result["event"] != "email.delivered" {
		t.Errorf("Expected event 'email.delivered', got '%v'", result["event"])
	}

	data, ok := result["data"].(map[string]interface{})
	if !ok {
		t.Error("Expected data to be a map")
	}
	if data["messageId"] != "abc-123" {
		t.Errorf("Expected messageId 'abc-123', got '%v'", data["messageId"])
	}
}
