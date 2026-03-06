package webhook

import (
	"encoding/base64"
	"testing"
)

func TestGenerateSignature_Deterministic(t *testing.T) {
	sig1 := GenerateSignature("secret", "payload")
	sig2 := GenerateSignature("secret", "payload")

	if sig1 != sig2 {
		t.Errorf("Expected signatures to be equal, got %s and %s", sig1, sig2)
	}
}

func TestGenerateSignature_DifferentSecrets(t *testing.T) {
	sig1 := GenerateSignature("secret1", "payload")
	sig2 := GenerateSignature("secret2", "payload")

	if sig1 == sig2 {
		t.Error("Expected different signatures for different secrets")
	}
}

func TestGenerateSignature_DifferentPayloads(t *testing.T) {
	sig1 := GenerateSignature("secret", "payload1")
	sig2 := GenerateSignature("secret", "payload2")

	if sig1 == sig2 {
		t.Error("Expected different signatures for different payloads")
	}
}

func TestGenerateSignature_ValidBase64(t *testing.T) {
	sig := GenerateSignature("secret", "payload")

	_, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Errorf("Expected valid base64, got error: %v", err)
	}
}

func TestGenerateSignature_SHA512Length(t *testing.T) {
	sig := GenerateSignature("secret", "payload")

	decoded, _ := base64.StdEncoding.DecodeString(sig)
	if len(decoded) != 64 {
		t.Errorf("Expected 64-byte SHA512 hash, got %d bytes", len(decoded))
	}
}
