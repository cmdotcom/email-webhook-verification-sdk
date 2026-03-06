package webhook

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
)

func GenerateSignature(secret, payload string) string {
	h := hmac.New(sha512.New, []byte(secret))
	h.Write([]byte(payload))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
