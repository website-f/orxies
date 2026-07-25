package auth

import (
	"testing"
	"time"
)

func TestTOTPRoundTrip(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatalf("NewTOTPSecret: %v", err)
	}
	code, err := totpAt(secret, time.Now())
	if err != nil {
		t.Fatalf("totpAt: %v", err)
	}
	if !VerifyTOTP(secret, code) {
		t.Errorf("VerifyTOTP rejected a freshly generated code")
	}
	if VerifyTOTP(secret, "000000") && code != "000000" {
		t.Errorf("VerifyTOTP accepted an unrelated code")
	}
	if VerifyTOTP(secret, "12345") { // wrong length
		t.Errorf("VerifyTOTP accepted a malformed code")
	}
}
