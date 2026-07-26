package secretbox

import (
	"path/filepath"
	"testing"
)

func TestSecretboxRoundTrip(t *testing.T) {
	b, err := Open(filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := b.Encrypt("ghp_supersecrettoken")
	if err != nil {
		t.Fatal(err)
	}
	if enc == "ghp_supersecrettoken" || enc == "" {
		t.Fatalf("ciphertext looks wrong: %q", enc)
	}
	pt, err := b.Decrypt(enc)
	if err != nil || pt != "ghp_supersecrettoken" {
		t.Fatalf("Decrypt = %q, %v", pt, err)
	}
	// Empty passthrough.
	if e, _ := b.Encrypt(""); e != "" {
		t.Errorf("Encrypt(\"\") = %q, want empty", e)
	}
	if d, _ := b.Decrypt(""); d != "" {
		t.Errorf("Decrypt(\"\") = %q, want empty", d)
	}
	// Tampering is rejected.
	if _, err := b.Decrypt(enc[:len(enc)-2] + "xx"); err == nil {
		t.Error("expected error decrypting tampered ciphertext")
	}
}

func TestKeyPersists(t *testing.T) {
	kp := filepath.Join(t.TempDir(), "k")
	b1, _ := Open(kp)
	enc, _ := b1.Encrypt("hello")
	b2, err := Open(kp) // reopen with same key file
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := b2.Decrypt(enc); err != nil || pt != "hello" {
		t.Fatalf("reopened box could not decrypt: %q %v", pt, err)
	}
}
