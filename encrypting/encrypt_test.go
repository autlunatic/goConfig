package encrypting

import (
	"testing"
)

func TestIsEncrypted(t *testing.T) {
	if IsEncrypted("notEncrypted", "testKey") {
		t.Errorf("should not be encrypted")
	}
	enc, _ := EncryptString("HansDampf", "jojojo")
	if !IsEncrypted(enc, "jojojo") {
		t.Errorf("should be encrypted")
	}
	if IsEncrypted(enc, "wrongKey") {
		t.Errorf("should not be treated as encrypted")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	data := []struct {
		input string
		key   string
	}{
		{"Foo", "Boo"},
		{"Bar", "Car"},
		{"Bar", ""},
		{"", "Car"},
		{"Long input with more than 16 characters", "Car"},
	}
	for _, d := range data {
		enc, err := EncryptString(d.input, d.key)
		if err != nil {
			t.Errorf("Unable to encrypt '%v' with key '%v': %v", d.input, d.key, err)
			continue
		}
		dec, err := DecryptString(enc, d.key)
		if err != nil {
			t.Errorf("Unable to decrypt '%v' with key '%v': %v", enc, d.key, err)
			continue
		}
		if dec != d.input {
			t.Errorf("Decrypt Key %v\n  Input: %v\n  Expect: %v\n  Actual: %v", d.key, enc, d.input, enc)
		}
		decryptedFromOldValue, err := DecryptString("0sC5Fvibgp4C7TyQxy9IOQDCoQQ280GRKp0=", "Boo")
		if decryptedFromOldValue != "Foo" {
			t.Errorf("Old encrypted Foo isnt decrypted correctly")
		}
	}
}
