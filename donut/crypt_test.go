package donut

import (
	"bytes"
	"testing"
)

func TestChaskeyState(t *testing.T) {
	// Test that chaskeyState can be created with 16-byte key
	key := make([]byte, DONUT_KEY_LEN)
	for i := range key {
		key[i] = byte(i)
	}

	c := newChaskeyState(key)
	if c == nil {
		t.Fatal("newChaskeyState returned nil")
	}
}

func TestChaskeyEncrypt(t *testing.T) {
	key := make([]byte, DONUT_KEY_LEN)
	for i := range key {
		key[i] = byte(i)
	}

	c := newChaskeyState(key)

	// Test encryption of a single block
	plaintext := make([]byte, DONUT_BLK_LEN)
	for i := range plaintext {
		plaintext[i] = byte(i + 0x10)
	}

	ciphertext := c.encrypt(plaintext)

	// Ciphertext should differ from plaintext
	if bytes.Equal(plaintext, ciphertext) {
		t.Error("Ciphertext equals plaintext")
	}

	// Encryption should be deterministic
	c2 := newChaskeyState(key)
	ciphertext2 := c2.encrypt(plaintext)

	if !bytes.Equal(ciphertext, ciphertext2) {
		t.Error("Chaskey encryption not deterministic")
	}
}

func TestEncryptCTR(t *testing.T) {
	// Create encryption context
	key := make([]byte, DONUT_KEY_LEN)
	ctr := make([]byte, DONUT_BLK_LEN)
	for i := range key {
		key[i] = byte(i)
	}
	for i := range ctr {
		ctr[i] = byte(0xFF - i)
	}

	// Test data
	plaintext := []byte("Hello, World! This is a test message for CTR mode encryption.")
	original := make([]byte, len(plaintext))
	copy(original, plaintext)

	// Encrypt
	encrypted := make([]byte, len(plaintext))
	copy(encrypted, plaintext)
	encrypted = EncryptCTR(key, ctr, encrypted)

	// Encrypted should differ from original
	if bytes.Equal(encrypted, original) {
		t.Error("Encrypted data equals original")
	}

	// CTR mode is symmetric - encrypting again should decrypt
	ctrCopy := make([]byte, DONUT_BLK_LEN)
	copy(ctrCopy, ctr)
	decrypted := EncryptCTR(key, ctrCopy, encrypted)

	if !bytes.Equal(decrypted, original) {
		t.Errorf("Decryption failed:\nGot: %s\nExpected: %s", decrypted, original)
	}
}

func TestEncryptCTREmptyData(t *testing.T) {
	key := make([]byte, DONUT_KEY_LEN)
	ctr := make([]byte, DONUT_BLK_LEN)
	data := []byte{}

	result := EncryptCTR(key, ctr, data)
	if len(result) != 0 {
		t.Errorf("EncryptCTR on empty data should return empty result")
	}
}

func TestEncryptCTRVariousLengths(t *testing.T) {
	key := make([]byte, DONUT_KEY_LEN)
	for i := range key {
		key[i] = byte(i)
	}

	// Test various data lengths including non-block-aligned
	lengths := []int{1, 15, 16, 17, 31, 32, 33, 100, 256}

	for _, length := range lengths {
		ctr := make([]byte, DONUT_BLK_LEN)
		for i := range ctr {
			ctr[i] = byte(i * 2)
		}

		data := make([]byte, length)
		for i := range data {
			data[i] = byte(i)
		}
		original := make([]byte, length)
		copy(original, data)

		encrypted := EncryptCTR(key, ctr, data)

		// Verify decryption works
		ctr2 := make([]byte, DONUT_BLK_LEN)
		for i := range ctr2 {
			ctr2[i] = byte(i * 2)
		}

		decrypted := EncryptCTR(key, ctr2, encrypted)

		if !bytes.Equal(decrypted, original) {
			t.Errorf("Round-trip failed for length %d", length)
		}
	}
}
