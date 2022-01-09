package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

func TestAES128GCM(t *testing.T) {
	key := bytes.Repeat([]byte{'k'}, 16)
	c, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(c)
	if err != nil {
		t.Fatal(err)
	}

	additionalData := []byte("additionaldata")
	plaintext := []byte("exampleplaintext")
	nonce := bytes.Repeat([]byte{'n'}, 12)
	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
	want := []byte("\x5e\x84\x2b\xcb\x73\x09\x9c\xcf\xdd\x8e\x7e\x27\x1c\x07\x14\xef\x74\xe2\xdf\xb3\x6e\x31\x90\x6f\xd5\xd1\x17\xd4\xa1\x7a\x14\x2d")
	// log.Printf("ciphertext=%x, len=%d, plaintext.len=%d", ciphertext,
	// 	len(ciphertext), len(plaintext))
	if got := ciphertext; !bytes.Equal(got, want) {
		t.Errorf("ciphertext mismatch,\n got=%x,\nwant=%x", got, want)
	}

	decrypted, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		t.Fatal(err)
	}
	// log.Printf("decrypted=%s", decrypted)
	if got, want := decrypted, plaintext; !bytes.Equal(got, want) {
		t.Errorf("decrypted text mismatch,\n got=%s,\nwant=%s", got, want)
	}
}
