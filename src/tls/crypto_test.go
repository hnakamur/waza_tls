package main

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestSha256(t *testing.T) {
	got := sha256.Sum256([]byte("hello"))
	want := []byte("\x2c\xf2\x4d\xba\x5f\xb0\xa3\x0e\x26\xe8\x3b\x2a\xc5\xb9\xe2\x9e\x1b\x16\x1e\x5c\x1f\xa7\x42\x5e\x73\x04\x33\x62\x93\x8b\x98\x24")
	if !bytes.Equal(got[:], want) {
		t.Errorf("result mismatch, got=%x, want=%x", got[:], want)
	}
}
