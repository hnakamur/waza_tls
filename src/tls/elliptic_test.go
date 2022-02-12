package main

import (
	"bytes"
	"crypto/elliptic"
	"testing"
)

func TestEllipticGenerateKey(t *testing.T) {
	var initial [12]uint32
	rnd := NewRandomForTest(initial)

	c := elliptic.P256()
	priv, x, y, err := elliptic.GenerateKey(c, &rnd)
	if err != nil {
		t.Fatal(err)
	}
	// log.Printf("priv=%x, x=%x, y=%x", priv, x.Bytes(), y.Bytes())
	wantPriv := []byte("\xc4\x9a\x67\x64\x3b\xf8\xdc\x07\xd4\xb0\x0b\x3b\x4c\x36\x21\x1b\x57\xa6\x9d\xf9\x78\x78\x6a\xfd\xe9\xea\x94\x88\x85\xfd\x59\xfd")
	wantX := []byte("\xb8\xe1\xb9\x07\xbd\x87\xf9\xdb\x37\x26\x63\x37\x40\x4a\x46\x1e\x18\x80\x16\xb8\x4c\x8c\x86\x39\xff\x38\xba\xe6\xee\xcd\x35\x43")
	wantY := []byte("\x5a\x7f\x1e\x42\xce\x56\x76\x01\xf7\x7d\x1f\xc1\x8a\xa4\x0d\x64\x5f\x03\x89\x5c\x15\x20\x43\xb1\x5d\x42\x3a\xb1\xa5\xf9\xb5\x19")

	if got := priv; !bytes.Equal(got, wantPriv) {
		t.Errorf("priv mismatch, got=%x, want=%x", got, wantPriv)
	}
	if got := x.Bytes(); !bytes.Equal(got, wantX) {
		t.Errorf("x mismatch, got=%x, want=%x", got, wantX)
	}
	if got := y.Bytes(); !bytes.Equal(got, wantY) {
		t.Errorf("y mismatch, got=%x, want=%x", got, wantY)
	}
}
