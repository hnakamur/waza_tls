package main

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"testing"
)

func TestTls13Sign(t *testing.T) {
	cert, err := tls.LoadX509KeyPair(
		"../../tests/p256-self-signed.crt.pem",
		"../../tests/p256-self-signed.key.pem",
	)
	// D=c6ae5808bbcdb5ae7625078b6cef4db0f486b4790af774971fc0fffc5063c686,
	// X=0834335c0b0b4bb8c00d2793842385ca632b1158732c94c062165e12f6b9b523,
	// Y=0545f7c507832e7ee8038ed0089146aaccfe365534e18850d3b18d5c37a3f2e3

	if err != nil {
		t.Fatal(err)
	}

	var initial [12]uint32
	rnd := NewRandomForTest(initial)

	signed := []byte("\x0d\x7a\x45\xfc\x76\xfe\xd7\xde\x30\xa5\xbb\x93\x71\x61\x16\x9f\x96\x20\x26\x59\x7f\x70\x8a\x1c\xb9\x2b\x7d\xff\xac\x15\xad\x43")

	sigHash := crypto.SHA256
	signOpts := crypto.SignerOpts(sigHash)
	sig, err := cert.PrivateKey.(crypto.Signer).Sign(&rnd, signed, signOpts)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("\x30\x45\x02\x20\x4b\x33\xe6\x66\x13\xd2\x30\xd6\xe0\x7a\x2c\xc4\x03\x0e\xcc\xbc\xad\x41\xd4\x81\x57\x9b\x33\xb0\x99\x10\x04\x5f\x2d\xb8\x19\x91\x02\x21\x00\xe0\xe7\x1f\x24\x51\xcb\xc1\xc3\x08\xaf\xad\x3b\xb0\x4a\x7f\x3b\x6d\xdb\x58\x72\xae\x3a\xf2\x18\x93\xc5\x6e\xcc\x12\x83\x23\x3b")
	if got := sig; !bytes.Equal(got, want) {
		t.Errorf("sig mismatch, got=%x, want=%x", got, want)
	}
}
