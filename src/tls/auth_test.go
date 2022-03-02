package main

import (
	"bytes"
	"crypto"
	"hash"
	"io"
	"testing"
)

func TestSignedMessage(t *testing.T) {
	testCases := []struct {
		sigHash    crypto.Hash
		transcript hash.Hash
		want       []byte
	}{
		{
			sigHash:    directSigning,
			transcript: crypto.SHA256.New(),
			want:       []byte("\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x54\x4c\x53\x20\x31\x2e\x33\x2c\x20\x73\x65\x72\x76\x65\x72\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x56\x65\x72\x69\x66\x79\x00\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55"),
		},
		{
			sigHash:    directSigning,
			transcript: crypto.SHA384.New(),
			want:       []byte("\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x54\x4c\x53\x20\x31\x2e\x33\x2c\x20\x73\x65\x72\x76\x65\x72\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x56\x65\x72\x69\x66\x79\x00\x38\xb0\x60\xa7\x51\xac\x96\x38\x4c\xd9\x32\x7e\xb1\xb1\xe3\x6a\x21\xfd\xb7\x11\x14\xbe\x07\x43\x4c\x0c\xc7\xbf\x63\xf6\xe1\xda\x27\x4e\xde\xbf\xe7\x6f\x65\xfb\xd5\x1a\xd2\xf1\x48\x98\xb9\x5b"),
		},
		{
			sigHash:    directSigning,
			transcript: crypto.SHA512.New(),
			want:       []byte("\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x54\x4c\x53\x20\x31\x2e\x33\x2c\x20\x73\x65\x72\x76\x65\x72\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x56\x65\x72\x69\x66\x79\x00\xcf\x83\xe1\x35\x7e\xef\xb8\xbd\xf1\x54\x28\x50\xd6\x6d\x80\x07\xd6\x20\xe4\x05\x0b\x57\x15\xdc\x83\xf4\xa9\x21\xd3\x6c\xe9\xce\x47\xd0\xd1\x3c\x5d\x85\xf2\xb0\xff\x83\x18\xd2\x87\x7e\xec\x2f\x63\xb9\x31\xbd\x47\x41\x7a\x81\xa5\x38\x32\x7a\xf9\x27\xda\x3e"),
		},
		{
			sigHash:    crypto.SHA256,
			transcript: crypto.SHA256.New(),
			want:       []byte("\x92\x2d\xff\x4b\x3f\xd9\x4f\x97\xf1\x85\x33\x61\x08\x40\xed\xdc\x20\xff\x77\x87\x39\x72\xcc\xa7\xac\xe1\x4b\xb8\x50\x9c\x09\x78"),
		},
		{
			sigHash:    crypto.SHA384,
			transcript: crypto.SHA256.New(),
			want:       []byte("\xe1\x13\xea\x7b\x46\xb1\xfc\xe4\xfe\x66\xae\xb5\x85\x78\x4d\xd2\xcd\xbd\x58\x60\x04\x07\xc0\x6a\x76\x75\x0f\xd5\xb4\x1b\x0f\x4f\x17\x9a\x46\x66\x02\x5a\x58\xc6\x74\x3b\x8e\x9c\x59\x1a\x74\x4d"),
		},
		{
			sigHash:    crypto.SHA512,
			transcript: crypto.SHA256.New(),
			want:       []byte("\xbb\xa4\x8a\x4f\xcb\x0c\x51\xff\x20\x7f\x9d\x61\xe6\x82\x44\xdc\x6a\xa7\x43\xf7\xfb\xed\xf6\xfa\x13\x1a\x06\x12\x97\xb5\x9e\xac\x85\x83\x6e\xb5\x32\x0a\x6d\x5a\x9b\xe3\xcf\x34\x81\xc6\x75\x2e\x70\xc8\x4a\xae\x5e\xc7\x94\xee\xde\x2a\xe4\xdb\x82\x13\x62\xfd"),
		},
	}
	for i, c := range testCases {
		got := signedMessage(c.sigHash, serverSignatureContext, c.transcript)
		if !bytes.Equal(got, c.want) {
			t.Errorf("case %d result mismatch, got=%x, want=%x", i, got, c.want)
		}
	}
}

// directSigning is a standard Hash value that signals that no pre-hashing
// should be performed, and that the input should be signed directly. It is the
// hash function associated with the Ed25519 signature scheme.
var directSigning crypto.Hash = 0

const (
	serverSignatureContext = "TLS 1.3, server CertificateVerify\x00"
	clientSignatureContext = "TLS 1.3, client CertificateVerify\x00"
)

var signaturePadding = []byte{
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
}

// signedMessage returns the pre-hashed (if necessary) message to be signed by
// certificate keys in TLS 1.3. See RFC 8446, Section 4.4.3.
func signedMessage(sigHash crypto.Hash, context string, transcript hash.Hash) []byte {
	if sigHash == directSigning {
		b := &bytes.Buffer{}
		b.Write(signaturePadding)
		io.WriteString(b, context)
		b.Write(transcript.Sum(nil))
		return b.Bytes()
	}
	h := sigHash.New()
	h.Write(signaturePadding)
	io.WriteString(h, context)
	h.Write(transcript.Sum(nil))
	return h.Sum(nil)
}