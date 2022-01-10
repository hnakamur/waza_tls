package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestPrefixNonceAeadAES128GCM(t *testing.T) {
	key := bytes.Repeat([]byte{'k'}, 16)
	noncePrefix := bytes.Repeat([]byte{'p'}, 4)
	aead := aeadAESGCM(key, noncePrefix)
	additionalData := []byte("additionaldata")
	plaintext := []byte("exampleplaintext")
	explicitNonce := bytes.Repeat([]byte{'n'}, 8)
	ciphertext := aead.Seal(nil, explicitNonce, plaintext, additionalData)
	want := []byte("\x4b\x94\x1c\x11\x1c\xc9\xe9\xdb\x4d\xa6\xdb\xf7\x69\xda\x42\x81\x07\xb4\x8a\x4c\x64\xda\x24\x62\xfc\xbc\xab\xb7\xfd\x76\x5e\x62")
	// want is ciphertext + tag (whose length is 16 byte = aead.Overhead())
	// log.Printf("ciphertext=%x, len=%d, plaintext.len=%d", ciphertext,
	// 	len(ciphertext), len(plaintext))
	if got := ciphertext; !bytes.Equal(got, want) {
		t.Errorf("ciphertext mismatch,\n got=%x,\nwant=%x", got, want)
	}

	decrypted, err := aead.Open(nil, explicitNonce, ciphertext, additionalData)
	if err != nil {
		t.Fatal(err)
	}
	// log.Printf("decrypted=%s", decrypted)
	if got, want := decrypted, plaintext; !bytes.Equal(got, want) {
		t.Errorf("decrypted text mismatch,\n got=%s,\nwant=%s", got, want)
	}
}

func TestPrefixNonceAeadAES256GCM(t *testing.T) {
	key := bytes.Repeat([]byte{'k'}, 32)
	noncePrefix := bytes.Repeat([]byte{'p'}, 4)
	aead := aeadAESGCM(key, noncePrefix)
	additionalData := []byte("additionaldata")
	plaintext := []byte("exampleplaintext")
	explicitNonce := bytes.Repeat([]byte{'n'}, 8)
	ciphertext := aead.Seal(nil, explicitNonce, plaintext, additionalData)
	// log.Printf("ciphertext=%x, len=%d, plaintext.len=%d", ciphertext,
	// 	len(ciphertext), len(plaintext))
	want := []byte("\x1a\xd2\x36\x15\xdd\xe3\x47\xec\xa5\x7d\xf1\x73\xef\xe8\xfa\x10\x9d\x47\x5e\x0a\x47\x05\xcb\x51\xd3\xba\x47\x31\xe8\x79\xad\xb9")
	if got := ciphertext; !bytes.Equal(got, want) {
		t.Errorf("ciphertext mismatch,\n got=%x,\nwant=%x", got, want)
	}

	decrypted, err := aead.Open(nil, explicitNonce, ciphertext, additionalData)
	if err != nil {
		t.Fatal(err)
	}
	// log.Printf("decrypted=%s", decrypted)
	if got, want := decrypted, plaintext; !bytes.Equal(got, want) {
		t.Errorf("decrypted text mismatch,\n got=%s,\nwant=%s", got, want)
	}
}

func TestXorNonceAeadAES128GCM(t *testing.T) {
	key := bytes.Repeat([]byte{'k'}, 16)
	nonceMask := bytes.Repeat([]byte{'m'}, 12)
	aead := aeadAESGCMTLS13(key, nonceMask)
	additionalData := []byte("additionaldata")
	plaintext := []byte("exampleplaintext")
	nonce := bytes.Repeat([]byte{'n'}, 8)
	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
	// want is ciphertext + tag (whose length is 16 byte = aead.Overhead())
	want := []byte("\x58\x92\x14\xf9\x47\x1f\x36\xc4\x95\x25\xe3\x16\x45\xc5\xbe\x39\xbc\xfa\xd7\x22\x79\xe1\xff\x3f\xcb\x1a\x51\x0d\x92\x2b\xbd\x8f")
	if got := ciphertext; !bytes.Equal(got, want) {
		t.Errorf("ciphertext mismatch,\n got=%x,\nwant=%x", got, want)
	}
	// log.Printf("ciphertext=%x, len=%d, plaintext.len=%d", ciphertext,
	// 	len(ciphertext), len(plaintext))

	decrypted, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		t.Fatal(err)
	}
	// log.Printf("decrypted=%s", decrypted)
	if got, want := decrypted, plaintext; !bytes.Equal(got, want) {
		t.Errorf("decrypted text mismatch,\n got=%s,\nwant=%s", got, want)
	}
}

func TestXorNonceAeadAES256GCM(t *testing.T) {
	key := bytes.Repeat([]byte{'k'}, 32)
	nonceMask := bytes.Repeat([]byte{'m'}, 12)
	aead := aeadAESGCMTLS13(key, nonceMask)
	additionalData := []byte("additionaldata")
	plaintext := []byte("exampleplaintext")
	nonce := bytes.Repeat([]byte{'n'}, 8)
	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
	// want is ciphertext + tag (whose length is 16 byte = aead.Overhead())
	want := []byte("\x61\x91\xb6\x55\xb7\x04\x54\xbf\xf5\x94\x4e\x7d\xbd\x83\x6b\x84\x90\xcc\x27\x9a\xb8\x5d\x84\xf4\xcf\x67\x05\x27\x22\x27\xd4\x58")
	if got := ciphertext; !bytes.Equal(got, want) {
		t.Errorf("ciphertext mismatch,\n got=%x,\nwant=%x", got, want)
	}
	// log.Printf("ciphertext=%x, len=%d, plaintext.len=%d", ciphertext,
	// 	len(ciphertext), len(plaintext))

	decrypted, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		t.Fatal(err)
	}
	// log.Printf("decrypted=%s", decrypted)
	if got, want := decrypted, plaintext; !bytes.Equal(got, want) {
		t.Errorf("decrypted text mismatch,\n got=%s,\nwant=%s", got, want)
	}
}

func TestXorNonceAeadChaCha20Poly1305(t *testing.T) {
	key := bytes.Repeat([]byte{'k'}, 32)
	nonceMask := bytes.Repeat([]byte{'m'}, 12)
	aead := aeadChaCha20Poly1305(key, nonceMask)
	additionalData := []byte("additionaldata")
	plaintext := []byte("exampleplaintext")
	nonce := bytes.Repeat([]byte{'n'}, 8)
	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
	// want is ciphertext + tag (whose length is 16 byte = aead.Overhead())
	want := []byte("\xdf\x39\x03\x0c\xb1\x2f\xe4\xf9\x24\xeb\x76\x15\x80\x4c\x40\xed\xd8\x1f\x15\x82\xfc\x6c\x15\x62\x12\x9c\x8f\x77\x77\x11\x91\x60")
	if got := ciphertext; !bytes.Equal(got, want) {
		t.Errorf("ciphertext mismatch,\n got=%x,\nwant=%x", got, want)
	}
	// log.Printf("ciphertext=%x, len=%d, plaintext.len=%d", ciphertext,
	// 	len(ciphertext), len(plaintext))

	decrypted, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		t.Fatal(err)
	}
	// log.Printf("decrypted=%s", decrypted)
	if got, want := decrypted, plaintext; !bytes.Equal(got, want) {
		t.Errorf("decrypted text mismatch,\n got=%s,\nwant=%s", got, want)
	}
}

func aeadAESGCM(key, noncePrefix []byte) aead {
	if len(noncePrefix) != noncePrefixLength {
		panic("tls: internal error: wrong nonce length")
	}
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	ret := &prefixNonceAEAD{aead: aead}
	copy(ret.nonce[:], noncePrefix)
	return ret
}

func aeadAESGCMTLS13(key, nonceMask []byte) aead {
	if len(nonceMask) != aeadNonceLength {
		panic("tls: internal error: wrong nonce length")
	}
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	ret := &xorNonceAEAD{aead: aead}
	copy(ret.nonceMask[:], nonceMask)
	return ret
}

func aeadChaCha20Poly1305(key, nonceMask []byte) aead {
	if len(nonceMask) != aeadNonceLength {
		panic("tls: internal error: wrong nonce length")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}

	ret := &xorNonceAEAD{aead: aead}
	copy(ret.nonceMask[:], nonceMask)
	return ret
}

type aead interface {
	cipher.AEAD

	// explicitNonceLen returns the number of bytes of explicit nonce
	// included in each record. This is eight for older AEADs and
	// zero for modern ones.
	explicitNonceLen() int
}

const (
	aeadNonceLength   = 12
	noncePrefixLength = 4
)

// prefixNonceAEAD wraps an AEAD and prefixes a fixed portion of the nonce to
// each call.
type prefixNonceAEAD struct {
	// nonce contains the fixed part of the nonce in the first four bytes.
	nonce [aeadNonceLength]byte
	aead  cipher.AEAD
}

func (f *prefixNonceAEAD) NonceSize() int        { return aeadNonceLength - noncePrefixLength }
func (f *prefixNonceAEAD) Overhead() int         { return f.aead.Overhead() }
func (f *prefixNonceAEAD) explicitNonceLen() int { return f.NonceSize() }

func (f *prefixNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	copy(f.nonce[4:], nonce)
	return f.aead.Seal(out, f.nonce[:], plaintext, additionalData)
}

func (f *prefixNonceAEAD) Open(out, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	copy(f.nonce[4:], nonce)
	return f.aead.Open(out, f.nonce[:], ciphertext, additionalData)
}

// xoredNonceAEAD wraps an AEAD by XORing in a fixed pattern to the nonce
// before each call.
type xorNonceAEAD struct {
	nonceMask [aeadNonceLength]byte
	aead      cipher.AEAD
}

func (f *xorNonceAEAD) NonceSize() int        { return 8 } // 64-bit sequence number
func (f *xorNonceAEAD) Overhead() int         { return f.aead.Overhead() }
func (f *xorNonceAEAD) explicitNonceLen() int { return 0 }

func (f *xorNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	result := f.aead.Seal(out, f.nonceMask[:], plaintext, additionalData)
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}

	return result
}

func (f *xorNonceAEAD) Open(out, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	result, err := f.aead.Open(out, f.nonceMask[:], ciphertext, additionalData)
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}

	return result, err
}

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
