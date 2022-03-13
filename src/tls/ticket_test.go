package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"io"
	"testing"
	"time"
)

func TestEncryptTicket(t *testing.T) {
	ticketKeys := []ticketKey{
		{
			keyName: [ticketKeyNameLen]byte{0xd0, 0x0b, 0xd9, 0x39, 0x5f, 0x7e, 0x64, 0x7d, 0xc7, 0x42, 0xb3, 0x30, 0xba, 0xfc, 0xc2, 0x93},
			aesKey:  [16]byte{0xe6, 0x17, 0xba, 0x9f, 0x47, 0x2f, 0xe8, 0x8d, 0xf8, 0x56, 0xdb, 0xcf, 0xa0, 0x99, 0x43, 0x3c},
			hmacKey: [16]byte{0xee, 0xd9, 0x2a, 0x4b, 0xdb, 0xd5, 0x77, 0x05, 0x0e, 0x10, 0xc3, 0x9f, 0xf9, 0xd4, 0x2d, 0xb2},
		},
	}
	state := []byte("\x03\x04\x00\x13\x01\x00\x00\x00\x00\x62\x2d\xfc\x89\x20\x1a\xc5\xa7\x82\x7d\x4e\xfe\x06\xb1\x9c\x8f\x32\xf4\xdc\x1f\x90\x67\xc8\xf5\x2c\xb4\x7f\x52\x7e\x15\xd6\x65\xbb\x3d\x45\x9b\x4f\x00\x00\x00")
	var initial [12]uint32
	r := NewRandomForTest(initial)
	got, err := encryptTicket(ticketKeys, state, &r)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("\xd0\x0b\xd9\x39\x5f\x7e\x64\x7d\xc7\x42\xb3\x30\xba\xfc\xc2\x93\xc4\xd8\x67\x64\x3b\xf8\xdc\x07\xd4\xb0\x0b\x3b\x4c\x36\x21\x1b\x2b\x05\xe6\xbb\x5e\xa2\xaf\x7e\xaa\x8c\xec\xe0\xd7\xab\xbc\xeb\xfd\x00\x25\x57\xe6\x0e\xcc\x0a\x0a\xe4\x34\x20\xf8\x0f\x94\x0a\x36\xf5\x4b\x39\x00\x3a\x3f\xff\x76\x30\x67\xf3\xd3\xe0\x08\x8c\x49\x91\x1c\xb5\xaf\xf6\x28\x69\x67\x3d\x84\x82\x9c\xa0\xfb\x78\xe2\x82\x90\x27\x3d\x8d\xcb\xb2\x71\x9b\x80\x68\x63\xce\x2f\x7c\x50")
	if !bytes.Equal(got, want) {
		t.Errorf("result mismatch, got=%x, want=%x", got, want)
	}
}

const ticketKeyNameLen = 16

// ticketKey is the internal representation of a session ticket key.
type ticketKey struct {
	// keyName is an opaque byte string that serves to identify the session
	// ticket key. It's exposed as plaintext in every session ticket.
	keyName [ticketKeyNameLen]byte
	aesKey  [16]byte
	hmacKey [16]byte
	// created is the time at which this ticket key was created. See Config.ticketKeys.
	created time.Time
}

func encryptTicket(ticketKeys []ticketKey, state []byte, rand io.Reader) ([]byte, error) {
	if len(ticketKeys) == 0 {
		return nil, errors.New("tls: internal error: session ticket keys unavailable")
	}

	encrypted := make([]byte, ticketKeyNameLen+aes.BlockSize+len(state)+sha256.Size)
	keyName := encrypted[:ticketKeyNameLen]
	iv := encrypted[ticketKeyNameLen : ticketKeyNameLen+aes.BlockSize]
	macBytes := encrypted[len(encrypted)-sha256.Size:]

	if _, err := io.ReadFull(rand, iv); err != nil {
		return nil, err
	}
	key := ticketKeys[0]
	copy(keyName, key.keyName[:])
	block, err := aes.NewCipher(key.aesKey[:])
	if err != nil {
		return nil, errors.New("tls: failed to create cipher while encrypting ticket: " + err.Error())
	}
	cipher.NewCTR(block, iv).XORKeyStream(encrypted[ticketKeyNameLen+aes.BlockSize:], state)

	mac := hmac.New(sha256.New, key.hmacKey[:])
	mac.Write(encrypted[:len(encrypted)-sha256.Size])
	mac.Sum(macBytes[:0])

	return encrypted, nil
}
