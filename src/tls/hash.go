package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"log"
	"strings"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	log.Printf("Sha256Hash hash=%x\n", sha256.Sum256([]byte("hello")))
	log.Printf("Sha384Hash hash=%x\n", sha512.Sum384([]byte("hello")))
	var result [12]byte
	var seed [32]byte
	secret := strings.Repeat("my secret", 100)
	pHash(result[:], []byte(secret),
		[]byte("master secret"+strings.Repeat("\x00", 32)),
		sha256.New)
	log.Printf("pHash result=%x\n", result)

	prf12Sha256 := prf12(sha256.New)
	prf12Sha256(result[:], []byte(secret), []byte("master secret"), seed[:])
	log.Printf("prf12 result=%x\n", result)
	return nil
}

// pHash implements the P_hash function, as defined in RFC 4346, Section 5.
func pHash(result, secret, seed []byte, hash func() hash.Hash) {
	h := hmac.New(hash, secret)
	h.Write(seed)
	a := h.Sum(nil)

	j := 0
	for j < len(result) {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		b := h.Sum(nil)
		copy(result[j:], b)
		j += len(b)

		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
}

func prf12(hashFunc func() hash.Hash) func(result, secret, label, seed []byte) {
	return func(result, secret, label, seed []byte) {
		labelAndSeed := make([]byte, len(label)+len(seed))
		copy(labelAndSeed, label)
		copy(labelAndSeed[len(label):], seed)

		pHash(result, secret, labelAndSeed, hashFunc)
	}
}
