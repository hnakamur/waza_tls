package main

import (
	"crypto"
	"crypto/sha256"
	"log"
	"testing"
)

func TestHashSize(t *testing.T) {
	testCases := []struct {
		want int
		hash crypto.Hash
	}{
		{32, crypto.SHA256},
		{48, crypto.SHA384},
		{64, crypto.SHA512},
		{20, crypto.SHA1},
	}
	for _, c := range testCases {
		got := c.hash.Size()
		if got != c.want {
			t.Errorf("size mismatch for %v, got=%d, want=%d", c.hash, got, c.want)
		}
	}
}

func TestHashSum(t *testing.T) {
	h := sha256.New()
	h.Write([]byte("hello"))
	log.Printf("sum=%x", h.Sum(nil))
	h.Write([]byte("goodbye"))
	log.Printf("sum=%x", h.Sum(nil))
}
