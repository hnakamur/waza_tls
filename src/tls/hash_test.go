package main

import (
	"crypto"
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
