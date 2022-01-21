package main

import (
	"log"
	"math/big"
	"testing"
)

func TestBigIntSetBytes(t *testing.T) {
	var i big.Int
	i.SetBytes([]byte{0x12, 0x34, 0x56, 0x78, 0x90})
	log.Printf("i=%s", i.String())
	if got, want := i.String(), "78187493520"; got != want {
		t.Errorf("result mismatch, got=%s, want=%s", got, want)
	}
}
