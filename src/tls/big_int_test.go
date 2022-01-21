package main

import (
	"log"
	"math/big"
	"testing"
)

func TestBigIntSetBytes(t *testing.T) {
	var i big.Int
	i.SetBytes([]byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0xfe})
	if got, want := i.String(), "335812727627494322174"; got != want {
		t.Errorf("result mismatch, got=%s, want=%s", got, want)
	}
}

func TestBigIntSetStringEmpty(t *testing.T) {
	i, ok := new(big.Int).SetString("0", 0)
	if !ok {
		t.Fatal("failed to set string")
	}
	log.Printf("i=%s", i.String())
}
