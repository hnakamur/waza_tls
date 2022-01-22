package main

import (
	"log"
	"math/big"
	"math/bits"
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

func TestBitsLeadingZeros(t *testing.T) {
	if got, want := bits.LeadingZeros(1), 63; got != want {
		t.Errorf("result mismatch, got=%d, want=%d", got, want)
	}
}

func TestBigIntDivMod(t *testing.T) {
	testCases := []struct {
		x, y int64
		q, r int64 // T-division
		d, m int64 // Euclidean division
	}{
		{5, 3, 1, 2, 1, 2},
		{-5, 3, -1, -2, -2, 1},
		{5, -3, -1, 2, -1, 2},
		{-5, -3, 1, -2, 2, 1},
		{1, 2, 0, 1, 0, 1},
		{8, 4, 2, 0, 2, 0},
	}
	for _, c := range testCases {
		x := big.NewInt(c.x)
		y := big.NewInt(c.y)

		q1 := new(big.Int).Quo(x, y)
		if got, want := q1.Int64(), c.q; got != want {
			t.Errorf("Quo mismatch, got=%d, want=%d", got, want)
		}

		r1 := new(big.Int).Rem(x, y)
		if got, want := r1.Int64(), c.r; got != want {
			t.Errorf("Rem mismatch, got=%d, want=%d", got, want)
		}

		q2, r2 := new(big.Int).QuoRem(x, y, new(big.Int))
		if got, want := q2.Int64(), c.q; got != want {
			t.Errorf("QuoRem quo mismatch, got=%d, want=%d", got, want)
		}
		if got, want := r2.Int64(), c.r; got != want {
			t.Errorf("QuoRem rem mismatch, got=%d, want=%d", got, want)
		}

		d1 := new(big.Int).Div(x, y)
		if got, want := d1.Int64(), c.d; got != want {
			t.Errorf("Div mismatch, got=%d, want=%d", got, want)
		}

		m1 := new(big.Int).Mod(x, y)
		if got, want := m1.Int64(), c.m; got != want {
			t.Errorf("Mod mismatch, got=%d, want=%d", got, want)
		}

		d2, m2 := new(big.Int).DivMod(x, y, new(big.Int))
		if got, want := d2.Int64(), c.d; got != want {
			t.Errorf("DivMod div mismatch, got=%d, want=%d", got, want)
		}
		if got, want := m2.Int64(), c.m; got != want {
			t.Errorf("DivMod mod mismatch, got=%d, want=%d", got, want)
		}
	}

}
