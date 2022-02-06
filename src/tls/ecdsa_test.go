package main

import (
	"crypto/elliptic"
	"io"
	"math/big"
	"testing"
)

var one = new(big.Int).SetInt64(1)

// randFieldElement returns a random element of the order of the given
// curve using the procedure given in FIPS 186-4, Appendix B.5.1.
func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	// Note that for P-521 this will actually be 63 bits more than the order, as
	// division rounds down, but the extra bit is inconsequential.
	b := make([]byte, params.BitSize/8+8) // TODO: use params.N.BitLen()
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

func TestRandFieldElement(t *testing.T) {
	c := elliptic.P256()
	var initial [12]uint32
	r := NewRandomForTest(initial)
	k, err := randFieldElement(c, &r)
	if err != nil {
		t.Fatal(err)
	}
	// fmt.Printf("k=%v\n", k)
	want := "7535431974917535157809964245275928230175247012883497609941754139633030054175"
	got := k.String()
	if got != want {
		t.Errorf("result mismatch, got=%v, want=%v", got, want)
	}
}
