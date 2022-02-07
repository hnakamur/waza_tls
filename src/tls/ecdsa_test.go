package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"io"
	"log"
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

func TestGenerateEcdsaPrivateKey(t *testing.T) {
	c := elliptic.P256()
	var initial [12]uint32
	r := NewRandomForTest(initial)
	key, err := ecdsa.GenerateKey(c, &r)
	if err != nil {
		t.Fatal(err)
	}
	// log.Printf("x=%x, y=%x, d=%x", key.X, key.Y, key.D)

	hexWantD := "10a8e7424b64ddaf8b3e7e428c3f6e0e253709be285c64bc41cc300fd800c11f"
	hexWantX := "b4eda0b0f478fdc289d8d759f5600eb873e711f70090a8cf55ccadcfeccaf023"
	hexWantY := "9f4cecf8a0eae3d3f6299cdb52fde60fb64aa3694795df1516bc9ddb05aa0ecc"

	hexGotD := fmt.Sprintf("%x", key.D)
	hexGotX := fmt.Sprintf("%x", key.X)
	hexGotY := fmt.Sprintf("%x", key.Y)

	if hexGotD != hexWantD {
		t.Errorf("D mismatch, got=%s, want=%s", hexGotD, hexWantD)
	}
	if hexGotX != hexWantX {
		t.Errorf("X mismatch, got=%s, want=%s", hexGotX, hexWantX)
	}
	if hexGotY != hexWantY {
		t.Errorf("Y mismatch, got=%s, want=%s", hexGotY, hexWantY)
	}
}

func TestSignAndVerify(t *testing.T) {
	testAllCurves(t, testSignAndVerify)
}

func testSignAndVerify(t *testing.T, c elliptic.Curve) {
	var initial [12]uint32
	rnd := NewRandomForTest(initial)

	priv, _ := ecdsa.GenerateKey(c, &rnd)

	hashed := []byte("testing")
	r, s, err := ecdsa.Sign(&rnd, priv, hashed)
	if err != nil {
		t.Errorf("error signing: %s", err)
		return
	}
	log.Printf("r=0x%x, s=0x%x", r.Bytes(), s.Bytes())
	// r=0xe14fd9eb5f743e74390b09c9dfffeae4e43fa7fa0985da7d8161b5cf83b61d46, s=0x67d212b5ca4880782922f7e41f7dc054ec025389d209dcb47216e7be98fe06ae

	if !ecdsa.Verify(&priv.PublicKey, hashed, r, s) {
		t.Errorf("Verify failed")
	}

	hashed[0] ^= 0xff
	if ecdsa.Verify(&priv.PublicKey, hashed, r, s) {
		t.Errorf("Verify always works!")
	}
}

func testAllCurves(t *testing.T, f func(*testing.T, elliptic.Curve)) {
	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P256", elliptic.P256()},
		// {"P224", elliptic.P224()},
		// {"P384", elliptic.P384()},
		// {"P521", elliptic.P521()},
	}
	if testing.Short() {
		tests = tests[:1]
	}
	for _, test := range tests {
		curve := test.curve
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f(t, curve)
		})
	}
}
