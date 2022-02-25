package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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
	log.Printf("randFieldElement b=%x", b)
	// b=5ff62c206728a6be32e475544b811474ea079d2665dcf84fc437014d359c2d328305870e65aa69d9

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	log.Printf("randFieldElement n_bytes=%x", n.Bytes())
	k.Mod(k, n)
	k.Add(k, one)
	log.Printf("randFieldElement k_bytes=%x", k.Bytes())
	// k_bytes=9a0d1c1184624197032e6bbbf637fcb380a3695d68f37bb648daaf4ea3b46e7a
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
	log.Printf("testSignAndVerify priv.D=%x", priv.D)
	// testSignAndVerify priv.D=10a8e7424b64ddaf8b3e7e428c3f6e0e253709be285c64bc41cc300fd800c11f

	hashed := []byte("testing")
	r, s, err := ecdsa.Sign(&rnd, priv, hashed)
	if err != nil {
		t.Errorf("error signing: %s", err)
		return
	}
	log.Printf("r=0x%x, s=0x%x", r.Bytes(), s.Bytes())
	// r=0xe14fd9eb5f743e74390b09c9dfffeae4e43fa7fa0985da7d8161b5cf83b61d46, s=0x67d212b5ca4880782922f7e41f7dc054ec025389d209dcb47216e7be98fe06ae

	// after calling Inverse, k=69679341414823589043920591308017428039318963656356153131478201006811587571322, kInv=86586517801769794643900956701147035451346541280727946852964839837080582533940

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

func TestHashToInt(t *testing.T) {
	hash := []byte("testing")
	c := elliptic.P256()
	n := hashToInt(hash, c)
	// log.Printf("n=%v", n)
	if got, want := n.String(), "32762643847147111"; got != want {
		t.Errorf("result mismatch, got=%v, want=%v", got, want)
	}
}

// hashToInt converts a hash value to an integer. Per FIPS 186-4, Section 6.4,
// we use the left-most bits of the hash to match the bit-length of the order of
// the curve. This also performs Step 5 of SEC 1, Version 2.0, Section 4.1.3.
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

func TestFermatInverse(t *testing.T) {
	k := new(big.Int)
	k.SetString("31165868474356909094101301562817744597875721467446372694368806754002914873404", 10)

	n := new(big.Int)
	n.SetString("115792089210356248762697446949407573529996955224135760342422259061068512044369", 10)

	ret := fermatInverse(k, n)
	got := ret.String()

	want := "86225417743096558800740718328827616534367331415382654615473225504007389458516"
	if got != want {
		t.Errorf("result mismatch, got=%v, want=%v", got, want)
	}
}

func fermatInverse(k, N *big.Int) *big.Int {
	two := big.NewInt(2)
	nMinus2 := new(big.Int).Sub(N, two)
	return new(big.Int).Exp(k, nMinus2, N)
}

const aesIV = "IV for ECDSA CTR"

func TestStreamReader(t *testing.T) {
	key := []byte("\x57\x0a\xb7\x5e\xb8\x7a\xbe\x27\x4b\xc4\x19\xb6\x45\xa6\x0f\xdc\xf8\x18\x05\xee\x0a\x49\xbf\x3d\x7c\xdc\x9a\xf7\xe7\x7f\x4e\x0d")
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	csprng := cipher.StreamReader{
		R: zeroReader,
		S: cipher.NewCTR(block, []byte(aesIV)),
	}

	c := elliptic.P256()

	k, err := randFieldElement(c, &csprng)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("\x9a\x0d\x1c\x11\x84\x62\x41\x97\x03\x2e\x6b\xbb\xf6\x37\xfc\xb3\x80\xa3\x69\x5d\x68\xf3\x7b\xb6\x48\xda\xaf\x4e\xa3\xb4\x6e\x7a")
	// log.Printf("k.bytes=%x", k.Bytes())
	if got := k.Bytes(); !bytes.Equal(got, want) {
		t.Errorf("result mismatch, got=%x, want=%x", got, want)
	}
}

type zr struct {
	io.Reader
}

// Read replaces the contents of dst with zeros.
func (z *zr) Read(dst []byte) (n int, err error) {
	for i := range dst {
		dst[i] = 0
	}
	return len(dst), nil
}

var zeroReader = &zr{}

func TestEcdsaPrivateKeySign(t *testing.T) {
	var initial [12]uint32
	rnd := NewRandomForTest(initial)
	c := elliptic.P256()
	priv, err := ecdsa.GenerateKey(c, &rnd)
	if err != nil {
		t.Fatal(err)
	}
	// log.Printf("priv.D=%x", priv.D)
	wantPrivD := []byte("\x10\xa8\xe7\x42\x4b\x64\xdd\xaf\x8b\x3e\x7e\x42\x8c\x3f\x6e\x0e\x25\x37\x09\xbe\x28\x5c\x64\xbc\x41\xcc\x30\x0f\xd8\x00\xc1\x1f")
	if got, want := priv.D.Bytes(), wantPrivD; !bytes.Equal(got, want) {
		t.Errorf("private key mismatch, got=%x, want=%x", got, want)
	}

	digest := []byte("\xcf\x36\xd2\xad\xe1\xc9\x40\x5c\x53\x04\xf6\xa6\xc4\xd1\xe3\x1a\xe3\x5b\x47\xd0\x4d\x6c\x27\x69\x14\x53\xed\x24\xdd\x76\x68\xe6")
	signed, err := priv.Sign(&rnd, digest, nil)
	if err != nil {
		t.Fatal(err)
	}
	// log.Printf("signed=%x", signed)

	// In this case, randutil.MaybeReadByte(rand) in ecdsa.Sign did not read byte.
	want := []byte("\x30\x44\x02\x20\x7e\xe2\x36\xae\x11\x2b\xe7\xa1\x92\xec\x5d\xd7\x40\x69\xbb\x7a\xf8\x13\x1d\x51\x61\xd6\x17\x06\x58\x9a\x9f\x74\xa3\x5b\xb0\x7c\x02\x20\x26\xd3\x02\x17\x5b\x0d\x4d\x28\x17\xa1\x93\xb2\x06\xbc\x4b\x2b\x02\x17\x35\x15\xde\xc4\x02\x69\xa8\x3a\x18\x35\xb8\xda\x4d\x40")
	if got := signed; !bytes.Equal(got, want) {
		t.Errorf("sign result mismatch, got=%x, want=%x", got, want)
	}
}
