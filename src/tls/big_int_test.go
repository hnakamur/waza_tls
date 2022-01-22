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

var gcdTests = []struct {
	d, x, y, a, b string
}{
	// a <= 0 || b <= 0
	// {"0", "0", "0", "0", "0"},
	// {"7", "0", "1", "0", "7"},
	// {"7", "0", "-1", "0", "-7"},
	// {"11", "1", "0", "11", "0"},
	// {"7", "-1", "-2", "-77", "35"},
	// {"935", "-3", "8", "64515", "24310"},
	{"935", "-3", "-8", "64515", "-24310"},
	// {"935", "3", "-8", "-64515", "-24310"},

	// {"1", "-9", "47", "120", "23"},
	// {"7", "1", "-2", "77", "35"},
	// {"935", "-3", "8", "64515", "24310"},
	// {"935000000000000000", "-3", "8", "64515000000000000000", "24310000000000000000"},
	// {"1", "-221", "22059940471369027483332068679400581064239780177629666810348940098015901108344", "98920366548084643601728869055592650835572950932266967461790948584315647051443", "991"},
}

func testGcd(t *testing.T, d, x, y, a, b *big.Int) {
	var X *big.Int
	if x != nil {
		X = new(big.Int)
	}
	var Y *big.Int
	if y != nil {
		Y = new(big.Int)
	}

	D := new(big.Int).GCD(X, Y, a, b)
	if D.Cmp(d) != 0 {
		t.Errorf("GCD(%s, %s, %s, %s): got d = %s, want %s", x, y, a, b, D, d)
	}
	if x != nil && X.Cmp(x) != 0 {
		t.Errorf("GCD(%s, %s, %s, %s): got x = %s, want %s", x, y, a, b, X, x)
	}
	if y != nil && Y.Cmp(y) != 0 {
		t.Errorf("GCD(%s, %s, %s, %s): got y = %s, want %s", x, y, a, b, Y, y)
	}

	// check results in presence of aliasing (issue #11284)
	a2 := new(big.Int).Set(a)
	b2 := new(big.Int).Set(b)
	a2.GCD(X, Y, a2, b2) // result is same as 1st argument
	if a2.Cmp(d) != 0 {
		t.Errorf("aliased z = a GCD(%s, %s, %s, %s): got d = %s, want %s", x, y, a, b, a2, d)
	}
	if x != nil && X.Cmp(x) != 0 {
		t.Errorf("aliased z = a GCD(%s, %s, %s, %s): got x = %s, want %s", x, y, a, b, X, x)
	}
	if y != nil && Y.Cmp(y) != 0 {
		t.Errorf("aliased z = a GCD(%s, %s, %s, %s): got y = %s, want %s", x, y, a, b, Y, y)
	}

	a2 = new(big.Int).Set(a)
	b2 = new(big.Int).Set(b)
	b2.GCD(X, Y, a2, b2) // result is same as 2nd argument
	if b2.Cmp(d) != 0 {
		t.Errorf("aliased z = b GCD(%s, %s, %s, %s): got d = %s, want %s", x, y, a, b, b2, d)
	}
	if x != nil && X.Cmp(x) != 0 {
		t.Errorf("aliased z = b GCD(%s, %s, %s, %s): got x = %s, want %s", x, y, a, b, X, x)
	}
	if y != nil && Y.Cmp(y) != 0 {
		t.Errorf("aliased z = b GCD(%s, %s, %s, %s): got y = %s, want %s", x, y, a, b, Y, y)
	}

	a2 = new(big.Int).Set(a)
	b2 = new(big.Int).Set(b)
	D = new(big.Int).GCD(a2, b2, a2, b2) // x = a, y = b
	if D.Cmp(d) != 0 {
		t.Errorf("aliased x = a, y = b GCD(%s, %s, %s, %s): got d = %s, want %s", x, y, a, b, D, d)
	}
	if x != nil && a2.Cmp(x) != 0 {
		t.Errorf("aliased x = a, y = b GCD(%s, %s, %s, %s): got x = %s, want %s", x, y, a, b, a2, x)
	}
	if y != nil && b2.Cmp(y) != 0 {
		t.Errorf("aliased x = a, y = b GCD(%s, %s, %s, %s): got y = %s, want %s", x, y, a, b, b2, y)
	}

	a2 = new(big.Int).Set(a)
	b2 = new(big.Int).Set(b)
	D = new(big.Int).GCD(b2, a2, a2, b2) // x = b, y = a
	if D.Cmp(d) != 0 {
		t.Errorf("aliased x = b, y = a GCD(%s, %s, %s, %s): got d = %s, want %s", x, y, a, b, D, d)
	}
	if x != nil && b2.Cmp(x) != 0 {
		t.Errorf("aliased x = b, y = a GCD(%s, %s, %s, %s): got x = %s, want %s", x, y, a, b, b2, x)
	}
	if y != nil && a2.Cmp(y) != 0 {
		t.Errorf("aliased x = b, y = a GCD(%s, %s, %s, %s): got y = %s, want %s", x, y, a, b, a2, y)
	}
}

func TestGcd(t *testing.T) {
	for _, test := range gcdTests {
		d, _ := new(big.Int).SetString(test.d, 0)
		// x, _ := new(big.Int).SetString(test.x, 0)
		// y, _ := new(big.Int).SetString(test.y, 0)
		a, _ := new(big.Int).SetString(test.a, 0)
		b, _ := new(big.Int).SetString(test.b, 0)

		testGcd(t, d, nil, nil, a, b)
		// testGcd(t, d, x, nil, a, b)
		// testGcd(t, d, nil, y, a, b)
		// testGcd(t, d, x, y, a, b)
	}
}

func TestUintSubOverflow(t *testing.T) {
	a := uint(2)
	b := uint(3)
	if got, want := a-b, uint(18446744073709551615); got != want {
		t.Errorf("result mismatch, got=%d, want=%d", got, want)
	}
}
