package main

import (
	"encoding/asn1"
	"fmt"
	"log"
	"math"
	"math/big"
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

func TestReadOptionalASN1(t *testing.T) {
	s := cryptobyte.String([]byte("\x02\x01\x00"))
	var child cryptobyte.String
	var present bool
	ok := s.ReadOptionalASN1(&child, &present, asn1.TagInteger)
	if !ok {
		t.Fatalf("read failed")
	}
	log.Printf("child=%+v, present=%v", child, present)
}

func TestReadASN1Integer(t *testing.T) {
	t.Run("BuildBigInt", func(t *testing.T) {
		testCases := []struct {
			input string
			want  string
		}{
			{input: "0", want: "\x02\x01\x00"},
			{input: "127", want: "\x02\x01\x7f"},
			{input: "128", want: "\x02\x02\x00\x80"},
			{input: "255", want: "\x02\x02\x00\xff"},
			{input: "256", want: "\x02\x02\x01\x00"},
			{input: "-1", want: "\x02\x01\xff"},
			{input: "-2", want: "\x02\x01\xfe"},
			{input: "-128", want: "\x02\x01\x80"},
			{input: "-129", want: "\x02\x02\xff\x7f"},
			{input: "-130", want: "\x02\x02\xff\x7e"},
		}
		for _, c := range testCases {
			bi, ok := big.NewInt(0).SetString(c.input, 10)
			if !ok {
				t.Fatalf("invalid input=%s", c.input)
			}
			b := cryptobyte.NewBuilder(nil)
			b.AddASN1BigInt(bi)
			got := string(b.BytesOrPanic())
			if got != c.want {
				t.Errorf("result mismatch, input=%s, got=%x, want=%x",
					c.input, got, c.want)
			}
		}
	})
	t.Run("BigInt", func(t *testing.T) {
		testCases := []struct {
			input       string
			wantSuccess bool
			wantStr     string
		}{
			{input: "\x02\x01\x00", wantSuccess: true, wantStr: "0"},
			{input: "\x02\x01\x01", wantSuccess: true, wantStr: "1"},
			{input: "\x02\x01\x7f", wantSuccess: true, wantStr: "127"},
			{input: "\x02\x01\x80", wantSuccess: true, wantStr: "-128"},
			{input: "\x02\x01\xff", wantSuccess: true, wantStr: "-1"},
			{input: "\x02\x02\x01\x00", wantSuccess: true, wantStr: "256"},
			{input: "\x02\x08\x00" + strings.Repeat("\xff", 7), wantSuccess: true,
				wantStr: "72057594037927935"},
			{input: "\x02\x09\x00" + strings.Repeat("\xff", 8), wantSuccess: true,
				wantStr: "18446744073709551615"},
		}
		for _, c := range testCases {
			var gotInt big.Int
			s := cryptobyte.String([]byte(c.input))
			gotSuccess := s.ReadASN1Integer(&gotInt)
			if gotSuccess != c.wantSuccess {
				t.Errorf("success mismatched, input=%q, got=%v, want=%v",
					c.input, gotSuccess, c.wantSuccess)
			} else {
				wantInt, ok := big.NewInt(0).SetString(c.wantStr, 10)
				if !ok {
					t.Fatalf("bad wantStr %s for input=%q", c.wantStr, c.input)
				}
				if gotInt.Cmp(wantInt) != 0 {
					t.Errorf("int value mismatched, input=%q, got=%v, want=%v",
						c.input, &gotInt, wantInt)
				}
			}
		}
	})
}

func TestAddASN1BigInt(t *testing.T) {
	// n := new(big.Int).SetInt64(-32768)
	n := new(big.Int).SetInt64(-256)
	nMinus1 := new(big.Int).Neg(n)
	bigOne := new(big.Int).SetInt64(1)
	nMinus1.Sub(nMinus1, bigOne)
	bytes := nMinus1.Bytes()
	fmt.Printf("bytes=%x\n", bytes)
	for i := range bytes {
		bytes[i] ^= 0xff
	}
	fmt.Printf("bytes#2=%x\n", bytes)
	var dest []byte
	if len(bytes) == 0 || bytes[0]&0x80 == 0 {
		dest = append(dest, 0xff)
	}
	dest = append(dest, bytes...)
	fmt.Printf("dest=%x\n", dest)

	var b cryptobyte.Builder
	b.AddASN1BigInt(n)
	bytes, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("result=%x\n", bytes)

	var out big.Int
	s := cryptobyte.String(bytes)
	if !s.ReadASN1Integer(&out) {
		t.Error("cannot read ASN1 integer")
	}
	if out.Cmp(n) != 0 {
		t.Errorf("read value mismatch, got=%v, want=%v", out, n)
	}
}

func TestAsn1Signed(t *testing.T) {
	testCases := []struct {
		input   string
		wantOut int64
		wantRet bool
	}{
		{input: "\x7f", wantOut: 127, wantRet: true},
		{input: "\x80", wantOut: -128, wantRet: true},
		{input: "\x81", wantOut: -127, wantRet: true},
		{input: "\xfe", wantOut: -2, wantRet: true},
		{input: "\xff", wantOut: -1, wantRet: true},
		{input: "\x7f\xff", wantOut: 32767, wantRet: true},
		{input: "\x80\x00", wantOut: -32768, wantRet: true},
		{input: "\x80\x01", wantOut: -32767, wantRet: true},
		{input: "\xff\xfe", wantOut: -2, wantRet: true},
		{input: "\xff\xff", wantOut: -1, wantRet: true},
		{input: "\x7f" + strings.Repeat("\xff", 7), wantOut: math.MaxInt64, wantRet: true},
		{input: strings.Repeat("\xff", 8), wantOut: -1, wantRet: true},
		{input: strings.Repeat("\xff", 9), wantRet: false},
	}
	for _, c := range testCases {
		var out int64
		ret := asn1Signed(&out, []byte(c.input))
		if ret != c.wantRet {
			t.Errorf("return value mismatch for input=%q, got=%v, want=%v", c.input, ret, c.wantRet)
		} else if out != c.wantOut {
			t.Errorf("output value mismatch for input=%q, got=%d, want=%d", c.input, out, c.wantOut)
		}
	}
}

func asn1Signed(out *int64, n []byte) bool {
	length := len(n)
	if length > 8 {
		return false
	}
	for i := 0; i < length; i++ {
		*out <<= 8
		*out |= int64(n[i])
	}
	// Shift up and down in order to sign extend the result.
	*out <<= 64 - uint8(length)*8
	*out >>= 64 - uint8(length)*8
	return true
}

func TestAsn1Unsigned(t *testing.T) {
	testCases := []struct {
		input   string
		wantOut uint64
		wantRet bool
	}{
		{input: "\x7f", wantOut: 127, wantRet: true},
		{input: "\x80", wantRet: false},
		{input: "\xff", wantRet: false},
		{input: "\x00\x80", wantOut: 128, wantRet: true},
		{input: strings.Repeat("\x00", 9), wantOut: 0, wantRet: true},
		{input: "\x00" + strings.Repeat("\xff", 8), wantOut: math.MaxUint64, wantRet: true},
		{input: "\x01" + strings.Repeat("\x00", 8), wantRet: false},
		{input: strings.Repeat("\x00", 10), wantRet: false},
	}
	for _, c := range testCases {
		var out uint64
		ret := asn1Unsigned(&out, []byte(c.input))
		if ret != c.wantRet {
			t.Errorf("return value mismatch for input=%q, got=%v, want=%v", c.input, ret, c.wantRet)
		} else if out != c.wantOut {
			t.Errorf("output value mismatch for input=%q, got=%d, want=%d", c.input, out, c.wantOut)
		}
	}
}

func asn1Unsigned(out *uint64, n []byte) bool {
	length := len(n)
	if length > 9 || length == 9 && n[0] != 0 {
		// Too large for uint64.
		return false
	}
	if n[0]&0x80 != 0 {
		// Negative number.
		return false
	}
	for i := 0; i < length; i++ {
		*out <<= 8
		*out |= uint64(n[i])
	}
	return true
}
