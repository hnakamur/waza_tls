package main

import (
	"math"
	"strings"
	"testing"
)

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
