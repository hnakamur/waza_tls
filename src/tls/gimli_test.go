package main

import (
	"bytes"
	"fmt"
	"testing"
	"unsafe"

	"github.com/bmkessler/gimli"
)

func TestGimli(t *testing.T) {
	var g gimli.Gimli
	g.Update()
	fmt.Printf("g=%d\n", g)
	g.Update()
	fmt.Printf("g=%d\n", g)
}

type GimliReader struct {
	g gimli.Gimli
}

func NewGimliReader(initial [12]uint32) GimliReader {
	g := gimli.Gimli(initial)
	return GimliReader{g: g}
}

func (r *GimliReader) permute() {
	r.g.Update()
}

const (
	blockBytes = 48
	rate       = 16
)

func (r *GimliReader) squeeze(out []byte) {
	i := 0
	for i+rate < len(out) {
		r.permute()
		copy(out[i:], unsafe.Slice((*byte)(unsafe.Pointer(&r.g[0])), rate))
		i += rate
	}
	leftover := len(out) - i
	if leftover != 0 {
		r.permute()
		copy(out[i:], unsafe.Slice((*byte)(unsafe.Pointer(&r.g[0])), leftover))
	}
}

func (r *GimliReader) Read(p []byte) (n int, err error) {
	if len(p) != 0 {
		r.squeeze(p)
	} else {
		r.permute()
	}
	for i := 0; i < 4; i++ {
		r.g[i] = 0
	}
	return len(p), nil
}

func TestGimliReader(t *testing.T) {
	expected := []string{
		"",
		"\x4a",
		"\xd9\xaa",
		"\x47\x5f\x17",
		"\x8c\x46\x12\xaa",
		"\xd7\x54\xeb\xec\x53",
		"\xaa\x6a\x28\xef\xe4\x94",
		"\x3b\x7d\x1d\x4c\x92\x7f\xcc",
		"\x63\xff\xb2\x36\xe2\x30\xf0\x0a",
		"\x26\xaf\xe3\x47\xe1\xb9\xaf\x1e\x36",
		"\xa3\xa0\x63\xcf\xd9\xd8\xf5\x8f\xa9\xcc",
		"\xf3\x73\x00\x14\xc3\xb4\x5e\xcd\x79\x6c\x86",
		"\xc6\xfb\x2c\x1a\x1e\x56\x12\xbe\xd7\x57\xc8\x4b",
		"\xfd\xf9\x03\x3d\x29\x9e\xbb\x56\x52\x67\x61\x95\x47",
		"\x87\x28\x2c\x91\x46\x84\x78\x6c\x74\x61\x11\xbe\x33\xfe",
		"\x19\xab\xed\x9c\xc8\x61\xa1\x0d\xfb\xb2\xf6\x88\x80\x36\x3b",
		"\x7b\x14\xe5\x40\x2f\xa7\x72\xc4\xe0\x92\xa4\xa9\xbb\x20\xd2\x86",
		"\xf2\xec\xf4\xd7\x94\xa0\x3d\x94\x5d\x68\x15\xed\xf7\x64\x74\x4d\x76",
		"\x9c\xf3\xd2\xc7\x6a\x4b\x68\xba\xd9\xf1\xf2\xbe\x0c\x17\x58\x1a\x0a\x1f",
		"\x58\x6f\x9d\x99\x9d\x7a\x75\x19\x4c\xdd\xcc\xaf\xb3\x31\x45\x18\xa4\x63\xe4",
	}

	var initial [12]uint32
	r := NewGimliReader(initial)
	var buf [20]byte
	for i := 0; i < len(buf); i++ {
		n, err := r.Read(buf[0:i])
		if err != nil {
			t.Fatal(err)
		}
		if n != i {
			t.Errorf("n mismatch, got=%d, want=%d", n, i)
		}
		// fmt.Printf("%x\n", buf[0:i])
		if got, want := []byte(expected[i]), buf[0:i]; !bytes.Equal(got, want) {
			t.Errorf("result mismatch, i=%d, got=%x, want=%x", i, got, want)
		}
	}
}
