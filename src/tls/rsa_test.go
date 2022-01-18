package main

import (
	"crypto/x509"
	"encoding/asn1"
	"log"
	"math/big"
	"os"
	"testing"
)

func TestReadRsaPrivateKey(t *testing.T) {
	der, err := os.ReadFile("../../tests/priv-rsa.der")
	if err != nil {
		t.Fatal(err)
	}
	// log.Printf("der=%x", der)
	key, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("key=%+v", key)
}

func TestParsePKCS1PrivateKey(t *testing.T) {
	der, err := os.ReadFile("../../tests/priv-rsa-2.der")
	if err != nil {
		t.Fatal(err)
	}
	var priv pkcs1PrivateKey
	rest, err := asn1.Unmarshal(der, &priv)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) > 0 {
		t.Fatal(asn1.SyntaxError{Msg: "trailing data"})
	}
	log.Printf("priv=%+v", priv)

}

func TestMarshalPKCS1PrivateKey(t *testing.T) {
	der, err := os.ReadFile("../../tests/priv-rsa-2.der")
	if err != nil {
		t.Fatal(err)
	}
	var priv pkcs1PrivateKey
	_, err = asn1.Unmarshal(der, &priv)
	if err != nil {
		t.Fatal(err)
	}
	priv.AdditionalPrimes = append(priv.AdditionalPrimes, priv.AdditionalPrimes[0])

	b, err := asn1.Marshal(priv)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile("../../tests/priv-rsa-3.der", b, 0o644)
	if err != nil {
		t.Fatal(err)
	}
}

// pkcs1PrivateKey is a structure which mirrors the PKCS #1 ASN.1 for an RSA private key.
type pkcs1PrivateKey struct {
	Version int
	N       *big.Int
	E       int
	D       *big.Int
	P       *big.Int
	Q       *big.Int
	// We ignore these values, if present, because rsa will calculate them.
	Dp   *big.Int `asn1:"optional"`
	Dq   *big.Int `asn1:"optional"`
	Qinv *big.Int `asn1:"optional"`

	AdditionalPrimes []pkcs1AdditionalRSAPrime `asn1:"optional,omitempty"`
}

type pkcs1AdditionalRSAPrime struct {
	Prime *big.Int

	// We ignore these values because rsa will calculate them.
	Exp   *big.Int
	Coeff *big.Int
}
