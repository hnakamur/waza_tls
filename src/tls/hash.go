package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"log"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	log.Printf("Sha256Hash hash=%x\n", sha256.Sum256([]byte("hello")))
	log.Printf("Sha384Hash hash=%x\n", sha512.Sum384([]byte("hello")))
	return nil
}
