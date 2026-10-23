package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/pem"
	"io"
)

func ecdsaP384GenerateKey(r io.Reader) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), r)
}

func pemEncodeBlock(kind string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
}
