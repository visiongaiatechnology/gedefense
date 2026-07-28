package main

import (
	"crypto/ed25519"
	"encoding/pem"
	"io"
)

func ed25519GenerateKey(r io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(r)
}

func pemEncodeBlock(kind string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
}
