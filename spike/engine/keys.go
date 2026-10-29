package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// loadRSAPublicKey reads an RSA public key in PKIX PEM format (what
// `openssl rsa -pubout` produces, see spike/keys/README.md). The engine never
// reads the proxy's private key (F80): only this file is mounted for it.
func loadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s does not contain a valid PEM block", path)
	}
	keyAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid PKIX key: %w", err)
	}
	key, ok := keyAny.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("PEM key is not an RSA public key")
	}
	return key, nil
}
