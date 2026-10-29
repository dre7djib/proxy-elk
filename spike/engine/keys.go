package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// loadRSAPublicKey lit une clé publique RSA au format PEM PKIX (celle que
// produit `openssl rsa -pubout`, voir spike/keys/README.md). Le moteur ne
// lit jamais la clé privée du proxy (F80) : seul ce fichier lui est monté.
func loadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("lecture de %s: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s ne contient pas de bloc PEM valide", path)
	}
	keyAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("clé PKIX invalide: %w", err)
	}
	key, ok := keyAny.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("la clé PEM n'est pas une clé publique RSA")
	}
	return key, nil
}
