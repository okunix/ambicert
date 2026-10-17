package keyutil

import (
	"crypto/ed25519"
	"crypto/rand"
)

func NewED25519() (*ed25519.PublicKey, *ed25519.PrivateKey, error) {
	publickey, privatekey, err := ed25519.GenerateKey(rand.Reader)
	return &publickey, &privatekey, err
}
