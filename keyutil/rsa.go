package keyutil

import (
	"crypto/rand"
	"crypto/rsa"
)

func NewRSA(bits int) (*rsa.PublicKey, *rsa.PrivateKey, error) {
	var privatekey *rsa.PrivateKey
	privatekey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return &privatekey.PublicKey, privatekey, err
}
