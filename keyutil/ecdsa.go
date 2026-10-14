package keyutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
)

func NewEDCSA(curve elliptic.Curve, r io.Reader) (*ecdsa.PublicKey, *ecdsa.PrivateKey, error) {
	privatekey, err := ecdsa.GenerateKey(curve, rand.Reader)
	return &privatekey.PublicKey, privatekey, err
}
