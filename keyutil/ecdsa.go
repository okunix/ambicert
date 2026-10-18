package keyutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

func NewEDCSA(curve elliptic.Curve) (*ecdsa.PublicKey, *ecdsa.PrivateKey, error) {
	privatekey, err := ecdsa.GenerateKey(curve, rand.Reader)
	return &privatekey.PublicKey, privatekey, err
}
