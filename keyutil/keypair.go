package keyutil

import (
	"crypto"
	"crypto/elliptic"
	"crypto/mldsa"
	"errors"
	"strings"
)

var (
	ErrUnsupportedPrivateKeyAlgorithm = errors.New("unsupported private key algorithm provided")
)

type KeyGeneratorParams struct {
	Algorithm      string
	RSABitDepth    int
	EllipticCurve  elliptic.Curve
	MLDSAParameter mldsa.Parameters
}

type KeyGenerator struct {
	params KeyGeneratorParams
}

func NewKeyGenerator(params KeyGeneratorParams) *KeyGenerator {
	return &KeyGenerator{params: params}
}

func (k KeyGenerator) NewKeyPair() (publickey crypto.PublicKey, privatekey crypto.PrivateKey, err error) {
	switch strings.ToLower(strings.TrimSpace(k.params.Algorithm)) {
	case "rsa":
		publickey, privatekey, err = NewRSA(k.params.RSABitDepth)
		return
	case "ed25519":
		publickey, privatekey, err = NewED25519()
		return
	case "ecdsa":
		publickey, privatekey, err = NewEDCSA(k.params.EllipticCurve)
		return
	case "mldsa":
		publickey, privatekey, err = NewMLDSA(k.params.MLDSAParameter)
		return
	}
	return nil, nil, ErrUnsupportedPrivateKeyAlgorithm
}
