package keyutil

import (
	"crypto"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
)

var (
	ErrUnsupportedPrivateKeyAlgorithm = errors.New("unsupported private key algorithm provided")
	ErrUnknownEllipticCurve           = errors.New("unknown elliptic curve")
)

type KeyConfig struct {
	Algorithm string `yaml:"algorithm"`
	// rsa only options
	RSABitDepth int `yaml:"rsaBitDepth"`
	// ecdsa only options
	EllipticCurve string `yaml:"ellipticCurve"`
}

func NewDefaultKeyConfig() KeyConfig {
	return KeyConfig{
		Algorithm:     "rsa",
		RSABitDepth:   4096,
		EllipticCurve: "P256",
	}
}

func (k KeyConfig) ellipticCurve() (elliptic.Curve, error) {
	switch strings.ToUpper(k.EllipticCurve) {
	case "P224":
		return elliptic.P224(), nil
	case "P256":
		return elliptic.P256(), nil
	case "P384":
		return elliptic.P384(), nil
	case "P521":
		return elliptic.P521(), nil
	}
	return &elliptic.CurveParams{}, ErrUnknownEllipticCurve
}

func (k KeyConfig) New() (publickey crypto.PublicKey, privatekey crypto.PrivateKey, err error) {
	switch strings.ToLower(strings.TrimSpace(k.Algorithm)) {
	case "rsa":
		var rsakey *rsa.PrivateKey
		rsakey, err = rsa.GenerateKey(rand.Reader, k.RSABitDepth)
		if err != nil {
			return nil, nil, err
		}
		publickey = rsakey.Public()
		privatekey = rsakey
		return
	case "ed25519":
		publickey, privatekey, err = ed25519.GenerateKey(rand.Reader)
		return
	case "ecdsa":
		var curve elliptic.Curve
		curve, err = k.ellipticCurve()
		if err != nil {
			return
		}
		publickey, privatekey, err = NewEDCSA(curve, rand.Reader)
		return
	}
	return nil, nil, ErrUnsupportedPrivateKeyAlgorithm
}
