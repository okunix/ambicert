package keyutil

import (
	"crypto"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
)

var (
	ErrUnsupportedPrivateKeyAlgorithm = errors.New("unsupported private key algorithm provided")
	ErrUnknownEllipticCurve           = errors.New("unknown elliptic curve")
	ErrUnsupportedMLDSAParameter      = errors.New("unsupported mldsa parameter")
)

type KeyConfig struct {
	Algorithm string `yaml:"algorithm"`
	// rsa options
	RSABitDepth int `yaml:"rsaBitDepth"`
	// ecdsa options
	EllipticCurve string `yaml:"ellipticCurve"`
	// mldsa options
	MLDSAParameter int `yaml:"mldsaParameter"`
}

func NewDefaultKeyConfig() KeyConfig {
	return KeyConfig{
		Algorithm:      "rsa",
		RSABitDepth:    4096,
		EllipticCurve:  "P256",
		MLDSAParameter: 44,
	}
}

func (k KeyConfig) ellipticCurve() (elliptic.Curve, error) {
	switch strings.ToLower(k.EllipticCurve) {
	case "p224":
		return elliptic.P224(), nil
	case "p256":
		return elliptic.P256(), nil
	case "p384":
		return elliptic.P384(), nil
	case "p521":
		return elliptic.P521(), nil
	}
	return &elliptic.CurveParams{}, ErrUnknownEllipticCurve
}

func (k KeyConfig) mldsaParameter() (mldsa.Parameters, error) {
	switch k.MLDSAParameter {
	case 44:
		return mldsa.MLDSA44(), nil
	case 65:
		return mldsa.MLDSA65(), nil
	case 87:
		return mldsa.MLDSA87(), nil
	}
	return mldsa.Parameters{}, ErrUnsupportedMLDSAParameter
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
	case "mldsa":
		var param mldsa.Parameters
		param, err = k.mldsaParameter()
		if err != nil {
			return
		}
		publickey, privatekey, err = NewMLDSA(param)
		return
	}
	return nil, nil, ErrUnsupportedPrivateKeyAlgorithm
}
