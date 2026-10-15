package config

import (
	"crypto/elliptic"
	"crypto/mldsa"
	"errors"
	"strings"

	"github.com/okunix/ambicert/storage"
)

var (
	ErrUnknownEllipticCurve      = errors.New("unknown elliptic curve")
	ErrUnsupportedMLDSAParameter = errors.New("unsupported mldsa parameter")
)

type KeyConfig struct {
	Algorithm string `yaml:"algorithm"`
	// rsa options
	RSABitDepth int `yaml:"rsaBitDepth"`
	// ecdsa options
	EllipticCurve string `yaml:"ellipticCurve"`
	// mldsa options
	MLDSAParameter int `yaml:"mldsaParameter"`
	// output configuration
	Outputs []OutputConfig `yaml:"outputs"`
}

func NewDefaultKeyConfig() KeyConfig {
	return KeyConfig{
		Algorithm:      "rsa",
		RSABitDepth:    4096,
		EllipticCurve:  "P256",
		MLDSAParameter: 44,
	}
}

func (k KeyConfig) GetEllipticCurve() (elliptic.Curve, error) {
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

func (k KeyConfig) GetMldsaParameter() (mldsa.Parameters, error) {
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

func (k KeyConfig) GetOutputs() ([]storage.Writable, error) {
	outputs := make([]storage.Writable, len(k.Outputs))
	for i, v := range k.Outputs {
		output, err := v.Output()
		if err != nil {
			return nil, err
		}
		outputs[i] = output
	}
	return outputs, nil
}
