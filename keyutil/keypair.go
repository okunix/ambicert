package keyutil

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/mldsa"
	"errors"
	"strings"

	"github.com/okunix/ambicert/config"
	"github.com/okunix/ambicert/pemutil"
)

var (
	ErrUnsupportedPrivateKeyAlgorithm = errors.New("unsupported private key algorithm provided")
)

type KeyGenerator struct {
	config config.KeyConfig
}

func NewKeyGenerator(config config.KeyConfig) *KeyGenerator {
	return &KeyGenerator{config: config}
}

func (k KeyGenerator) NewKeyPair() (publickey crypto.PublicKey, privatekey crypto.PrivateKey, err error) {
	switch strings.ToLower(strings.TrimSpace(k.config.Algorithm)) {
	case "rsa":
		publickey, privatekey, err = NewRSA(k.config.RSABitDepth)
		return
	case "ed25519":
		publickey, privatekey, err = NewED25519()
		return
	case "ecdsa":
		var curve elliptic.Curve
		curve, err = k.config.GetEllipticCurve()
		if err != nil {
			return
		}
		publickey, privatekey, err = NewEDCSA(curve)
		return
	case "mldsa":
		var param mldsa.Parameters
		param, err = k.config.GetMldsaParameter()
		if err != nil {
			return
		}
		publickey, privatekey, err = NewMLDSA(param)
		return
	}
	return nil, nil, ErrUnsupportedPrivateKeyAlgorithm
}

func (k *KeyGenerator) Populate() (crypto.PrivateKey, error) {
	outputs, err := k.config.GetOutputs()
	if err != nil {
		return nil, err
	}

	_, privatekey, err := k.NewKeyPair()
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	err = pemutil.EncodePrivateKey(&buf, privatekey)
	if err != nil {
		return nil, err
	}

	pem := buf.String()
	for _, v := range outputs {
		if err := v.Write(pem); err != nil {
			return nil, err
		}
	}
	return privatekey, nil
}
