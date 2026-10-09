package keyutil

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
)

var (
	ErrUnsupportedPrivateKeyAlgorithm = errors.New("unsupported private key algorithm provided")
)

type KeyConfig struct {
	Algorithm string `yaml:"algorithm"`
	// rsa only options
	RSABitDepth int `yaml:"rsaBitDepth"`
}

func newDefaultKeyConfig() KeyConfig {
	return KeyConfig{
		Algorithm:   "rsa",
		RSABitDepth: 4096,
	}
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
	}
	return nil, nil, ErrUnsupportedPrivateKeyAlgorithm
}
