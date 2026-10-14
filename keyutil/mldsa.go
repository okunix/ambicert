package keyutil

import (
	"crypto/mldsa"
)

func NewMLDSA(params mldsa.Parameters) (*mldsa.PublicKey, *mldsa.PrivateKey, error) {
	privatekey, err := mldsa.GenerateKey(params)
	if err != nil {
		return nil, nil, err
	}
	publickey := privatekey.PublicKey()
	return publickey, privatekey, nil
}
