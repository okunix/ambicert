package service

import (
	"context"
	"crypto"

	"github.com/okunix/ambicert/keyutil"
	"github.com/okunix/ambicert/storage"
)

type keyService struct {
}

type KeyService interface {
	CreateAndPublish(
		ctx context.Context,
		keyGenParams keyutil.KeyGeneratorParams,
		outputs ...storage.Writable,
	) (crypto.PrivateKey, error)
}

func NewKeyService() KeyService {
	return &keyService{}
}

func (c *keyService) CreateAndPublish(
	ctx context.Context,
	keyGenParams keyutil.KeyGeneratorParams,
	outputs ...storage.Writable,
) (crypto.PrivateKey, error) {
	keygen := keyutil.NewKeyGenerator(keyGenParams)
	_, privatekey, err := keygen.NewKeyPair()
	if err != nil {
		return privatekey, err
	}
	return privatekey, storage.PublishPrivateKey(ctx, privatekey, outputs...)
}
