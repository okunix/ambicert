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
	CreateKeyPair(
		ctx context.Context,
		keyGenParams keyutil.KeyGeneratorParams,
	) (crypto.PublicKey, crypto.PrivateKey, error)
	PublishPrivateKey(
		ctx context.Context,
		privatekey crypto.PrivateKey,
		outputs ...storage.Writable,
	) error
}

func NewKeyService() KeyService {
	return &keyService{}
}

func (c *keyService) CreateAndPublish(
	ctx context.Context,
	keyGenParams keyutil.KeyGeneratorParams,
	outputs ...storage.Writable,
) (crypto.PrivateKey, error) {
	_, privatekey, err := c.CreateKeyPair(ctx, keyGenParams)
	if err != nil {
		return nil, err
	}
	return privatekey, c.PublishPrivateKey(ctx, privatekey, outputs...)
}

func (c *keyService) CreateKeyPair(
	ctx context.Context,
	keyGenParams keyutil.KeyGeneratorParams,
) (crypto.PublicKey, crypto.PrivateKey, error) {
	keygen := keyutil.NewKeyGenerator(keyGenParams)
	return keygen.NewKeyPair()
}

func (c *keyService) PublishPrivateKey(
	ctx context.Context,
	privatekey crypto.PrivateKey,
	outputs ...storage.Writable,
) error {
	return storage.PublishPrivateKey(ctx, privatekey, outputs...)
}
