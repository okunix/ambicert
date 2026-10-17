package service

import (
	"context"
	"crypto"

	"github.com/okunix/ambicert/csr"
	"github.com/okunix/ambicert/storage"
)

type csrService struct {
}

type CsrService interface {
	CreateAndPublish(
		ctx context.Context,
		privatekey crypto.PrivateKey,
		csrGenParams csr.CsrGeneratorParams,
		outputs ...storage.Writable,
	) ([]byte, error)
}

func NewCsrService() CsrService {
	return &csrService{}
}

func (c *csrService) CreateAndPublish(
	ctx context.Context,
	privatekey crypto.PrivateKey,
	csrGenParams csr.CsrGeneratorParams,
	outputs ...storage.Writable,
) ([]byte, error) {
	csrgen := csr.NewCsrGenerator(csrGenParams)
	generatedCsr, err := csrgen.New(privatekey)
	if err != nil {
		return nil, err
	}
	return generatedCsr, storage.PublishCertificateRequest(ctx, generatedCsr, outputs...)
}
