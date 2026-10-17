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
	CreateCsr(ctx context.Context, privatekey crypto.PrivateKey, csrGenParams csr.CsrGeneratorParams) ([]byte, error)
	PublishCsr(ctx context.Context, csr []byte, outputs ...storage.Writable) error
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
	generatedCsr, err := c.CreateCsr(ctx, privatekey, csrGenParams)
	if err != nil {
		return nil, err
	}
	return generatedCsr, c.PublishCsr(ctx, generatedCsr, outputs...)
}

func (c *csrService) CreateCsr(
	ctx context.Context,
	privatekey crypto.PrivateKey,
	csrGenParams csr.CsrGeneratorParams) ([]byte, error) {
	csrgen := csr.NewCsrGenerator(csrGenParams)
	return csrgen.New(privatekey)
}
func (c *csrService) PublishCsr(
	ctx context.Context,
	csr []byte,
	outputs ...storage.Writable,
) error {
	return storage.PublishCertificateRequest(ctx, csr, outputs...)
}
