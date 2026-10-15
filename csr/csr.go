package csr

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"

	"github.com/okunix/ambicert/config"
	"github.com/okunix/ambicert/pemutil"
)

type CsrGenerator struct {
	config config.CsrConfig
}

func NewCsrGenerator(config config.CsrConfig) *CsrGenerator {
	return &CsrGenerator{config: config}
}

func (c *CsrGenerator) New(key crypto.PrivateKey) (csr []byte, err error) {
	ipAddresses, err := c.config.GetIPs()
	if err != nil {
		return
	}

	signatureAlgorithm, err := c.config.GetSignatureAlgorithm()
	if err != nil {
		return
	}

	exts := make([]pkix.Extension, 0)
	basicConstraints, err := c.config.GetBasicConstraints()
	if err != nil {
		return
	}
	if basicConstraints != nil {
		exts = append(exts, *basicConstraints)
	}

	keyUsage, err := c.config.GetKeyUsage()
	if err != nil {
		return
	}
	if keyUsage != nil {
		exts = append(exts, *keyUsage)
	}

	extendedKeyUsage, err := c.config.GetExtendedKeyUsage()
	if err != nil {
		return
	}
	if extendedKeyUsage != nil {
		exts = append(exts, *extendedKeyUsage)
	}

	uris, err := c.config.GetURIs()
	if err != nil {
		return
	}

	template := x509.CertificateRequest{
		Subject:            c.config.GetSubject(),
		DNSNames:           c.config.DNSNames,
		EmailAddresses:     c.config.EmailAddresses,
		SignatureAlgorithm: signatureAlgorithm,
		IPAddresses:        ipAddresses,
		URIs:               uris,
		ExtraExtensions:    exts,
	}

	csr, err = x509.CreateCertificateRequest(rand.Reader, &template, key)
	return
}

func (c *CsrGenerator) Populate(key crypto.PrivateKey) error {
	outputs, err := c.config.GetOutputs()
	if err != nil {
		return err
	}

	der, err := c.New(key)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	err = pemutil.Encode(&buf, "CERTIFICATE REQUEST", der)
	if err != nil {
		return err
	}

	pem := buf.String()
	for _, v := range outputs {
		if err := v.Write(pem); err != nil {
			return err
		}
	}
	return nil
}
