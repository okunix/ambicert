package csr

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/url"
)

type CsrGeneratorParams struct {
	Subject            pkix.Name
	SignatureAlgorithm x509.SignatureAlgorithm
	BasicConstraints   *pkix.Extension
	KeyUsage           *pkix.Extension
	ExtendedKeyUsage   *pkix.Extension
	DNSNames           []string
	EmailAddresses     []string
	IPAddresses        []net.IP
	URIs               []*url.URL
}

type CsrGenerator struct {
	params CsrGeneratorParams
}

func NewCsrGenerator(params CsrGeneratorParams) *CsrGenerator {
	return &CsrGenerator{params: params}
}

func (c *CsrGenerator) New(key crypto.PrivateKey) (csr []byte, err error) {
	basicConstraints := c.params.BasicConstraints
	keyUsage := c.params.KeyUsage
	extendedKeyUsage := c.params.ExtendedKeyUsage

	exts := make([]pkix.Extension, 0)
	if basicConstraints != nil {
		exts = append(exts, *basicConstraints)
	}
	if keyUsage != nil {
		exts = append(exts, *keyUsage)
	}
	if extendedKeyUsage != nil {
		exts = append(exts, *extendedKeyUsage)
	}

	template := x509.CertificateRequest{
		Subject:            c.params.Subject,
		DNSNames:           c.params.DNSNames,
		EmailAddresses:     c.params.EmailAddresses,
		SignatureAlgorithm: c.params.SignatureAlgorithm,
		IPAddresses:        c.params.IPAddresses,
		URIs:               c.params.URIs,
		ExtraExtensions:    exts,
	}

	csr, err = x509.CreateCertificateRequest(rand.Reader, &template, key)
	return
}
