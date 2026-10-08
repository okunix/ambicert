package csr

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"strings"
)

type Config struct {
	IO  IOConfig  `yaml:"io"`
	CSR CSRConfig `yaml:"csr"`
}

type IOConfig struct {
	// where to put csr after generation. use stdout if not specified
	CSROutputFile string `yaml:"csrOutputFile"`

	// maybe i should move this options to CSRConfig instead
	// user can provide his own key
	PrivateKeyFile string `yaml:"privateKeyFile"`

	// auto-generated key configuration. options are ignored if privateKeyFile is provided
	Key KeyConfig `yaml:"key"`
}

type SubjectConfig struct {
	Country            []string `yaml:"country,omitempty"`
	Organization       []string `yaml:"organization,omitempty"`
	OrganizationalUnit []string `yaml:"organizatinoalUnit,omitempty"`
	Locality           []string `yaml:"locality,omitempty"`
	Province           []string `yaml:"province,omitempty"`
	StreetAddress      []string `yaml:"streetAddress,omitempty"`
	PostalCode         []string `yaml:"postalCode,omitempty"`
	SerialNumber       string   `yaml:"serialNumber,omitempty"`
	CommonName         string   `yaml:"commonName,omitempty"`
}

type CSRConfig struct {
	Subject            SubjectConfig `yaml:"subject"`
	SignatureAlgorithm string        `yaml:"signatureAlgorithm"`
	DNSNames           []string      `yaml:"dnsNames"`
	EmailAddresses     []string      `yaml:"emailAddresses"`
	IPAddresses        []string      `yaml:"ipAddresses"`

	KeyUsage         []KeyUsage `yaml:"keyUsage"`
	ExtendedKeyUsage []KeyUsage `yaml:"extendedKeyUsage"`
	BasicConstraints []string   `yaml:"basicConstraints"`
}

func (csrConfig CSRConfig) GetIPs() ([]net.IP, error) {
	ips := make([]net.IP, 0)
	for _, v := range csrConfig.IPAddresses {
		ip := net.ParseIP(v)
		if ip == nil {
			return nil, errors.New("failed to parse an ip address")
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func (csrConfig CSRConfig) GetSignatureAlgorithm() (x509.SignatureAlgorithm, error) {
	switch strings.TrimSpace(csrConfig.SignatureAlgorithm) {
	case "SHA256WithRSA":
		return x509.SHA256WithRSA, nil
	}
	return x509.UnknownSignatureAlgorithm, nil
}

func (csrConfig CSRConfig) GetSubject() pkix.Name {
	return pkix.Name{
		CommonName:         csrConfig.Subject.CommonName,
		Country:            csrConfig.Subject.Country,
		Organization:       csrConfig.Subject.Organization,
		OrganizationalUnit: csrConfig.Subject.OrganizationalUnit,
		Locality:           csrConfig.Subject.Locality,
		Province:           csrConfig.Subject.Province,
		StreetAddress:      csrConfig.Subject.StreetAddress,
		PostalCode:         csrConfig.Subject.PostalCode,
		SerialNumber:       csrConfig.Subject.SerialNumber,
	}
}

func (cfg *Config) New() (key crypto.PrivateKey, csr []byte, err error) {
	_, key, err = cfg.IO.Key.New()
	if err != nil {
		return
	}

	ipAddresses, err := cfg.CSR.GetIPs()
	if err != nil {
		return
	}

	signatureAlgorithm, err := cfg.CSR.GetSignatureAlgorithm()
	if err != nil {
		return
	}

	template := x509.CertificateRequest{
		Subject:            cfg.CSR.GetSubject(),
		DNSNames:           cfg.CSR.DNSNames,
		EmailAddresses:     cfg.CSR.EmailAddresses,
		SignatureAlgorithm: signatureAlgorithm,
		IPAddresses:        ipAddresses,
		// ExtraExtensions: cfg.ExtraExtensions,
	}

	csr, err = x509.CreateCertificateRequest(rand.Reader, &template, key)
	return
}
