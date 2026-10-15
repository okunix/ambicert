package config

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net"
	"net/url"
	"strings"

	"github.com/okunix/ambicert/storage"
)

var (
	ErrInvalidIP       = errors.New("failed to parse an ip address")
	ErrUnknownKeyUsage = errors.New("unknown key usage provided")
)

type BasicConstraints struct {
	IsCA       bool `yaml:"isCA,omitempty"`
	MaxPathLen int  `yaml:"maxPathLen,omitempty"`
	Critical   bool `yaml:"critical,omitempty"`
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

type CsrConfig struct {
	Subject            SubjectConfig `yaml:"subject"`
	SignatureAlgorithm string        `yaml:"signatureAlgorithm"`
	DNSNames           []string      `yaml:"dnsNames"`
	EmailAddresses     []string      `yaml:"emailAddresses"`
	IPAddresses        []string      `yaml:"ipAddresses"`
	URIs               []string      `yaml:"uris"`

	KeyUsage         KeyUsage         `yaml:"keyUsage"`
	ExtendedKeyUsage KeyUsage         `yaml:"extendedKeyUsage"`
	BasicConstraints BasicConstraints `yaml:"basicConstraints"`

	// output configuration
	Outputs []OutputConfig `yaml:"outputs"`
}

func (c CsrConfig) GetKeyUsage() (*pkix.Extension, error) {
	if len(c.KeyUsage.Values) == 0 {
		return nil, nil
	}
	var ku x509.KeyUsage
	for _, v := range c.KeyUsage.Values {
		switch v {
		case "digitalSignature":
			ku |= x509.KeyUsageDigitalSignature
		case "keyEnchiperment":
			ku |= x509.KeyUsageKeyEncipherment
		case "dataEncipherment":
			ku |= x509.KeyUsageDataEncipherment
		case "keyAgreement":
			ku |= x509.KeyUsageKeyAgreement
		case "keyCertSign":
			ku |= x509.KeyUsageCertSign
		case "CRLSign":
			ku |= x509.KeyUsageCRLSign
		case "encipherOnly":
			ku |= x509.KeyUsageEncipherOnly
		case "decipherOnly":
			ku |= x509.KeyUsageDecipherOnly
		default:
			return nil, ErrUnknownKeyUsage
		}
	}
	der, err := keyUsageDER(ku)
	if err != nil {
		return nil, err
	}
	ext := &pkix.Extension{
		Id:       oidKeyUsage,
		Critical: c.KeyUsage.Critical,
		Value:    der,
	}
	return ext, nil
}

func (c CsrConfig) GetBasicConstraints() (*pkix.Extension, error) {
	der, err := asn1.Marshal(struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}{IsCA: c.BasicConstraints.IsCA, MaxPathLen: c.BasicConstraints.MaxPathLen})
	return &pkix.Extension{
		Id:       oidBasicConstraints,
		Critical: c.BasicConstraints.Critical,
		Value:    der,
	}, err
}

func (c CsrConfig) GetExtendedKeyUsage() (*pkix.Extension, error) {
	if len(c.ExtendedKeyUsage.Values) == 0 {
		return nil, nil
	}
	oid := make([]asn1.ObjectIdentifier, 0)
	for _, v := range c.ExtendedKeyUsage.Values {
		switch v {
		case "serverAuth":
			oid = append(oid, oidServerAuth)
		case "clientAuth":
			oid = append(oid, oidClientAuth)
		case "codeSigning":
			oid = append(oid, oidCodeSigning)
		case "emailProtection":
			oid = append(oid, oidEmailProtection)
		case "timeStamping":
			oid = append(oid, oidTimeStamping)
		case "OCSPSigning":
			oid = append(oid, oidOCSPSigning)
		}
	}
	der, err := asn1.Marshal(oid)
	if err != nil {
		return nil, err
	}
	ext := &pkix.Extension{
		Id:       oidExtKeyUsage,
		Critical: c.ExtendedKeyUsage.Critical,
		Value:    der,
	}
	return ext, nil
}

func (c CsrConfig) GetIPs() ([]net.IP, error) {
	ips := make([]net.IP, 0)
	for _, v := range c.IPAddresses {
		ip := net.ParseIP(v)
		if ip == nil {
			return nil, ErrInvalidIP
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func (c CsrConfig) GetSignatureAlgorithm() (x509.SignatureAlgorithm, error) {
	switch strings.TrimSpace(c.SignatureAlgorithm) {
	case "SHA256WithRSA":
		return x509.SHA256WithRSA, nil
	case "MD5WithRSA":
		return x509.SHA256WithRSA, nil
	case "SHA1WithRSA":
		return x509.SHA1WithRSA, nil
	case "SHA384WithRSA":
		return x509.SHA384WithRSA, nil
	case "SHA512WithRSA":
		return x509.SHA512WithRSA, nil
	case "ECDSAWithSHA1":
		return x509.ECDSAWithSHA1, nil
	case "ECDSAWithSHA256":
		return x509.ECDSAWithSHA256, nil
	case "ECDSAWithSHA384":
		return x509.ECDSAWithSHA384, nil
	case "ECDSAWithSHA512":
		return x509.ECDSAWithSHA512, nil
	case "SHA256WithRSAPSS":
		return x509.SHA256WithRSAPSS, nil
	case "SHA384WithRSAPSS":
		return x509.SHA384WithRSAPSS, nil
	case "SHA512WithRSAPSS":
		return x509.SHA512WithRSAPSS, nil
	case "PureEd25519":
		return x509.PureEd25519, nil
	case "MLDSA44":
		return x509.MLDSA44, nil
	case "MLDSA65":
		return x509.MLDSA65, nil
	case "MLDSA87":
		return x509.MLDSA87, nil
	}
	return x509.UnknownSignatureAlgorithm, nil
}

func (c CsrConfig) GetURIs() ([]*url.URL, error) {
	res := make([]*url.URL, len(c.URIs))
	for k, v := range c.URIs {
		uri, err := url.Parse(v)
		if err != nil {
			return nil, err
		}
		res[k] = uri
	}
	return res, nil
}

func (c CsrConfig) GetSubject() pkix.Name {
	return pkix.Name{
		CommonName:         c.Subject.CommonName,
		Country:            c.Subject.Country,
		Organization:       c.Subject.Organization,
		OrganizationalUnit: c.Subject.OrganizationalUnit,
		Locality:           c.Subject.Locality,
		Province:           c.Subject.Province,
		StreetAddress:      c.Subject.StreetAddress,
		PostalCode:         c.Subject.PostalCode,
		SerialNumber:       c.Subject.SerialNumber,
	}
}

func (c CsrConfig) GetOutputs() ([]storage.Writable, error) {
	outputs := make([]storage.Writable, len(c.Outputs))
	for k, v := range c.Outputs {
		output, err := v.Output()
		if err != nil {
			return nil, err
		}
		outputs[k] = output
	}
	return outputs, nil
}
