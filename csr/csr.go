package csr

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net"
	"net/url"
	"strings"
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

type CSRConfig struct {
	Subject            SubjectConfig `yaml:"subject"`
	SignatureAlgorithm string        `yaml:"signatureAlgorithm"`
	DNSNames           []string      `yaml:"dnsNames"`
	EmailAddresses     []string      `yaml:"emailAddresses"`
	IPAddresses        []string      `yaml:"ipAddresses"`
	URIs               []string      `yaml:"uris"`

	KeyUsage         KeyUsage         `yaml:"keyUsage"`
	ExtendedKeyUsage KeyUsage         `yaml:"extendedKeyUsage"`
	BasicConstraints BasicConstraints `yaml:"basicConstraints"`
}

func (c CSRConfig) keyUsage() (*pkix.Extension, error) {
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

func (c CSRConfig) basicConstraints() (*pkix.Extension, error) {
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

func (c CSRConfig) extendedKeyUsage() (*pkix.Extension, error) {
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

func (c CSRConfig) ips() ([]net.IP, error) {
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

func (c CSRConfig) signatureAlgorithm() (x509.SignatureAlgorithm, error) {
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

func (c CSRConfig) uris() ([]*url.URL, error) {
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

func (c CSRConfig) subject() pkix.Name {
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

func (c *CSRConfig) New(key crypto.PrivateKey) (csr []byte, err error) {
	ipAddresses, err := c.ips()
	if err != nil {
		return
	}

	signatureAlgorithm, err := c.signatureAlgorithm()
	if err != nil {
		return
	}

	exts := make([]pkix.Extension, 0)
	basicConstraints, err := c.basicConstraints()
	if err != nil {
		return
	}
	if basicConstraints != nil {
		exts = append(exts, *basicConstraints)
	}

	keyUsage, err := c.keyUsage()
	if err != nil {
		return
	}
	if keyUsage != nil {
		exts = append(exts, *keyUsage)
	}

	extendedKeyUsage, err := c.extendedKeyUsage()
	if err != nil {
		return
	}
	if extendedKeyUsage != nil {
		exts = append(exts, *extendedKeyUsage)
	}

	uris, err := c.uris()
	if err != nil {
		return
	}

	template := x509.CertificateRequest{
		Subject:            c.subject(),
		DNSNames:           c.DNSNames,
		EmailAddresses:     c.EmailAddresses,
		SignatureAlgorithm: signatureAlgorithm,
		IPAddresses:        ipAddresses,
		URIs:               uris,
		ExtraExtensions:    exts,
	}

	csr, err = x509.CreateCertificateRequest(rand.Reader, &template, key)
	return
}
