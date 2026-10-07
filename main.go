package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"

	"go.yaml.in/yaml/v4"
)

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

func (s SubjectConfig) ToPKIXName() pkix.Name {
	return pkix.Name{
		CommonName:        s.CommonName,
		Country:           s.Country,
		Organization:      s.Organization,
		OrganizationalUnit s.OrganizationalUnit,
		Locality:          s.Locality,
		Province:          s.Province,
		StreetAddress:     s.StreetAddress,
		PostalCode:        s.PostalCode,
		SerialNumber:      s.SerialNumber,
	}
}

type CSRConfig struct {
	Output             string                  `yaml:"output"`
	SignatureAlgorithm x509.SignatureAlgorithm `yaml:"signatureAlgorithm"`
	Subject            SubjectConfig           `yaml:"subject"`
	DNSNames           []string                `yaml:"dnsNames"`
	EmailAddresses     []string                `yaml:"emailAddresses"`
	IPAddresses        []net.IP                `yaml:"ipAddresses"`
	URIs               []*url.URL              `yaml:"uris"`
	ExtraExtensions    []pkix.Extension        `yaml:"extraExtensions"`
}


func savePEM(path string, blockType string, data []byte) error {
    f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: data})
}


func main() {
	var csrConfigFlag string

	flag.StringVar(&csrConfigFlag, "csr-config", "", "CSR configuration file")
	flag.Parse()

	if csrConfigFlag == ""{
		fmt.Println("Error: --csr-config is required")
		os.Exit(1)
	}

	file, err := os.Open(csrConfigFlag)
	if err != nil {
		panic(err)
	}

	defer file.Close()

	var csrConfig CSRConfig
	if err := yaml.NewDecoder(file).Decode(&csrConfig); err != nil {
		panic(err)
	}

	key, csr, err := generateCrypto(csrConfig)
	if err != nil {
		panic(err)
	}

	if err := savePEM(cfg.Output, "CERTIFICATE REQUEST", csr); err != nil {
		panic(err)
	}
	if err := savePEM("private.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key)); err != nil {
		panic(err)
	}

	fmt.Println("Generated CSR for %s in %s\n", cfg.Subject.CommonName, cfg.Output)
}

func generateCrypto(cfg CSRConfig) (*rsa.PrivateKey, []byte, error){
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := x509.CertificateRequest{
		Subject:         cfg.Subject.ToPKIXName(),
		DNSNames:        cfg.DNSNames,
		EmailAddresses:  cfg.EmailAddresses,
		URIs:            cfg.URIs,
		ExtraExtensions: cf.ExtraExtensions,
	}

	csr, er := x509.CreateCertificateRequest(rand.Reader, &template, key)
	return key, csr, err
}
