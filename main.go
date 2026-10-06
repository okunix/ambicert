package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
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

var (
	csrConfigFlag string
)

func main() {
	flag.StringVar(&csrConfigFlag, "csr-config", "", "CSR configuration file")
	flag.Parse()
	file, err := os.Open(csrConfigFlag)
	if err != nil {
		panic(err)
	}
	var csrConfig CSRConfig
	yaml.NewDecoder(file).Decode(&csrConfig)
	fmt.Printf("%+v\n", csrConfig)
}
