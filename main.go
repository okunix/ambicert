package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"os"

	"go.yaml.in/yaml/v4"
)

func main() {
	var csrConfigFlag string

	flag.StringVar(&csrConfigFlag, "csr-config", "", "CSR configuration file")
	flag.Parse()

	if csrConfigFlag == "" {
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

	if err := savePEM(csrConfig.Output, "CERTIFICATE REQUEST", csr); err != nil {
		panic(err)
	}
	if err := savePEM("private.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key)); err != nil {
		panic(err)
	}

	fmt.Printf("Generated CSR for %s in %s\n", csrConfig.Subject.CommonName, csrConfig.Output)
}
