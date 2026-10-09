package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/okunix/ambicert/csr"
	"github.com/okunix/ambicert/keyutil"
	"go.yaml.in/yaml/v4"
)

type Config struct {
	// where to put csr after generation. use stdout if not specified
	OutputFile string `yaml:"csrOutputFile"`

	// maybe i should move this options to CSRConfig instead
	// user can provide his own key
	PrivateKeyFile string `yaml:"privateKeyFile"`

	// auto-generated key configuration. options are ignored if privateKeyFile is provided
	Key keyutil.KeyConfig `yaml:"key"`

	Template csr.CSRConfig `yaml:"template"`
}

var csrConfigFlag string

func init() {
	flag.StringVar(&csrConfigFlag, "csr-config", "", csrConfigFlag)
}

func main() {
	flag.Parse()

	file, err := os.Open(csrConfigFlag)
	if err != nil {
		panic(err)
	}

	var csrConfig Config
	if err := yaml.NewDecoder(file).Decode(&csrConfig); err != nil {
		panic(err)
	}

	keyPEM, err := os.ReadFile(csrConfig.PrivateKeyFile)
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(keyPEM)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	csr, err := csrConfig.Template.New(key.(crypto.PrivateKey))
	if err != nil {
		fmt.Println("error creating csr")
		panic(err)
	}

	err = pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})
	if err != nil {
		panic(err)
	}
}
