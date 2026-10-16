package config

import (
	"fmt"
	"io"
	"os"

	"go.yaml.in/yaml/v4"
)

type CertConfig struct {
	// auto-generated key configuration
	Key KeyConfig `yaml:"key"`
	// certificate signing request configuration
	CSR CsrConfig `yaml:"csr"`
}

func newDefaultCertConfig() CertConfig {
	return CertConfig{
		Key: NewDefaultKeyConfig(),
	}
}

func ReadCertConfigFile(configFile string) (CertConfig, error) {
	file, err := os.Open(configFile)
	if err != nil {
		return newDefaultCertConfig(), fmt.Errorf("failed to open file %s", configFile)
	}
	return ReadCertConfig(file)
}

func ReadCertConfig(r io.Reader) (CertConfig, error) {
	csrConfig := newDefaultCertConfig()
	err := yaml.NewDecoder(r).Decode(&csrConfig)
	return csrConfig, err
}
