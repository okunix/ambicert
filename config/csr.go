package config

import (
	"fmt"
	"io"
	"os"

	"github.com/okunix/ambicert/csr"
	"github.com/okunix/ambicert/keyutil"
	"go.yaml.in/yaml/v4"
)

type CsrConfig struct {
	// where to put csr after generation. use stdout if not specified
	OutputFile string `yaml:"csrOutputFile"`
	// where to put key after generation. use stdout if not specified
	KeyFile string `yaml:"keyOutputFile"`

	// maybe i should move this options to CSRConfig instead
	// user can provide his own key
	PrivateKeyFile string `yaml:"privateKeyFile"`

	// auto-generated key configuration. options are ignored if privateKeyFile is provided
	Key keyutil.KeyConfig `yaml:"key"`

	Template csr.CSRConfig `yaml:"template"`
}

func newDefaultCsrConfig() CsrConfig {
	return CsrConfig{
		Key: keyutil.NewDefaultKeyConfig(),
	}
}

func ReadCsrConfigFile(configFile string) (CsrConfig, error) {
	file, err := os.Open(configFile)
	if err != nil {
		return newDefaultCsrConfig(), fmt.Errorf("failed to open file %s", configFile)
	}
	return ReadCsrConfig(file)
}
func ReadCsrConfig(r io.Reader) (CsrConfig, error) {
	csrConfig := newDefaultCsrConfig()
	err := yaml.NewDecoder(r).Decode(&csrConfig)
	return csrConfig, err
}
