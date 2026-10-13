package cmd

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/okunix/ambicert/csr"
	"github.com/okunix/ambicert/keyutil"
	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v4"
)

type Config struct {
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

func newDefaultConfig() Config {
	return Config{
		Key: keyutil.NewDefaultKeyConfig(),
	}
}

var csrCmd = &cobra.Command{
	Use:   "csr [-c PATH|--csrout PATH] [--key PATH|-k PATH|--keyout PATH] config.yaml",
	Short: "generate CSR based on config",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error

		configFile := args[0]

		csrout, _ := cmd.Flags().GetString("csrout")
		keyout, _ := cmd.Flags().GetString("keyout")
		privatekeyfile, _ := cmd.Flags().GetString("key")

		file, err := os.Open(configFile)
		if err != nil {
			return fmt.Errorf("failed to open file %s", configFile)
		}

		csrConfig := newDefaultConfig()
		if err := yaml.NewDecoder(file).Decode(&csrConfig); err != nil {
			return err
		}

		keyfile := csrConfig.PrivateKeyFile
		if privatekeyfile != "" {
			keyfile = privatekeyfile
		}

		var key crypto.PrivateKey

		if keyfile != "" {
			keyPEM, err := os.ReadFile(keyfile)
			if err != nil {
				return err
			}
			block, _ := pem.Decode(keyPEM)
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return err
			}
		} else {
			_, key, err = csrConfig.Key.New()
			if err != nil {
				return err
			}
			keydest := csrConfig.KeyFile
			if keyout != "" {
				keydest = keyout
			}
			keywriter := os.Stdout
			if keydest != "-" && keydest != "" {
				keywriter, err = os.OpenFile(keydest, os.O_WRONLY|os.O_CREATE, 0o600)
				if err != nil {
					return err
				}
			}
			keyder, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				return err
			}
			err = pem.Encode(keywriter, &pem.Block{Type: "PRIVATE KEY", Bytes: keyder})
			if err != nil {
				return err
			}
		}

		csr, err := csrConfig.Template.New(key)
		if err != nil {
			fmt.Println("error creating csr")
			return err
		}

		csrfile := csrConfig.OutputFile
		if csrout != "" {
			csrfile = csrout
		}

		csrdest := os.Stdout
		if csrfile != "" {
			csrdest, err = os.OpenFile(csrfile, os.O_WRONLY|os.O_CREATE, 0o644)
			if err != nil {
				return err
			}
		}

		err = pem.Encode(csrdest, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	csrCmd.Flags().StringP("csrout", "c", "", "CSR destination path")
	csrCmd.Flags().StringP("keyout", "k", "", "Key destination path")
	csrCmd.Flags().String("key", "", "Provide your own private key")

	rootCmd.AddCommand(csrCmd)
}
