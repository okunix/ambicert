package cmd

import (
	"github.com/okunix/ambicert/config"
	"github.com/okunix/ambicert/csr"
	"github.com/okunix/ambicert/keyutil"
	"github.com/spf13/cobra"
)

// TODO: Add check if destination file is present and ask confirmation for overwrite. Also add --force flag to overwrite file without confirmation.

var csrCmd = &cobra.Command{
	Use:   "csr config.yaml",
	Short: "generate CSR based on config",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Retriving config file path
		configFile := args[0]

		// Parsing csr config file
		certConfig, err := config.ReadCertConfigFile(configFile)
		if err != nil {
			return err
		}

		// Creating new key generator based on config
		keygen := keyutil.NewKeyGenerator(certConfig.Key)
		privatekey, err := keygen.Populate()
		if err != nil {
			return err
		}

		// Generating csr
		csrgen := csr.NewCsrGenerator(certConfig.CSR)
		return csrgen.Populate(privatekey)
	},
}

func init() {
	rootCmd.AddCommand(csrCmd)
}
