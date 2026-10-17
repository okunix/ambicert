package cmd

import (
	"github.com/okunix/ambicert/config"
	"github.com/okunix/ambicert/csr"
	"github.com/okunix/ambicert/keyutil"
	"github.com/okunix/ambicert/storage"
	"github.com/spf13/cobra"
)

// TODO: Add check if destination file is present and ask confirmation for overwrite. Also add --force flag to overwrite file without confirmation.

var csrCmd = &cobra.Command{
	Use:   "csr config.yaml",
	Short: "generate CSR based on config",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Getting command context
		ctx := cmd.Context()

		// Retriving config file path
		configFile := args[0]

		// Parsing csr config file
		certConfig, err := config.ReadCertConfigFile(configFile)
		if err != nil {
			return err
		}

		// Generating private key
		keyGenParams, err := certConfig.Key.NewKeyGeneratorParams()
		if err != nil {
			return err
		}
		keygen := keyutil.NewKeyGenerator(keyGenParams)
		_, privatekey, err := keygen.NewKeyPair()
		if err != nil {
			return err
		}

		// Generating csr
		csrGenParams, err := certConfig.CSR.NewCsrGeneratorParams()
		if err != nil {
			return err
		}
		csrgen := csr.NewCsrGenerator(csrGenParams)
		generatedCsr, err := csrgen.New(privatekey)
		if err != nil {
			return err
		}

		// Saving csr and key to storage
		csrOutputs, err := certConfig.CSR.GetOutputs()
		if err != nil {
			return err
		}
		keyOutputs, err := certConfig.Key.GetOutputs()
		if err != nil {
			return err
		}

		err = storage.PublishPrivateKey(ctx, privatekey, keyOutputs...)
		if err != nil {
			return err
		}
		return storage.PublishCertificateRequest(ctx, generatedCsr, csrOutputs...)
	},
}

func init() {
	rootCmd.AddCommand(csrCmd)
}
