package cmd

import (
	"github.com/okunix/ambicert/config"
	"github.com/okunix/ambicert/service"
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
		keyOutputs, err := certConfig.Key.GetOutputs()
		if err != nil {
			return err
		}
		keyService := service.NewKeyService()
		privatekey, err := keyService.CreateAndPublish(ctx, keyGenParams, keyOutputs...)
		if err != nil {
			return err
		}

		// Generating csr
		csrGenParams, err := certConfig.CSR.NewCsrGeneratorParams()
		if err != nil {
			return err
		}
		csrOutputs, err := certConfig.CSR.GetOutputs()
		if err != nil {
			return err
		}
		csrService := service.NewCsrService()
		_, err = csrService.CreateAndPublish(ctx, privatekey, csrGenParams, csrOutputs...)
		return err
	},
}

func init() {
	rootCmd.AddCommand(csrCmd)
}
