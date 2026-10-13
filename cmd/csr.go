package cmd

import (
	"os"

	"github.com/okunix/ambicert/config"
	"github.com/okunix/ambicert/pemutil"
	"github.com/spf13/cobra"
)

// TODO: Add check if destination file is present and ask confirmation for overwrite. Also add --force flag to overwrite file without confirmation.

var csrCmd = &cobra.Command{
	Use:   "csr [-c PATH|--csrout PATH] [--key PATH|-k PATH|--keyout PATH] config.yaml",
	Short: "generate CSR based on config",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Retriving config file path
		configFile := args[0]

		// Parsing csr config file
		csrConfig, err := config.ReadCsrConfigFile(configFile)
		if err != nil {
			return err
		}

		// Parsing flags
		csrout, _ := cmd.Flags().GetString("csrout")
		if csrout == "" {
			csrout = csrConfig.OutputFile
		}

		// Setting key destination file
		keyout, _ := cmd.Flags().GetString("keyout")
		if keyout == "" {
			keyout = csrConfig.KeyFile
		}

		// Creating new private key based on config
		_, key, err := csrConfig.Key.New()
		if err != nil {
			return err
		}

		// Deciding where to put generated key
		keydest := os.Stdout
		if keyout != "-" && keyout != "" {
			keydest, err = os.OpenFile(keyout, os.O_WRONLY|os.O_CREATE, 0o600)
			if err != nil {
				return err
			}
		}

		// Writing key to the destination file encoded in pem format
		if err := pemutil.EncodePrivateKey(keydest, key); err != nil {
			return err
		}

		// Generating csr
		csr, err := csrConfig.Template.New(key)
		if err != nil {
			return err
		}

		// Deciding where to put generated csr
		csrdest := os.Stdout
		if csrout != "" && csrout != "-" {
			csrdest, err = os.OpenFile(csrout, os.O_WRONLY|os.O_CREATE, 0o644)
			if err != nil {
				return err
			}
		}

		// Writing csr
		return pemutil.Encode(csrdest, "CERTIFICATE REQUEST", csr)
	},
}

func init() {
	csrCmd.Flags().StringP("csrout", "c", "", "CSR destination path")
	csrCmd.Flags().StringP("keyout", "k", "", "Key destination path")

	rootCmd.AddCommand(csrCmd)
}
