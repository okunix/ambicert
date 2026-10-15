package cmd

import (
	"fmt"

	"github.com/okunix/ambicert/version"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:           "ambicert",
	Short:         "PKI utility",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		versionFlag, _ := cmd.Flags().GetBool("version")
		if versionFlag {
			fmt.Println(version.Version())
			return nil
		}
		return cmd.Help()
	},
}

func Execute() error {
	rootCmd.Flags().BoolP("version", "v", false, "show version")
	return rootCmd.Execute()
}
