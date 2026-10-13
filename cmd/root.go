package cmd

import "github.com/spf13/cobra"

var rootCmd = &cobra.Command{
	Use:           "ambicert",
	Short:         "PKI utility",
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() error {
	return rootCmd.Execute()
}
