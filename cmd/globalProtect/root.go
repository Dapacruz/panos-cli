package globalProtect

import (
	"github.com/Dapacruz/panos-cli/cmd"
	"github.com/spf13/cobra"
)

// globalProtectCmd represents the globalProtect command
var globalProtectCmd = &cobra.Command{
	Use:   "global-protect",
	Short: "A set of commands for working with GlobalProtect",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	cmd.RootCmd.AddCommand(globalProtectCmd)
}
