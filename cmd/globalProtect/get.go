package globalProtect

import (
	"github.com/spf13/cobra"
)

// globalProtectCmd represents the globalProtect command
var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Get GlobalProtect information",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	globalProtectCmd.AddCommand(getCmd)
}
