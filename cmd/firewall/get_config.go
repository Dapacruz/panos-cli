package firewall

import (
	"github.com/spf13/cobra"
)

// getCmd represents the get command
var getConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Get firewall configuration",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	getCmd.AddCommand(getConfigCmd)
}
