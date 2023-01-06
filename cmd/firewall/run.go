package firewall

import (
	"github.com/spf13/cobra"
)

// getCmd represents the get command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run commands",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	firewallCmd.AddCommand(runCmd)
}
