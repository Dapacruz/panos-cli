package firewall

import (
	"github.com/Dapacruz/panos-cli/cmd"
	"github.com/spf13/cobra"
)

var Config = &cmd.Config

// firewallCmd represents the firewall command
var firewallCmd = &cobra.Command{
	Use:   "firewall",
	Short: "A set of commands for working with firewalls",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	cmd.RootCmd.AddCommand(firewallCmd)
}
