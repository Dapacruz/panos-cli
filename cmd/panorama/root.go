package panorama

import (
	"github.com/Dapacruz/panos-cli/cmd"
	"github.com/spf13/cobra"
)

var Config = &cmd.Config

// panoramaCmd represents the panorama command
var panoramaCmd = &cobra.Command{
	Use:   "panorama",
	Short: "A set of commands for working with Panorama",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	cmd.RootCmd.AddCommand(panoramaCmd)
}
