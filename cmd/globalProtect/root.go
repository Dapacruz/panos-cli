package globalProtect

import (
	"github.com/Dapacruz/panos-cli/cmd"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// Create objects to colorize stdout
var (
	blue   *color.Color = color.New(color.FgBlue)
	green  *color.Color = color.New(color.FgGreen)
	red    *color.Color = color.New(color.FgRed)
	yellow *color.Color = color.New(color.FgHiYellow)
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
