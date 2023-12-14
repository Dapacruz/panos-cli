package firewall

import (
	"os"
	"sync"

	"github.com/Dapacruz/panos-cli/cmd"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	user          string
	password      string
	timeout       int
	expectTimeout int
	sshTimeout    int
	hosts         []string
	wg            sync.WaitGroup
)

// Create objects to colorize stdout
var (
	blue   *color.Color = color.New(color.FgBlue)
	green  *color.Color = color.New(color.FgGreen)
	red    *color.Color = color.New(color.FgRed)
	yellow *color.Color = color.New(color.FgHiYellow)
)

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

func isInputFromPipe() bool {
	fileInfo, _ := os.Stdin.Stat()
	return fileInfo.Mode()&os.ModeCharDevice == 0
}
