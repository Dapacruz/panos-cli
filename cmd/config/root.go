package config

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/Dapacruz/panos-cli/cmd"
	"github.com/skratchdot/open-golang/open"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "A set of commands for working with the config",
	Long:  `A set of commands for working with the config`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "Print config file path",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("\n%v\n", viper.GetViper().ConfigFileUsed())
	},
}

// showCmd represents the show command
var showCmd = &cobra.Command{
	Use:   "show",
	Short: "Print config file",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		log.Println()

		file, err := os.Open(viper.ConfigFileUsed())
		if err != nil {
			log.Fatalf("%v\n\n", err)
		}
		defer file.Close()

		b, err := io.ReadAll(file)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("\n%v\n", string(b))
	},
}

// editCmd represents the edit command
var editCmd = &cobra.Command{
	Use:   "edit",
	Short: "Open config file in default editor",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		err := open.Run(viper.ConfigFileUsed())
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	cmd.RootCmd.AddCommand(configCmd)
	configCmd.AddCommand(listCmd)
	configCmd.AddCommand(showCmd)
	configCmd.AddCommand(editCmd)
}
