package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	ViperConfigName string = ".panos-cli"
	ViperConfigPath string = "$HOME"
)

var Config config

type config struct {
	ApiKey        string `mapstructure:"apikey"`
	User          string `mapstructure:"user"`
	Password      string
	UserFlagSet   bool
	GlobalProtect struct {
		Gateways []string `mapstructure:"gateways"`
	} `mapstructure:"global-protect"`
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "panos-cli",
	Short: "A utility for working with Palo Alto Networks Panorama and firewalls",
	Long:  "",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	viper.SetConfigName(ViperConfigName)
	viper.AddConfigPath(ViperConfigPath)
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error
		} else {
			panic(fmt.Errorf("fatal error config file: %w", err))
		}
	} else {
		err := viper.Unmarshal(&Config)
		if err != nil {
			panic(fmt.Errorf("unable to decode into struct, %v", err))
		}
	}
}
