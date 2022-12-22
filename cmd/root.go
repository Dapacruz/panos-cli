package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	VIPER_CONFIG_NAME string = ".panos-cli"
	VIPER_CONFIG_PATH string = "$HOME"
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

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:     "panos-cli",
	Version: "0.1.2",
	Short:   "A utility for working with Palo Alto Networks Panorama and firewalls",
	Long:    "",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the RootCmd.
func Execute() {
	err := RootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	viper.SetConfigName(VIPER_CONFIG_NAME)
	viper.SetConfigType("yml")
	viper.AddConfigPath(VIPER_CONFIG_PATH)
	// viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found
			initalizeConfig()
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

func initalizeConfig() {
	fmt.Printf("Initializing configuration file...\n\n")

	// Initialize the default config
	var baseConfig = `
apikey: ""
user: ""
global-protect:
  gateways: []
`
	err := viper.ReadConfig(bytes.NewBuffer([]byte(baseConfig)))
	if err != nil {
		panic(fmt.Errorf("fatal error config file: %w", err))
	}

	// Get the API key from stdin
	var apikey string
	fmt.Fprint(os.Stderr, "API Key: ")
	fmt.Scanln(&apikey)
	// Add to the config
	viper.Set("apikey", apikey)

	// Get the default user from stdin
	var user string
	fmt.Fprint(os.Stderr, "Default PAN User: ")
	fmt.Scanln(&user)
	// Add to the config
	viper.Set("user", user)

	// Get the IP/hostname of all GlobalProtect gateways from stdin
	fmt.Printf("Enter IP/Hostname of all GlobalProtect gateways (comma separated): ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	// Convert the comma separated string to a space separated string
	gatewayInput := strings.ReplaceAll(scanner.Text(), ",", " ")
	// Split the string into a slice
	gateways := strings.Fields(gatewayInput)
	// Remove empty string if it exists
	if gateways[0] == "" {
		gateways = []string{}
	}
	// Add to the config
	viper.Set("global-protect.gateways", gateways)

	// Save the new config file
	err = viper.SafeWriteConfig()
	if err != nil {
		panic(fmt.Errorf("unable to write config file, %v", err))
	}

	// Read in the new config file
	err = viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("fatal error config file: %w", err))
	}

	// Populate the conrfig struct with the contents of the new config file
	err = viper.Unmarshal(&Config)
	if err != nil {
		panic(fmt.Errorf("unable to decode into struct, %v", err))
	}

	fmt.Printf("\n\nInitialization complete.\n\n")
	fmt.Printf("Configuration file saved to %v\n\n", viper.ConfigFileUsed())

	os.Exit(0)
}
