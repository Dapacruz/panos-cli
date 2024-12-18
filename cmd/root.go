package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/exp/slices"
)

var noConfig bool

const (
	VERSION           string = "0.11.5"
	VIPER_CONFIG_NAME string = ".panos-cli"
	VIPER_CONFIG_PATH string = "$HOME"
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:     "panos-cli",
	Version: VERSION,
	Short:   "A utility for working with Palo Alto Networks Panorama and firewalls",
	Long:    "",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the RootCmd.
func Execute() {
	err := RootCmd.Execute()
	if err != nil {
		panic(err)
	}
}

func init() {
	RootCmd.PersistentFlags().BoolVar(&noConfig, "no-config", false, "bypass the configuration file")

	RootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		log.SetFlags(0)
	}

	// Bypass the config file if the --no-config flag is set
	if slices.Contains(os.Args, "--no-config") {
		return
	}

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

	// Get the API key from stdin
	var panorama string
	fmt.Fprint(os.Stderr, "Panorama IP/Hostname: ")
	fmt.Scanln(&panorama)
	// Add to the config
	viper.Set("panorama", panorama)

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

	// Set the permissions on the config file
	os.Chmod(viper.ConfigFileUsed(), 0600)

	fmt.Printf("\n\nInitialization complete.\n\n")
	fmt.Printf("Configuration file saved to %v.\n\n", viper.ConfigFileUsed())

	os.Exit(0)
}
