package main

import (
	"github.com/Dapacruz/panos-cli/cmd"
	_ "github.com/Dapacruz/panos-cli/cmd/firewall"
	_ "github.com/Dapacruz/panos-cli/cmd/globalProtect"
)

func main() {
	cmd.Execute()
}
