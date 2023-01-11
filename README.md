# panos-cli

![License](https://img.shields.io/github/license/dapacruz/panos-cli)
![Go Report](https://goreportcard.com/badge/github.com/Dapacruz/panos-cli)
![Downloads](https://img.shields.io/github/downloads/Dapacruz/panos-cli/total)

A lightweight utility, that utilizes the PAN-OS API, for working with Palo Alto Networks Panorama and firewalls.<br />

panos-cli is wrtten in Go, enabling you to download a dependency free binary for your platform.<br /><br />

- [Usage](#usage-guide)
  - [panos-cli panorama get firewalls](#panos-cli-panorama-get-firewalls)
  - [panos-cli firewall get interfaces](#panos-cli-firewall-get-interfaces)
  - [panos-cli firewall get pingable-hosts](#panos-cli-firewall-get-pingable-hosts)
  - [panos-cli firewall run commands](#panos-cli-firewall-run-commands-linux-and-macos-only)
  - [panos-cli global-protect get users](#panos-cli-global-protect-get-users)
- [Installation](#installation)
<br /><br />

## Usage Guide
### *panos-cli panorama get firewalls*
Print all firewalls managed by the Panorama appliance in the config file:
```sh
> panos-cli panorama get firewalls
```
Print all active/standalone firewalls managed by panorama.example.com:
```sh
> panos-cli panorama get firewalls --panorama panorama.example.com --state active,standalone
```

Print all connected firewalls where the firewall name contains "ca" or "ny":
```sh
> panos-cli panorama get firewalls --connected yes --firewall "*ca*","*ny*"
```

Print all firewall names to be piped to another command:
```sh
> panos-cli panorama get firewalls --terse
```
### *panos-cli firewall get interfaces*
Print all interfaces of 'fw01.example.com' and 'fw02.example.com':
```sh
> panos-cli firewall get interfaces fw01.example.com fw02.example.com
```

Print interfaces of firewalls returned from the 'panos-cli panorama get firewalls' command:
```sh
> panos-cli panorama get firewalls --terse | panos-cli firewall get interfaces
```

Print interfaces that have an IP address and the interface name begins with 'eth' or 'ae':
```sh
> panos-cli firewall get interfaces --has-ip --name "eth*","ae*" fw01.example.com
```
### *panos-cli firewall get pingable-hosts*

Print two pingable addresses behind each interface on fw01.example.com:
```sh
> panos-cli firewall get pingable-hosts fw01.example.com
```

Print four pingable addresses behind each interface on fw01.example.com and set the ICMP timeout to 1000ms:
```sh
> panos-cli firewall get pingable-hosts --timeout 1000 --num-addrs 4 fw01.example.com
```
### *panos-cli firewall run commands* (Linux and macOS only)
Execute the 'show system info' and 'show arp all' commands on fw01.example.com:
```sh
> panos-cli firewall run commands --command "show system info","show arp all" fw01.example.com
```

Execute the 'show system info' command on fw01.example.com and fw02.example.com, use key based auth, and ignore host key verification:
```sh
> panos-cli firewall run commands --command "show system info" --key-based-auth --insecure fw01.example.com fw02.example.com
```

Execute the 'show system info' command on all firewalls returned from the 'panos-cli panorama get firewalls' command:
```sh
> panos-cli panorama get firewalls --terse | panos-cli firewall run commands --command "show system info" --key-based-auth
```
### *panos-cli global-protect get users*
Print connected users on all gateways in the config file:
```sh
> panos-cli global-protect get users
```

Print connected users on specified gateways and include stats:
```sh
> panos-cli global-protect get users --stats --gateways gw01.example.com,gw02.example.com
```

Print connected users where the username contains 'doe':
```sh
> panos-cli global-protect get users --connected-user "*doe*"
```
<br />

## Installation

Download the latest binary from the [release page](https://github.com/Dapacruz/panos-cli/releases/latest) or install via `go install`.

Installing via `go install`:
1. Download and install Go (https://go.dev/dl/)
2. Execute `go install github.com/Dapacruz/panos-cli@latest`
