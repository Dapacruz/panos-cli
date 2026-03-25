# panos-cli

![License](https://img.shields.io/github/license/dapacruz/panos-cli)
![Go Report](https://goreportcard.com/badge/github.com/Dapacruz/panos-cli)
![Downloads](https://img.shields.io/github/downloads/Dapacruz/panos-cli/total)
![Version](https://img.shields.io/github/v/release/Dapacruz/panos-cli)

A lightweight, multithreaded CLI utility that uses the PAN-OS API to interact with Palo Alto Networks Panorama appliances and firewalls.

`panos-cli` is written in Go, providing a dependency-free binary for your platform. Commands can be piped together for powerful workflows across many devices simultaneously.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Authentication](#authentication)
- [Environment Variables](#environment-variables)
- [Usage Guide](#usage-guide)
  - [panos-cli config](#panos-cli-config)
  - [panos-cli panorama get firewalls](#panos-cli-panorama-get-firewalls)
  - [panos-cli firewall get interfaces](#panos-cli-firewall-get-interfaces)
  - [panos-cli firewall get pingable-hosts](#panos-cli-firewall-get-pingable-hosts)
  - [panos-cli firewall get object-limits](#panos-cli-firewall-get-object-limits)
  - [panos-cli firewall get config set](#panos-cli-firewall-get-config-set-linux-and-macos-only)
  - [panos-cli firewall get config xml](#panos-cli-firewall-get-config-xml)
  - [panos-cli firewall run commands](#panos-cli-firewall-run-commands-linux-and-macos-only)
  - [panos-cli global-protect get users](#panos-cli-global-protect-get-users)
- [Global Flags](#global-flags)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Features

- Query Panorama for all managed firewalls with rich filtering options
- Retrieve firewall interface details (IP, MAC, speed, zone, VLAN, etc.)
- Discover pingable hosts from a firewall's ARP cache
- Report on firewall object limit utilization
- Retrieve firewall configuration in set or XML format
- Execute CLI commands across multiple firewalls simultaneously via SSH
- Query GlobalProtect gateways for connected users
- Pipe commands together to operate on many devices at once
- Supports API key and username/password authentication

## Requirements

- **OS:** Linux, macOS, or Windows
  - `firewall get config set` and `firewall run commands` require **Linux or macOS** — these commands use the [Google Expect](https://github.com/google/goexpect) library for SSH session automation, which does not support Windows
  - `firewall get pingable-hosts` requires running with `sudo` (raw ICMP socket)
- **Network:** HTTPS (port 443) access to Panorama/firewall management interfaces; SSH (port 22) access for SSH-based commands
- **PAN-OS:** A user account with API access, or a generated API key

## Installation

### Download a Pre-built Binary

Download the latest binary for your platform from the [releases page](https://github.com/Dapacruz/panos-cli/releases/latest).

### Install via `go install`

1. Install Go from [https://go.dev/dl/](https://go.dev/dl/)
2. Run:
   ```sh
   go install github.com/Dapacruz/panos-cli@latest
   ```

### Build from Source

```sh
git clone https://github.com/Dapacruz/panos-cli.git
cd panos-cli
go build -o panos-cli .
```

## Configuration

On first run, `panos-cli` will detect that no configuration file exists and launch an interactive initialization wizard. It will prompt for:

- **API Key** — a PAN-OS API key (leave blank to use username/password authentication)
- **Default PAN User** — the default admin username
- **GlobalProtect Gateways** — comma-separated list of gateway hostnames/IPs
- **Panorama IP/Hostname** — the Panorama management address

The configuration file is saved to `~/.panos-cli.yml` with permissions set to `0600`.

### Configuration File Format

```yaml
apikey: "your-api-key-here"
user: "admin"
panorama: "panorama.example.com"
global-protect:
  gateways:
    - gw01.example.com
    - gw02.example.com
```

### Managing the Configuration

```sh
# Print the path to the config file
panos-cli config list

# Print the contents of the config file
panos-cli config show

# Open the config file in your default editor
panos-cli config edit
```

## Authentication

`panos-cli` supports two authentication methods, checked in the following priority order:

1. **API Key** (`apikey` in config or `PANOS_APIKEY` environment variable) — used automatically when reading hosts from stdin (pipe mode). This is the recommended method for automation.
2. **Username/Password** — if no API key is set, you will be prompted interactively. The `--user` and `--password` flags can be used to supply credentials non-interactively. Setting `--user` explicitly always prompts for a password (overriding any stored API key).

For SSH-based commands (`firewall run commands`, `firewall get config set`), key-based authentication is also supported via `--key-based-auth`. The tool reads `~/.ssh/id_rsa`. If the key is passphrase-protected, it will check `ssh-agent` first before prompting for the passphrase.

## Environment Variables

All configuration values can be overridden with environment variables using the `PANOS_` prefix. This is useful for CI/CD pipelines or scripting without modifying the config file.

| Environment Variable | Config Key | Description |
|---|---|---|
| `PANOS_APIKEY` | `apikey` | PAN-OS API key |
| `PANOS_USER` | `user` | Default PAN admin username |
| `PANOS_PASSWORD` | `password` | Password for PAN admin user |
| `PANOS_PANORAMA` | `panorama` | Panorama IP/hostname |

**Example:**
```sh
PANOS_APIKEY='your-api-key' panos-cli panorama get firewalls
```

## Usage Guide

### *panos-cli config*

Manage the `panos-cli` configuration file.

```sh
# Print the path to the config file
panos-cli config list

# Print the contents of the config file
panos-cli config show

# Open the config file in the default system editor
panos-cli config edit
```

---

### *panos-cli panorama get firewalls*

Query Panorama for managed firewalls. Supports extensive filtering. Use `--terse` to output just hostnames for piping to other commands.

```sh
# Print all firewalls managed by the Panorama appliance in the config file
panos-cli panorama get firewalls

# Print all active/standalone firewalls managed by a specific Panorama
panos-cli panorama get firewalls --panorama panorama.example.com --state active,standalone

# Print all connected firewalls where the name contains "ca" or "ny"
panos-cli panorama get firewalls --connected yes --firewall "*ca*","*ny*"

# Print firewalls running a specific PAN-OS version
panos-cli panorama get firewalls --version "10.2.*"

# Print firewalls matching a specific model
panos-cli panorama get firewalls --model "PA-3220","PA-3250"

# Print firewalls with a specific Panorama tag
panos-cli panorama get firewalls --tag "datacenter*"

# Print firewalls that do NOT have a specific tag
panos-cli panorama get firewalls --not-tag "decommissioned"

# Print firewall names only (for piping to other commands)
panos-cli panorama get firewalls --terse
```

**Flags:**

| Flag | Short | Description |
|---|---|---|
| `--panorama` | `-p` | Panorama IP/hostname (overrides config) |
| `--firewall` | `-f` | Filter by name patterns (wildcards, comma-separated) |
| `--connected` | `-c` | Filter by connected state: `yes` or `no` |
| `--state` | `-s` | Filter by HA state: `active`, `passive`, `suspended`, `standalone` |
| `--model` | | Filter by model (comma-separated) |
| `--not-model` | | Exclude by model (comma-separated) |
| `--tag` | `-t` | Filter by Panorama tag patterns (wildcards supported) |
| `--not-tag` | | Exclude by Panorama tag patterns (wildcards supported) |
| `--vsys` | `-v` | Filter by virtual system name patterns |
| `--not-vsys` | | Exclude by virtual system name patterns |
| `--version` | | Filter by PAN-OS version patterns (wildcards supported) |
| `--not-version` | | Exclude by PAN-OS version patterns |
| `--serial` | | Filter by serial number patterns |
| `--not-serial` | | Exclude by serial number patterns |
| `--terse` | | Print managed firewall names only |
| `--user` | | PAN admin user |
| `--password` | | Password for PAN admin user |

---

### *panos-cli firewall get interfaces*

Retrieve interface details from one or more firewalls. Outputs a table with name, IP, MTU, type, MAC, status, state, virtual system, VLAN, aggregate group, zone, management profile, and comment.

```sh
# Print all interfaces of fw01.example.com and fw02.example.com
panos-cli firewall get interfaces fw01.example.com fw02.example.com

# Print interfaces of firewalls returned from panorama (pipe mode requires API key)
panos-cli panorama get firewalls --terse | panos-cli firewall get interfaces

# Print interfaces with an IP address where the name begins with "eth" or "ae"
panos-cli firewall get interfaces --has-ip --name "eth*","ae*" fw01.example.com

# Print interfaces belonging to vsys1
panos-cli firewall get interfaces --vsys "vsys1" fw01.example.com

# Print interfaces that are members of an aggregate group
panos-cli firewall get interfaces --aggregate-group "ae1" fw01.example.com
```

**Flags:**

| Flag | Short | Description |
|---|---|---|
| `--name` | `-n` | Filter by interface name patterns (wildcards, comma-separated) |
| `--vsys` | `-v` | Filter by virtual system patterns (wildcards, comma-separated) |
| `--aggregate-group` | `-a` | Filter by aggregate group patterns (wildcards, comma-separated) |
| `--has-ip` | `-i` | Only show interfaces with an IP address |
| `--user` | | PAN admin user |
| `--password` | | Password for PAN admin user |

---

### *panos-cli firewall get pingable-hosts*

Downloads the ARP cache from a firewall and pings discovered hosts to find reachable addresses behind each interface. Useful for connectivity validation.

> **Note:** This command requires `sudo` due to raw ICMP socket operations.

```sh
# Print two pingable addresses per interface on fw01.example.com
sudo panos-cli firewall get pingable-hosts fw01.example.com

# Print four pingable addresses per interface and set the ICMP timeout to 1000ms
sudo panos-cli firewall get pingable-hosts --timeout 1000 --num-addrs 4 fw01.example.com
```

**Flags:**

| Flag | Short | Description |
|---|---|---|
| `--num-addrs` | `-n` | Number of addresses to find per interface (default: 2) |
| `--timeout` | `-t` | ICMP timeout in milliseconds (default: 250) |
| `--user` | | PAN admin user |
| `--password` | | Password for PAN admin user |

---

### *panos-cli firewall get object-limits*

Reports on address, service, and policy object counts vs. platform limits — useful for capacity planning.

```sh
# Print object limits of fw01.example.com and fw02.example.com
panos-cli firewall get object-limits fw01.example.com fw02.example.com

# Print object limits of all firewalls managed by Panorama
panos-cli panorama get firewalls --terse | panos-cli firewall get object-limits
```

Output columns include: Firewall, Object, Limit, Used, Remaining, Percent Used. Tracked objects: Address, Address Group, Service, Service Group, Security Policy, PBF Policy, NAT Policy, QoS Policy.

**Flags:**

| Flag | Description |
|---|---|
| `--user` | PAN admin user |
| `--password` | Password for PAN admin user |

---

### *panos-cli firewall get config set* (Linux and macOS only)

Retrieves the firewall configuration in set-format via SSH. Requires SSH access to the firewall management interface.

```sh
# Print set configuration of fw01.example.com and fw02.example.com
panos-cli firewall get config set fw01.example.com fw02.example.com

# Print set configuration of all Panorama-managed firewalls using key-based auth
panos-cli panorama get firewalls --terse | panos-cli firewall get config set --key-based-auth

# Filter output for lines containing "mgt-config"
panos-cli firewall get config set --filter "mgt-config" fw01.example.com
```

**Flags:**

| Flag | Short | Description |
|---|---|---|
| `--key-based-auth` | `-k` | Use SSH key-based authentication (`~/.ssh/id_rsa`) |
| `--insecure` | `-K` | Skip SSH host key verification |
| `--filter` | `-f` | Filter configuration output (grep-like) |
| `--port` | `-p` | SSH port (default: 22) |
| `--expect-timeout` | `-e` | Expect timeout per command in seconds (default: 30) |
| `--ssh-timeout` | `-S` | SSH connection timeout in seconds (default: 30) |
| `--password-stdin` | | Read password from standard input |
| `--user` | | PAN admin user |
| `--password` | | Password for PAN admin user |

---

### *panos-cli firewall get config xml*

Retrieves the firewall configuration in XML format via the PAN-OS API.

```sh
# Print running configuration of fw01.example.com and fw02.example.com
panos-cli firewall get config xml fw01.example.com fw02.example.com

# Print running configuration of all Panorama-managed firewalls (requires API key)
panos-cli panorama get firewalls --terse | panos-cli firewall get config xml

# Print running configuration at a specific XPath
panos-cli firewall get config xml --xpath "mgt-config" fw01.example.com

# Print effective running configuration at a specific XPath
panos-cli firewall get config xml --type "effective-running" --xpath "mgt-config" fw01.example.com

# Print the candidate configuration
panos-cli firewall get config xml --type "candidate" fw01.example.com
```

**Flags:**

| Flag | Short | Description |
|---|---|---|
| `--type` | `-t` | Configuration type to retrieve (default: `running`). Options: `candidate`, `effective-running`, `merged`, `pushed-shared-policy`, `pushed-template`, `running`, `synced`, `synced-diff` |
| `--xpath` | `-x` | XPath of the node to retrieve (only valid with `effective-running` and `running` types, default: `.`) |
| `--user` | | PAN admin user |
| `--password` | | Password for PAN admin user |

---

### *panos-cli firewall run commands* (Linux and macOS only)

Executes one or more CLI commands across multiple firewalls concurrently via SSH.

```sh
# Execute 'show system info' and 'show arp all' on fw01.example.com
panos-cli firewall run commands --command "show system info","show arp all" fw01.example.com

# Execute a command on multiple firewalls using key-based auth, ignoring host key verification
panos-cli firewall run commands --command "show system info" --key-based-auth --insecure fw01.example.com fw02.example.com

# Execute a command on all Panorama-managed firewalls
panos-cli panorama get firewalls --terse | panos-cli firewall run commands --command "show system info" --key-based-auth

# Sort command output and increase timeouts for slow devices
panos-cli firewall run commands --command "show routing route" --sort-output --expect-timeout 60 fw01.example.com
```

**Flags:**

| Flag | Short | Description |
|---|---|---|
| `--command` | `-c` | Comma-separated list of CLI commands to execute |
| `--key-based-auth` | `-k` | Use SSH key-based authentication (`~/.ssh/id_rsa`) |
| `--insecure` | `-K` | Skip SSH host key verification |
| `--sort-output` | `-s` | Sort command output |
| `--port` | `-p` | SSH port (default: 22) |
| `--expect-timeout` | `-e` | Expect timeout per command in seconds (default: 30) |
| `--ssh-timeout` | `-S` | SSH connection timeout in seconds (default: 30) |
| `--password-stdin` | | Read password from standard input |
| `--user` | | PAN admin user |
| `--password` | | Password for PAN admin user |

---

### *panos-cli global-protect get users*

Queries GlobalProtect gateways for connected users. Automatically skips passive HA members and queries only active gateways.

```sh
# Print connected users on all gateways in the config file
panos-cli global-protect get users

# Print connected users on specific gateways with statistics
panos-cli global-protect get users --stats --gateways gw01.example.com,gw02.example.com

# Find a specific connected user (wildcards supported)
panos-cli global-protect get users --connected-user "*doe*"
```

**Flags:**

| Flag | Short | Description |
|---|---|---|
| `--gateways` | `-g` | Comma-separated list of GlobalProtect gateway IPs/hostnames |
| `--connected-user` | `-c` | Find a connected user by username pattern (wildcards supported) |
| `--stats` | `-s` | Show connected user count statistics per gateway |
| `--user` | | PAN admin user |
| `--password` | | Password for PAN admin user |

## Global Flags

These flags are available on all commands:

| Flag | Description |
|---|---|
| `--no-config` | Bypass the configuration file entirely (credentials must be supplied via flags or environment variables) |
| `--version` | Print the version of panos-cli |
| `--help` | Print help for any command |

## Troubleshooting

**`firewall get pingable-hosts` fails with an ICMP socket error**

This command uses raw ICMP sockets, which require elevated privileges. Run with `sudo`:
```sh
sudo panos-cli firewall get pingable-hosts fw01.example.com
```

**`firewall run commands` or `firewall get config set` fails with a host key error**

The SSH client checks `~/.ssh/known_hosts` by default. Either add the host key first:
```sh
ssh-keyscan fw01.example.com >> ~/.ssh/known_hosts
```
Or bypass host key checking (not recommended in production):
```sh
panos-cli firewall run commands --insecure --command "show system info" fw01.example.com
```

**`firewall get interfaces` or `firewall get object-limits` fails with "api key based auth is required when reading hosts from stdin"**

When piping hostnames from `panorama get firewalls`, the tool cannot prompt for credentials interactively. Add an API key to your config file:
```sh
panos-cli config edit
```
Then set the `apikey` field to your PAN-OS API key.

**Key-based SSH authentication fails with "passphrase protected"**

If your `~/.ssh/id_rsa` is passphrase-protected, `panos-cli` will check `ssh-agent` first. Add your key to the agent:
```sh
ssh-add ~/.ssh/id_rsa
```

**Config file not found / initialization fails**

If you need to re-initialize the config, delete `~/.panos-cli.yml` and run any command to trigger the wizard again. You can also create or edit the file manually — see [Configuration](#configuration) for the expected format.

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes
4. Push to your fork and open a pull request

Please open an issue first for significant changes to discuss the approach.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
