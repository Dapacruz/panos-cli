package firewall

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	wildcard "path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/rodaine/table"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

var (
	namePattern  []string
	vsysPattern  []string
	aePattern    []string
	hasIpAddress bool
)

type interfaceSlice struct {
	Firewall        string
	Network         []*interfaceNetwork  `xml:"result>ifnet>entry"`
	Hardware        []*interfaceHardware `xml:"result>hw>entry"`
	EthernetConfig  []*interfaceConfig   `xml:"result>config>devices>entry>network>interface>ethernet>entry"`
	AggregateConfig []*interfaceConfig   `xml:"result>config>devices>entry>network>interface>aggregate-ethernet>entry"`
	LoopbackConfig  []*interfaceConfig   `xml:"result>config>devices>entry>network>interface>loopback>units>entry"`
	TunnelConfig    []*interfaceConfig   `xml:"result>config>devices>entry>network>interface>tunnel>units>entry"`
	Error           string
}

type interfaceNetwork struct {
	Name          string `xml:"name"`
	IP            string `xml:"ip"`
	Type          string `xml:"fwd"`
	VirtualSystem string `xml:"vsys"`
	VLAN          string `xml:"tag"`
	Zone          string `xml:"zone"`
}

type interfaceHardware struct {
	Name   string `xml:"name"`
	Duplex string `xml:"duplex"`
	MAC    string `xml:"mac"`
	Mode   string `xml:"mode"`
	Speed  string `xml:"speed"`
	State  string `xml:"state"`
	Status string `xml:"st"`
}

type interfaceConfig struct {
	Name              string             `xml:"name,attr"`
	Comment           string             `xml:"comment"`
	MTU               string             `xml:"layer3>mtu"`
	AggregateGroup    string             `xml:"aggregate-group"`
	MgmtProfile       string             `xml:"interface-management-profile"`
	IP                []*ipAddresses     `xml:"ip>entry"`
	Layer3IP          []*ipAddresses     `xml:"layer3>ip>entry"`
	SubInterfaces     []*interfaceConfig `xml:"layer3>units>entry"`
	Layer3MgmtProfile string             `xml:"layer3>interface-management-profile"`
}

type ipAddresses struct {
	IP string `xml:"name,attr"`
}

type firewallInterface struct {
	Firewall       string
	Name           string
	IP             string
	MTU            string
	MAC            string
	Mode           string
	Speed          string
	Duplex         string
	Status         string
	State          string
	ID             string
	Type           string
	VLAN           string
	AggregateGroup string
	Zone           string
	VirtualSystem  string
	Comment        string
	MgmtProfile    string
}

// getInterfacesCmd represents the getInterfaces command
var getInterfacesCmd = &cobra.Command{
	Use:   "interfaces [flags] <firewall> [firewall]...",
	Short: "Get firewall interfaces",
	Long: `Get firewall interfaces

Examples:
  # Print all interfaces of 'fw01.example.com' and 'fw02.example.com':

    > panos-cli firewall get interfaces fw01.example.com fw02.example.com

  # Print interfaces of firewalls returned from the 'panos-cli panorama get firewalls' command:

    > panos-cli panorama get firewalls --terse | panos-cli firewall get interfaces

  # Print interfaces that have an IP address and the interface name begins with 'eth' or 'ae':

    > panos-cli firewall get interfaces --has-ip --name "eth*","ae*" fw01.example.com`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Println()

		// Ensure at least one host is specified
		hosts = cmd.Flags().Args()
		if len(hosts) == 0 {
			if isInputFromPipe() {
				if viper.GetString("apikey") == "" {
					log.Fatalf("api key based auth is required when reading hosts from stdin, execute `panos-cli config edit` to add an api key\n\n")
				}

				// Read hosts from stdin
				scanner := bufio.NewScanner(bufio.NewReader(os.Stdin))
				for scanner.Scan() {
					hosts = append(hosts, scanner.Text())
				}
			} else {
				cmd.Help()
				log.Fatalf("\nno hosts specified\n\n")
			}
		}

		// If the user flag is not set or the user is not set, prompt for user
		if viper.GetString("user") == "" && user == "" {
			fmt.Fprint(os.Stderr, "PAN User: ")
			fmt.Scanln(&user)
		} else if user == "" {
			user = viper.GetString("user")
		}

		// If the user flag is set, or the password and apikey are not set, prompt for password
		userFlagSet := cmd.Flags().Changed("user")
		if userFlagSet || (viper.GetString("apikey") == "" && password == "") {
			tty, err := os.Open("/dev/tty")
			if err != nil {
				log.Fatalf("error allocating terminal: %v\n\n", err)
			}
			fd := int(tty.Fd())
			fmt.Fprintf(os.Stderr, "Password (%s): ", user)
			bytepw, err := term.ReadPassword(int(fd))
			if err != nil {
				log.Fatalf("%v\n\n", err)
			}
			tty.Close()
			password = string(bytepw)
			log.Printf("\n\n")
		}

		start := time.Now()

		var errorBuffer bytes.Buffer
		ch := make(chan interfaceSlice, 10)
		doneCh := make(chan struct{})

		go printInterfaces(ch, &errorBuffer, doneCh, cmd)

		wg.Add(len(hosts))
		for _, fw := range hosts {
			go getInterfaces(ch, fw, userFlagSet)
		}
		wg.Wait()
		close(ch)
		<-doneCh

		log.Println()

		// Print errors
		if errorBuffer.String() != "" {
			red.Fprintf(os.Stderr, "%s", errorBuffer.String())
		}

		// Print summary
		elapsed := time.Since(start)
		log.Printf("\n Completed in %.3f seconds\n", elapsed.Seconds())
	},
}

func init() {
	getCmd.AddCommand(getInterfacesCmd)

	getInterfacesCmd.Flags().StringVar(&user, "user", user, "PAN admin user")
	getInterfacesCmd.Flags().StringVar(&password, "password", password, "password for PAN user")
	getInterfacesCmd.Flags().StringSliceVarP(&namePattern, "name", "n", []string{}, "print interfaces matching a comma separated set of name patterns (wildcards supported)")
	getInterfacesCmd.Flags().StringSliceVarP(&vsysPattern, "vsys", "v", []string{}, "print interfaces matching a comma separated set of vsys patterns (wildcards supported)")
	getInterfacesCmd.Flags().StringSliceVarP(&aePattern, "aggregate-group", "a", []string{}, "print interfaces matching a comma separated set of aggregate-group patterns (wildcards supported)")
	getInterfacesCmd.Flags().BoolVarP(&hasIpAddress, "has-ip", "i", false, "print interfaces with an IP address")
}

func getInterfaces(ch chan<- interfaceSlice, fw string, userFlagSet bool) {
	defer wg.Done()

	interfaces := interfaceSlice{Firewall: fw}
	defer func() {
		ch <- interfaces
	}()

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	url := fmt.Sprintf("https://%s/api/", fw)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		interfaces.Error = fmt.Sprintf("%s: %v\n\n", fw, err)
		return
	}

	// Get interface operational data
	q := req.URL.Query()
	q.Add("type", "op")
	q.Add("cmd", "<show><interface>all</interface></show>")
	if !userFlagSet && viper.GetString("apikey") != "" {
		q.Add("key", viper.GetString("apikey"))
	} else {
		creds := fmt.Sprintf("%s:%s", user, password)
		credsEnc := base64.StdEncoding.EncodeToString([]byte(creds))
		req.Header.Set("Authorization", fmt.Sprintf("Basic %s", credsEnc))
	}

	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		interfaces.Error = fmt.Sprintf("%s: %v\n\n", fw, err)
		return
	}
	if resp.StatusCode != 200 {
		red.Fprintf(os.Stderr, "fail\n\n")
		log.Fatalf("%s (%s)", resp.Status, fw)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		interfaces.Error = fmt.Sprintf("%s: %v\n\n", fw, err)
		return
	}

	resp.Body.Close()

	err = xml.Unmarshal(respBody, &interfaces)
	if err != nil {
		interfaces.Error = fmt.Sprintf("%s: %v\n\n", fw, err)
		return
	}

	// Get interface configuration data
	q = req.URL.Query()
	q.Add("type", "op")
	q.Add("cmd", "<show><config><merged></merged></config></show>")
	if !userFlagSet && viper.GetString("apikey") != "" {
		q.Add("key", viper.GetString("apikey"))
	} else {
		creds := fmt.Sprintf("%s:%s", user, password)
		credsEnc := base64.StdEncoding.EncodeToString([]byte(creds))
		req.Header.Set("Authorization", fmt.Sprintf("Basic %s", credsEnc))
	}

	req.URL.RawQuery = q.Encode()

	resp, err = client.Do(req)
	if err != nil {
		interfaces.Error = fmt.Sprintf("%s: %v\n\n", fw, err)
		return
	}
	if resp.StatusCode != 200 {
		interfaces.Error = fmt.Sprintf("%s: response status code: %s\n\n", fw, resp.Status)
		return
	}

	respBody, err = io.ReadAll(resp.Body)
	if err != nil {
		interfaces.Error = fmt.Sprintf("%s: %v\n\n", fw, err)
		return
	}

	resp.Body.Close()

	err = xml.Unmarshal(respBody, &interfaces)
	if err != nil {
		interfaces.Error = fmt.Sprintf("%s: %v\n\n", fw, err)
		return
	}
}

func printInterfaces(ch <-chan interfaceSlice, error *bytes.Buffer, done chan<- struct{}, cmd *cobra.Command) {
	// Print interfaces
	headerFmt := color.New(color.FgBlue, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgHiYellow).SprintfFunc()

	tbl := table.New("Firewall", "Name", "IP", "MTU", "Type", "MAC", "Status", "State", "Virtual System", "VLAN", "Aggregate Group", "Zone", "Management Profile", "Comment")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

	for fw := range ch {
		if fw.Error != "" {
			error.WriteString(fw.Error)
		} else {

			// Parse interface hardware data
			ints := map[string]*firewallInterface{}
			for _, i := range fw.Hardware {
				ints[i.Name] = &firewallInterface{
					Firewall: fw.Firewall,
					Name:     i.Name,
					MAC:      i.MAC,
					Speed:    i.Speed,
					Duplex:   i.Duplex,
					Status:   i.Status,
					Mode:     i.Mode,
					State:    i.State,
				}
			}

			// Interface network data
			for _, i := range fw.Network {
				i.VirtualSystem = fmt.Sprintf("vsys%s", i.VirtualSystem)
				if i.VLAN == "0" {
					i.VLAN = ""
				}
				if _, ok := ints[i.Name]; !ok {
					ints[i.Name] = &firewallInterface{}
				}
				ints[i.Name].Firewall = fw.Firewall
				ints[i.Name].Name = i.Name
				ints[i.Name].Type = i.Type
				ints[i.Name].VirtualSystem = i.VirtualSystem
				ints[i.Name].VLAN = i.VLAN
				ints[i.Name].Zone = i.Zone
			}

			// Parse interface configuration data
			var configs []*interfaceConfig
			configs = append(configs, fw.EthernetConfig...)
			configs = append(configs, fw.AggregateConfig...)
			configs = append(configs, fw.LoopbackConfig...)
			configs = append(configs, fw.TunnelConfig...)
			for _, i := range configs {
				if _, ok := ints[i.Name]; !ok {
					ints[i.Name] = &firewallInterface{}
				}
				ints[i.Name].Comment = i.Comment
				ints[i.Name].AggregateGroup = i.AggregateGroup
				ints[i.Name].MTU = i.MTU
				if i.MgmtProfile != "" {
					ints[i.Name].MgmtProfile = i.MgmtProfile
				} else {
					ints[i.Name].MgmtProfile = i.Layer3MgmtProfile
				}

				// Parse IP addresses from merged local/Panorama configurations
				addresses := []string{}
				var addrs []*ipAddresses
				addrs = append(addrs, i.IP...)
				addrs = append(addrs, i.Layer3IP...)
				for _, addr := range addrs {
					addresses = append(addresses, addr.IP)
				}
				ints[i.Name].IP = strings.Join(addresses, "\n")

				// Parse sub interfaces
				for _, si := range i.SubInterfaces {
					if _, ok := ints[si.Name]; !ok {
						ints[si.Name] = &firewallInterface{}
					}
					ints[si.Name].Comment = si.Comment
					if si.MgmtProfile != "" {
						ints[si.Name].MgmtProfile = si.MgmtProfile
					} else {
						ints[si.Name].MgmtProfile = si.Layer3MgmtProfile
					}
					addresses := []string{}
					var addrs []*ipAddresses
					addrs = append(addrs, si.IP...)
					addrs = append(addrs, si.Layer3IP...)
					for _, addr := range addrs {
						addresses = append(addresses, addr.IP)
					}
					ints[si.Name].IP = strings.Join(addresses, "\n")
				}
			}

			// Sort interfaces by name
			var keys []string
			for k := range ints {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			// TODO: Sort interface numbers correctly
			//sort.SliceStable(keys, func(i, j int) bool {
			//iSplit := strings.Split(keys[i], ".")
			//jSplit := strings.Split(keys[j], ".")
			//if len(iSplit) < 2 {
			//return true
			//}
			//if len(jSplit) < 2 {
			//return true
			//}
			//return iSplit[1] < jSplit[1]
			//})

			// Match one or more IP addresses, with or without slash notation
			r := regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{2})?(, \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{2})?)?$`)
			for _, k := range keys {
				switch {
				case cmd.Flags().Changed("name") && !match(namePattern, "", ints[k].Name, "/", ""):
					continue
				case cmd.Flags().Changed("vsys") && !match(vsysPattern, "", ints[k].VirtualSystem):
					continue
				case cmd.Flags().Changed("aggregate-group") && !match(aePattern, "", ints[k].AggregateGroup) && !match(aePattern, "", ints[k].Name):
					continue
				case hasIpAddress && !r.MatchString(ints[k].IP):
					continue
				}
				tbl.AddRow(ints[k].Firewall, ints[k].Name, ints[k].IP, ints[k].MTU, ints[k].Type, ints[k].MAC, ints[k].Status, ints[k].State, ints[k].VirtualSystem, ints[k].VLAN, ints[k].AggregateGroup, ints[k].Zone, ints[k].MgmtProfile, ints[k].Comment)
			}
		}
	}

	tbl.Print()

	done <- struct{}{}
}

func match(patns []string, trim string, item ...string) bool {
	for _, i := range item {
		for _, p := range patns {
			// Trim, lowercase, and replace all / with empty string
			p = strings.ReplaceAll(strings.Trim(strings.TrimSpace(strings.ToLower(p)), trim), "/", "")
			i = strings.ReplaceAll(strings.Trim(strings.ToLower(i), trim), "/", "")
			if m, _ := wildcard.Match(p, i); m {
				return true
			}
		}
	}
	return false
}
