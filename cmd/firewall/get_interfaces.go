package firewall

// TODO: Handle interfaces that have more than one IP address

import (
	"bufio"
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
	"syscall"
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
	hasIpAddress bool
)

type interfaceSlice struct {
	Firewall string
	Network  []*interfaceNetwork  `xml:"result>ifnet>entry"`
	Hardware []*interfaceHardware `xml:"result>hw>entry"`
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

type firewallInterface struct {
	Firewall      string
	Name          string
	IP            string
	MAC           string
	Mode          string
	Speed         string
	Duplex        string
	Status        string
	State         string
	ID            string
	Type          string
	VLAN          string
	Zone          string
	VirtualSystem string
}

// getInterfacesCmd represents the getInterfaces command
var getInterfacesCmd = &cobra.Command{
	Use:   "interfaces [flags] <firewall> [<firewall> ...]",
	Short: "Gets firewall interfaces",
	Long: `Gets firewall interfaces

Examples:
  > panos-cli firewall get interfaces
  > panos-cli firewall get interfaces  -u user`,
	Run: func(cmd *cobra.Command, args []string) {
		// Ensure at least one host is specified
		hosts = cmd.Flags().Args()
		if len(hosts) == 0 {
			if isInputFromPipe() {
				if viper.GetString("apikey") == "" {
					log.Fatal("api key based auth is required when reading hosts from stdin, execute `panos-cli config edit` to add an api key")
				}

				// Read hosts from stdin
				scanner := bufio.NewScanner(bufio.NewReader(os.Stdin))
				for scanner.Scan() {
					hosts = append(hosts, scanner.Text())
				}
			} else {
				cmd.Help()
				fmt.Printf("\nno hosts specified\n")
				os.Exit(1)
			}
		}

		// If the user flag is not set or the user is not set, prompt for user
		fmt.Fprintln(os.Stderr)
		if viper.GetString("user") == "" && user == "" {
			fmt.Fprint(os.Stderr, "PAN User: ")
			fmt.Scanln(&user)
		} else if user == "" {
			user = viper.GetString("user")
		}

		// If the user flag is set, or the password and apikey are not set, prompt for password
		userFlagSet := cmd.Flags().Changed("user")
		if userFlagSet || (viper.GetString("apikey") == "" && password == "") {
			fmt.Fprintf(os.Stderr, "Password (%s): ", user)
			bytepw, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				panic(err)
			}
			password = string(bytepw)
			fmt.Fprintf(os.Stderr, "\n\n")
		}

		start := time.Now()

		ch := make(chan interfaceSlice, 10)
		doneCh := make(chan struct{})

		go printInterfaces(ch, doneCh, cmd)

		wg.Add(len(hosts))
		for _, fw := range hosts {
			go getInterfaces(ch, fw, userFlagSet)
		}
		wg.Wait()
		close(ch)
		<-doneCh
		fmt.Fprintln(os.Stderr)

		// Print summary
		elapsed := time.Since(start)
		fmt.Fprintf(os.Stderr, " Completed in %.3f seconds\n", elapsed.Seconds())
	},
}

func init() {
	getCmd.AddCommand(getInterfacesCmd)

	getInterfacesCmd.Flags().StringVar(&user, "user", user, "PAN admin user")
	getInterfacesCmd.Flags().StringVar(&password, "password", password, "password for PAN user")
	getInterfacesCmd.Flags().StringSliceVarP(&namePattern, "name", "n", []string{}, "return interfaces matching a comma separated set of name patterns (wildcards supported)")
	getInterfacesCmd.Flags().StringSliceVarP(&vsysPattern, "vsys", "v", []string{}, "return interfaces matching a comma separated set of vsys patterns (wildcards supported)")
	getInterfacesCmd.Flags().BoolVarP(&hasIpAddress, "has-ip", "i", false, "return interfaces with an IP address")
}

func getInterfaces(ch chan<- interfaceSlice, fw string, userFlagSet bool) {
	defer wg.Done()

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	url := fmt.Sprintf("https://%s/api/", fw)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		red.Fprintf(os.Stderr, "fail\n\n")
		panic(err)
	}

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
		red.Fprintf(os.Stderr, "fail\n\n")
		panic(err)
	}
	if resp.StatusCode != 200 {
		red.Fprintf(os.Stderr, "fail\n\n")
		log.Fatal(resp.Status)
	}

	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		red.Fprintf(os.Stderr, "fail\n\n")
		panic(err)
	}

	interfaces := interfaceSlice{Firewall: fw}
	err = xml.Unmarshal(respBody, &interfaces)
	if err != nil {
		panic(err)
	}

	ch <- interfaces
}

func printInterfaces(ch <-chan interfaceSlice, doneCh chan<- struct{}, cmd *cobra.Command) {
	// Print connected users
	headerFmt := color.New(color.FgBlue, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgHiYellow).SprintfFunc()

	tbl := table.New("Firewall", "Name", "IP", "Type", "MAC", "Speed", "Duplex", "Status", "Mode", "State", "Virtual System", "VLAN", "Zone")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

	for fw := range ch {
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
			ints[i.Name].IP = i.IP
			ints[i.Name].Type = i.Type
			ints[i.Name].VirtualSystem = i.VirtualSystem
			ints[i.Name].VLAN = i.VLAN
			ints[i.Name].Zone = i.Zone
		}

		// Sort interfaces by name
		var keys []string
		for k := range ints {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		r := regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{2})?$`)
		for _, k := range keys {
			switch {
			case cmd.Flags().Changed("name") && !match(namePattern, "", ints[k].Name, "/", ""):
				continue
			case cmd.Flags().Changed("vsys") && !match(vsysPattern, "", ints[k].VirtualSystem):
				continue
			case hasIpAddress && !r.MatchString(ints[k].IP):
				continue
			}
			tbl.AddRow(ints[k].Firewall, ints[k].Name, ints[k].IP, ints[k].Type, ints[k].MAC, ints[k].Speed, ints[k].Duplex, ints[k].Status, ints[k].Mode, ints[k].State, ints[k].VirtualSystem, ints[k].VLAN, ints[k].Zone)
		}
	}

	tbl.Print()

	doneCh <- struct{}{}
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
