package panorama

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	wildcard "path/filepath"
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
	user            string
	password        string
	firewallPattern []string
	tagPattern      []string
	notTagPattern   []string
	panorama        string
	terse           bool
	connected       string
	state           []string
	model           []string
	notModel        []string
)

// Create objects to colorize stdout
var (
	green *color.Color = color.New(color.FgGreen)
	red   *color.Color = color.New(color.FgRed)
)

type firewallSlice struct {
	Firewalls []fw `xml:"result>devices>entry"`
}

type fw struct {
	Name            string   `xml:"hostname"`
	Address         string   `xml:"ip-address"`
	Serial          string   `xml:"serial"`
	Connected       string   `xml:"connected"`
	Uptime          string   `xml:"uptime"`
	Model           string   `xml:"model"`
	SoftwareVersion string   `xml:"sw-version"`
	HaState         string   `xml:"ha>state"`
	MultiVsys       string   `xml:"multi-vsys"`
	VirtualSystems  []string `xml:"vsys>entry>display-name"`
}

type tagSlice struct {
	Firewalls []tag `xml:"result>mgt-config>devices>entry"`
}

type tag struct {
	SerialNumber string   `xml:"name,attr"`
	Tags         []string `xml:"vsys>entry>tags>member"`
}

var exists = struct{}{}

type set struct {
	m map[string]struct{}
}

func newSet() *set {
	s := &set{}
	s.m = make(map[string]struct{})
	return s
}

func (s *set) add(value string) {
	s.m[value] = exists
}

func (s *set) contains(value string) bool {
	_, c := s.m[value]
	return c
}

func (f *fw) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type FW fw // new type to prevent recursion
	firewall := FW{
		HaState: "standalone",
	}
	if err := d.DecodeElement(&firewall, &start); err != nil {
		return err
	}
	*f = (fw)(firewall)
	return nil
}

// getFirewallsCmd represents the getFirewalls command
var getFirewallsCmd = &cobra.Command{
	Use:   "firewalls",
	Short: "Get Panorama managed firewalls",
	Long: `Get Panorama managed firewalls

Examples:
  > panos-cli panorama get firewalls
  > panos-cli panorama get firewalls -u user
`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprintln(os.Stderr)
		if viper.GetString("user") == "" && user == "" {
			fmt.Fprint(os.Stderr, "PAN User: ")
			fmt.Scanln(&user)
		} else if user == "" {
			user = viper.GetString("user")
		}

		if viper.GetString("panorama") == "" && panorama == "" {
			fmt.Fprint(os.Stderr, "Panorama IP/Hostname: ")
			fmt.Scanln(&panorama)
		} else if panorama == "" {
			panorama = viper.GetString("panorama")
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

		fmt.Fprintf(os.Stderr, "Getting managed firewalls from %v ... ", panorama)
		resp := getFirewalls(userFlagSet)
		var managedFirewalls firewallSlice
		err := xml.Unmarshal([]byte(resp), &managedFirewalls)
		if err != nil {
			red.Fprintf(os.Stderr, "fail\n\n")
			panic(err)
		}
		green.Fprintf(os.Stderr, "success\n\n")

		sort.Slice(managedFirewalls.Firewalls, func(i, j int) bool {
			return managedFirewalls.Firewalls[i].Name < managedFirewalls.Firewalls[j].Name
		})

		// Print results
		switch {
		case terse:
			for _, fw := range managedFirewalls.Firewalls {
				if len(firewallPattern) > 0 {
					if !findFirewall(fw.Name, firewallPattern) {
						continue
					}
				}
				fmt.Printf("%v\n", strings.ToLower(fw.Name))
			}
		default:
			firewallTags := getFirewallTags(cmd.Flags().Changed("user"))

			headerFmt := color.New(color.FgBlue, color.Underline).SprintfFunc()
			columnFmt := color.New(color.FgHiYellow).SprintfFunc()
			tbl := table.New("Name", "Connected", "Mgmt IP", "Serial", "Uptime", "Model", "Version", "HA State", "Multi-Vsys", "Virtual Systems", "Tags")
			tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

			for _, fw := range managedFirewalls.Firewalls {
				switch {
				case len(firewallPattern) > 0 && !findFirewall(fw.Name, firewallPattern):
					continue
				case cmd.Flags().Changed("tag") && !findTag(firewallTags[fw.Serial], tagPattern):
					continue
				case cmd.Flags().Changed("not-tag") && findTag(firewallTags[fw.Serial], notTagPattern):
					continue
				case cmd.Flags().Changed("connected") && (connected != fw.Connected):
					continue
				case cmd.Flags().Changed("state") && !contains(state, fw.HaState):
					continue
				case cmd.Flags().Changed("model") && !modelContains(model, fw.Model):
					continue
				case cmd.Flags().Changed("not-model") && modelContains(notModel, fw.Model):
					continue
				default:
					tbl.AddRow(fw.Name, fw.Connected, fw.Address, fw.Serial, fw.Uptime, fw.Model, fw.SoftwareVersion, fw.HaState, fw.MultiVsys, strings.Join(fw.VirtualSystems, ", "), strings.Join(firewallTags[fw.Serial], ", "))
				}
			}

			tbl.Print()
		}

		// Print summary
		elapsed := time.Since(start)
		fmt.Printf(" \n\nCompleted in %.3f seconds\n", elapsed.Seconds())
	},
}

func init() {
	getCmd.AddCommand(getFirewallsCmd)

	getFirewallsCmd.Flags().StringVar(&user, "user", user, "PAN admin user")
	getFirewallsCmd.Flags().StringVar(&password, "password", password, "password for PAN user")
	getFirewallsCmd.Flags().StringVarP(&panorama, "panorama", "p", panorama, "Panorama IP/hostname")
	getFirewallsCmd.Flags().BoolVar(&terse, "terse", false, "return managed firewall names only")
	getFirewallsCmd.Flags().StringSliceVarP(&firewallPattern, "firewall", "f", []string{}, "return firewalls matching a comma separated set of name patterns (wildcards supported)")
	getFirewallsCmd.Flags().StringSliceVarP(&state, "state", "s", []string{}, "return firewalls matching a comma separated set of states: active, passive, suspended, standalone")
	getFirewallsCmd.Flags().StringSliceVar(&model, "model", []string{}, "return firewalls matching a comma separated set of models")
	getFirewallsCmd.Flags().StringSliceVar(&notModel, "not-model", []string{}, "return firewalls not matching a comma separated set of models")
	getFirewallsCmd.Flags().StringVarP(&connected, "connected", "c", "", "return firewalls matching connected state: yes, no")
	getFirewallsCmd.Flags().StringSliceVarP(&tagPattern, "tag", "t", []string{}, "return firewalls matching a comma separated set of tag patterns (wildcards supported)")
	getFirewallsCmd.Flags().StringSliceVar(&notTagPattern, "not-tag", []string{}, "return firewalls not matching a comma separated set of tag patterns (wildcards supported)")
}

func contains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[strings.ToLower(s)] = struct{}{}
	}

	_, ok := set[strings.ToLower(item)]
	return ok
}

func modelContains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[strings.TrimLeft(strings.ToLower(s), "pa-")] = struct{}{}
	}

	_, ok := set[strings.TrimLeft(strings.ToLower(item), "pa-")]
	return ok
}

func findFirewall(fw string, patterns []string) bool {
	for _, p := range patterns {
		if m, _ := wildcard.Match(strings.TrimSpace(strings.ToLower(p)), strings.ToLower(fw)); m {
			return true
		}
	}
	return false
}

func findTag(tags []string, patterns []string) bool {
	for _, t := range tags {
		for _, p := range patterns {
			if m, _ := wildcard.Match(strings.TrimSpace(strings.ToLower(p)), strings.ToLower(t)); m {
				return true
			}
		}
	}
	return false
}

func getFirewalls(userFlagSet bool) string {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	url := fmt.Sprintf("https://%s/api/", panorama)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		red.Fprintf(os.Stderr, "fail\n\n")
		panic(err)
	}

	q := req.URL.Query()
	q.Add("type", "op")
	q.Add("cmd", "<show><devices><all></all></devices></show>")
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
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		red.Fprintf(os.Stderr, "fail\n\n")
		log.Fatal(resp.Status)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		red.Fprintf(os.Stderr, "fail\n\n")
		panic(err)
	}

	return string(respBody)
}

func getFirewallTags(userFlagSet bool) map[string][]string {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	url := fmt.Sprintf("https://%s/api/", panorama)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		red.Fprintf(os.Stderr, "fail\n\n")
		panic(err)
	}

	q := req.URL.Query()
	q.Add("type", "config")
	q.Add("action", "get")
	q.Add("xpath", "/config/mgt-config")
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
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		red.Fprintf(os.Stderr, "fail\n\n")
		log.Fatal(resp.Status)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		red.Fprintf(os.Stderr, "fail\n\n")
		panic(err)
	}

	return parseTags(respBody)
}

func parseTags(c []byte) map[string][]string {
	var firewalls tagSlice
	err := xml.Unmarshal(c, &firewalls)
	if err != nil {
		red.Fprintf(os.Stderr, "unable to unmarshal xml\n")
	}

	tags := make(map[string][]string)
	for _, fw := range firewalls.Firewalls {
		// Remove duplicate tags
		unique := newSet()
		for _, tag := range fw.Tags {
			if unique.contains(tag) {
				continue
			} else {
				unique.add(tag)
				tags[fw.SerialNumber] = append(tags[fw.SerialNumber], tag)
			}
		}
	}

	return tags
}
