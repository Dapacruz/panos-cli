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
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	user     string
	password string
	panorama string
	terse    bool
)

// Create objects to colorize stdout
var (
	green *color.Color = color.New(color.FgGreen)
	red   *color.Color = color.New(color.FgRed)
)

type firewallSlice struct {
	Firewalls []firewall `xml:"result>devices>entry"`
}

type firewall struct {
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
		if Config.User == "" && user == "" {
			fmt.Fprint(os.Stderr, "PAN User: ")
			fmt.Scanln(&user)
		} else if user == "" {
			user = Config.User
		}

		if Config.Panorama == "" && panorama == "" {
			fmt.Fprint(os.Stderr, "Panorama IP/Hostname: ")
			fmt.Scanln(&panorama)
		} else if panorama == "" {
			panorama = Config.Panorama
		}

		// If the user flag is set, or the password and apikey are not set, prompt for password
		userFlagSet := cmd.Flags().Changed("user")
		if userFlagSet || (Config.ApiKey == "" && password == "") {
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
		for _, fw := range managedFirewalls.Firewalls {
			if fw.HaState == "" {
				fw.HaState = "standalone"
			}
			switch {
			case terse:
				fmt.Printf("%v\n", strings.ToLower(fw.Name))
			default:
				fmt.Printf("%+v\n", fw)
			}
		}

		// Print summary
		elapsed := time.Since(start)
		fmt.Printf(" \n\nCompleted in %.3f seconds\n", elapsed.Seconds())
	},
}

func init() {
	getCmd.AddCommand(getFirewallsCmd)

	getFirewallsCmd.Flags().StringVarP(&user, "user", "u", user, "PAN admin user")
	getFirewallsCmd.Flags().StringVar(&password, "password", password, "password for PAN user")
	getFirewallsCmd.Flags().StringVarP(&panorama, "panorama", "p", panorama, "Panorama IP/hostname")
	getFirewallsCmd.Flags().BoolVarP(&terse, "terse", "t", false, "list managed firewall names only")
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
	if !userFlagSet && Config.ApiKey != "" {
		q.Add("key", Config.ApiKey)
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
