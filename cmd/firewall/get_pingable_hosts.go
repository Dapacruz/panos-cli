package firewall

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/go-ping/ping"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

var numAddresses int

type addressSlice struct {
	Addresses []address `xml:"result>entries>entry"`
}

type address struct {
	Name    string `xml:"interface"`
	Address string `xml:"ip"`
}

// getPingableHostsCmd represents the getPingableHosts command
var getPingableHostsCmd = &cobra.Command{
	Use:   "pingable-hosts [flags] <firewall>",
	Short: "Collects pingable IP addresses from a firewall ARP cache",
	Long: `Collects pingable IP addresses from a firewall ARP cache

Examples:
  # Print two pingable addresses behind each interface on fw01.example.com:

    > panos-cli firewall get pingable-hosts fw01.example.com

  # Print four pingable addresses behind each interface on fw01.example.com and set the ICMP timeout to 1000ms:

    > panos-cli firewall get pingable-hosts --timeout 1000 --num-addrs 4 fw01.example.com`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Println()

		var firewall string

		// Ensure the target firewall is defined, otherwise exit and display usage
		if len(args) != 1 {
			cmd.Help()
			log.Fatalf("\nno host specified\n\n")
		} else {
			firewall = args[0]
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
			fmt.Fprintf(os.Stderr, "\n\n")
		}

		start := time.Now()

		fmt.Printf("Downloading ARP cache from %v ... ", firewall)
		data, err := getArpCache(firewall, userFlagSet)
		if err != nil {
			red.Fprintf(os.Stderr, "fail\n\n")
			log.Fatalf("%v\n\n", err)
		}

		var arpCache addressSlice
		err = xml.Unmarshal([]byte(data), &arpCache)
		if err != nil {
			red.Fprintf(os.Stderr, "fail\n\n")
			log.Fatalf("%v\n\n", err)
		}
		green.Fprintf(os.Stderr, "success\n")

		fmt.Fprintf(os.Stderr, "Parsing ARP cache ... ")
		// Create a map of interfaces with a slice of addresses
		interfaces := make(map[string][]string)
		for _, int := range arpCache.Addresses {
			interfaces[int.Name] = append(interfaces[int.Name], int.Address)
		}
		green.Fprintf(os.Stderr, "success\n")

		fmt.Fprintf(os.Stderr, "Pinging IP addresses ... ")
		// Harvest pingable addresses from each interface
		var pingableHosts []string
		for _, addrs := range interfaces {
			pingableAddrs, err := getPingableAddresses(addrs)
			if err != nil {
				red.Fprintf(os.Stderr, "fail\n")
				log.Fatalf("%v\n\n", err)
			}
			pingableHosts = append(pingableHosts, pingableAddrs...)
		}
		green.Fprintf(os.Stderr, "success\n\n")

		// Sort the pingableHosts slice
		pingableHostsSorted := make([]net.IP, 0, len(pingableHosts))
		for _, ip := range pingableHosts {
			pingableHostsSorted = append(pingableHostsSorted, net.ParseIP(ip))
		}
		sort.Slice(pingableHostsSorted, func(i int, j int) bool {
			return bytes.Compare(pingableHostsSorted[i], pingableHostsSorted[j]) < 0
		})

		// Print results
		for _, addr := range pingableHostsSorted {
			fmt.Println(addr)
		}
		log.Println()

		// Print summary
		elapsed := time.Since(start)
		log.Printf(" Collection complete: Discovered %d pingable addresses in %.3f seconds\n", len(pingableHosts), elapsed.Seconds())
	},
}

func init() {
	getCmd.AddCommand(getPingableHostsCmd)

	getPingableHostsCmd.Flags().StringVar(&user, "user", user, "PAN admin user")
	getPingableHostsCmd.Flags().StringVar(&password, "password", password, "password for PAN user")
	getPingableHostsCmd.Flags().IntVarP(&numAddresses, "num-addrs", "n", 2, "number of addresses per interface")
	getPingableHostsCmd.Flags().IntVarP(&timeout, "timeout", "t", 250, "ICMP timeout in milliseconds")
}

func getPingableAddresses(addrs []string) ([]string, error) {
	var pingableAddrs []string

	for _, addr := range addrs {
		// If ip addr begins with 0 skip iteration
		if strings.HasPrefix(addr, "0") {
			continue
		}

		// Ping ip addr and add to pingableAddrs if a response is received
		stats, err := pingAddr(addr)
		if err != nil {
			return nil, err
		}

		if stats.PacketLoss == 0 {
			pingableAddrs = append(pingableAddrs, addr)
		}

		// skip remaining addrs if pingableAddrs is eqaul to numAddrs
		if len(pingableAddrs) == numAddresses {
			break
		}
	}

	return pingableAddrs, nil
}

func pingAddr(addr string) (*ping.Statistics, error) {
	// ping ip addr

	pinger, err := ping.NewPinger(addr)
	if err != nil {
		return nil, err
	}

	pinger.SetPrivileged(true)
	pinger.Timeout = time.Duration((time.Duration(timeout) * time.Millisecond))
	pinger.Count = 1

	err = pinger.Run()
	if err != nil {
		return nil, errors.New("\nICMP socket operations require 'sudo'")
	}

	stats := pinger.Statistics()

	return stats, nil
}

func getArpCache(fw string, userFlagSet bool) (string, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	url := fmt.Sprintf("https://%s/api/", fw)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	q := req.URL.Query()
	q.Add("type", "op")
	q.Add("cmd", "<show><arp><entry name = 'all'/></arp></show>")
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
		return "", err
	}
	if resp.StatusCode != 200 {
		red.Fprintf(os.Stderr, "fail\n\n")
		log.Fatal(resp.Status)
	}

	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(respBody), nil
}
