package globalProtect

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
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var wg sync.WaitGroup

type haState struct {
	Enabled string `xml:"result>enabled"`
	State   string `xml:"result>group>local-info>state"`
}

type gatewayUsers struct {
	Entries []*gatewayUser `xml:"result>entry"`
}

type gatewayUser struct {
	Username  string `xml:"username"`
	Domain    string `xml:"domain"`
	Computer  string `xml:"computer"`
	Client    string `xml:"client"`
	VirtualIP string `xml:"virtual-ip"`
	PublicIP  string `xml:"public-ip"`
	LoginTime string `xml:"login-time"`
	Gateway   string
}

// getUsersCmd represents the getUsers command
var getUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Get connected users from all gateways",
	Long: `Get connected users from all gateways

Examples:
  > panos-cli global-protect get-users
  > panos-cli global-protect get-users -u user
`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprintln(os.Stderr)
		if Config.User == "" {
			fmt.Fprint(os.Stderr, "PAN User: ")
			fmt.Scanln(Config.User)
		}

		// If the user flag is set, or the password and apikey are not set, prompt for password
		Config.UserFlagSet = cmd.Flags().Changed("user")
		if Config.UserFlagSet || (Config.Password == "" && Config.ApiKey == "") {
			fmt.Fprintf(os.Stderr, "Password (%s): ", Config.User)
			bytepw, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				panic(err)
			}
			Config.Password = string(bytepw)
			fmt.Fprintf(os.Stderr, "\n\n")
		}

		start := time.Now()

		// Get active users
		queue := make(chan gatewayUsers, 100)
		for _, gw := range Config.GlobalProtect.Gateways {
			wg.Add(1)
			go getActiveUsers(gw, Config.User, Config.Password, queue)
		}
		wg.Wait()
		close(queue)

		// Print active users
		userCount := map[string]int{}
		for users := range queue {
			for _, user := range users.Entries {
				fmt.Printf("%+v\n", *user)
				userCount[user.Gateway] += 1
				userCount["total"] += 1
			}
		}

		// Sort userCount slice
		keys := make([]string, 0, len(userCount))
		for key := range userCount {
			keys = append(keys, key)
		}

		sort.SliceStable(keys, func(i, j int) bool {
			return userCount[keys[i]] > userCount[keys[j]]
		})

		// Print statistics
		fmt.Fprintf(os.Stderr, "\nActive Users:\n\n")
		for _, k := range keys {
			if k == "total" {
				continue
			}
			fmt.Fprintf(os.Stderr, "%v: %v\n", k, userCount[k])
		}
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Total Active Users:", userCount["total"])

		// Print summary
		elapsed := time.Since(start)
		fmt.Fprintf(os.Stderr, "\n\n Completed in %.3f seconds\n", elapsed.Seconds())
	},
}

func init() {
	getCmd.AddCommand(getUsersCmd)

	getUsersCmd.Flags().StringVarP(&Config.User, "user", "u", Config.User, "PAN User")
	getUsersCmd.Flags().StringVarP(&Config.Password, "password", "p", Config.Password, "Password for PAN user")
}

func queryGateway(fw, user, pw string) gatewayUsers {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	url := fmt.Sprintf("https://%s/api/", fw)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(err)
	}

	q := req.URL.Query()
	q.Add("type", "op")
	q.Add("cmd", "<show><global-protect-gateway><current-user></current-user></global-protect-gateway></show>")
	if !Config.UserFlagSet && Config.ApiKey != "" {
		q.Add("key", Config.ApiKey)
	} else {
		creds := fmt.Sprintf("%s:%s", user, pw)
		credsEnc := base64.StdEncoding.EncodeToString([]byte(creds))
		req.Header.Set("Authorization", fmt.Sprintf("Basic %s", credsEnc))
	}

	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	if resp.StatusCode != 200 {
		log.Fatal(resp.Status)
	}

	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	var activeUsers gatewayUsers
	err = xml.Unmarshal([]byte(respBody), &activeUsers)
	if err != nil {
		panic(err)
	}

	for _, user := range activeUsers.Entries {
		user.Gateway = fw
	}

	return activeUsers
}

func gatewayActive(gw, user, pw string) bool {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	url := fmt.Sprintf("https://%s/api/", gw)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(err)
	}

	q := req.URL.Query()
	q.Add("type", "op")
	q.Add("cmd", "<show><high-availability><state></state></high-availability></show>")
	if !Config.UserFlagSet && Config.ApiKey != "" {
		q.Add("key", Config.ApiKey)
	} else {
		creds := fmt.Sprintf("%s:%s", user, pw)
		credsEnc := base64.StdEncoding.EncodeToString([]byte(creds))
		req.Header.Set("Authorization", fmt.Sprintf("Basic %s", credsEnc))
	}

	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	if resp.StatusCode != 200 {
		log.Fatal(resp.Status)
	}

	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	var haState haState
	err = xml.Unmarshal([]byte(respBody), &haState)
	if err != nil {
		panic(err)
	}

	if haState.Enabled == "no" || haState.State == "active" {
		return true
	}

	return false
}

func getActiveUsers(gw, user, pw string, queue chan<- gatewayUsers) {
	defer wg.Done()
	if gatewayActive(gw, user, pw) {
		queue <- queryGateway(gw, user, pw)
	}
}
