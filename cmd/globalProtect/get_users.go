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
	wildcard "path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/rodaine/table"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

var (
	wg         sync.WaitGroup
	gateways   []string
	user       string
	password   string
	activeUser string
	stats      bool
)

type haState struct {
	Enabled string `xml:"result>enabled"`
	State   string `xml:"result>group>local-info>state"`
}

type userSlice struct {
	Users []*connectedUser `xml:"result>entry"`
}

type connectedUser struct {
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
	Short: "Get active users from all gateways",
	Long: `Get active users from all gateways

Examples:
  > panos-cli global-protect get users
  > panos-cli global-protect get users -u user
`,
	Run: func(cmd *cobra.Command, args []string) {
		// If no gateways are set by flag or config file, exit
		if len(gateways) == 0 && len(Config.GlobalProtect.Gateways) == 0 {
			cmd.Help()
			fmt.Fprintf(os.Stderr, "\n\nNo GlobalProtect Gateways found in config file %v. Update config file or use the --gateways flag.\n", viper.ConfigFileUsed())
			os.Exit(1)
		} else if len(gateways) == 0 {
			gateways = Config.GlobalProtect.Gateways
		}

		// If the apikey and user is not set, prompt for user
		fmt.Fprintln(os.Stderr)
		if Config.ApiKey == "" && Config.User == "" && user == "" {
			fmt.Fprint(os.Stderr, "PAN User: ")
			fmt.Scanln(&user)
		} else if user == "" {
			user = Config.User
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

		ch := make(chan userSlice, 100)
		doneCh := make(chan struct{})

		userCount := map[string]int{}
		activeUserFlagSet := cmd.Flags().Changed("active-user")
		go printResults(ch, doneCh, userCount, activeUserFlagSet)

		fmt.Fprintf(os.Stderr, "Getting active users...\n\n")

		// Get active users
		for _, gw := range gateways {
			wg.Add(1)
			go getActiveUsers(gw, ch, userFlagSet)
		}
		wg.Wait()
		close(ch)
		<-doneCh

		// Sort userCount slice
		keys := make([]string, 0, len(userCount))
		for key := range userCount {
			keys = append(keys, key)
		}

		sort.SliceStable(keys, func(i, j int) bool {
			return userCount[keys[i]] > userCount[keys[j]]
		})

		// Print statistics
		if stats {
			fmt.Printf("\nActive Users:\n\n")
			for _, k := range keys {
				if k == "total" {
					continue
				}
				fmt.Printf("%v: %v\n", k, userCount[k])
			}
			fmt.Println()
			fmt.Println("Total Active Users:", userCount["total"])
		}

		// Print summary
		elapsed := time.Since(start)
		fmt.Printf("\n\n Completed in %.3f seconds\n", elapsed.Seconds())
	},
}

func init() {
	getCmd.AddCommand(getUsersCmd)

	getUsersCmd.Flags().StringVarP(&user, "user", "u", user, "PAN admin user")
	getUsersCmd.Flags().StringVar(&password, "password", password, "password for PAN user")
	getUsersCmd.Flags().StringSliceVarP(&gateways, "gateways", "g", gateways, "GlobalProtect gateways (comma separated)")
	getUsersCmd.Flags().StringVarP(&activeUser, "active-user", "a", activeUser, "find active user (wildcards supported)")
	getUsersCmd.Flags().BoolVarP(&stats, "stats", "s", false, "print active user statistics")
}

func printResults(ch <-chan userSlice, doneCh chan<- struct{}, userCount map[string]int, activeUserFlagSet bool) {
	// Print active users
	headerFmt := color.New(color.FgBlue, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgHiYellow).SprintfFunc()

	tbl := table.New("Username", "Domain", "Computer", "Client", "Virtual IP", "Public IP", "Login Time", "Gateway")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

	for users := range ch {
		for _, user := range users.Users {
			// Print user
			if activeUserFlagSet {
				if m, _ := wildcard.Match(activeUser, user.Username); m {
					tbl.AddRow(user.Username, user.Domain, user.Computer, user.Client, user.VirtualIP, user.PublicIP, user.LoginTime, user.Gateway)
				}
			} else {
				tbl.AddRow(user.Username, user.Domain, user.Computer, user.Client, user.VirtualIP, user.PublicIP, user.LoginTime, user.Gateway)
			}
			userCount[user.Gateway] += 1
			userCount["total"] += 1
		}
	}

	tbl.Print()

	doneCh <- struct{}{}
}

func queryGateway(gw string, userFlagSet bool) userSlice {
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
	q.Add("cmd", "<show><global-protect-gateway><current-user></current-user></global-protect-gateway></show>")
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

	var activeUsers userSlice
	err = xml.Unmarshal([]byte(respBody), &activeUsers)
	if err != nil {
		panic(err)
	}

	for _, user := range activeUsers.Users {
		user.Gateway = gw
	}

	return activeUsers
}

func gatewayActive(gw string, userFlagSet bool) bool {
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

func getActiveUsers(gw string, queue chan<- userSlice, userFlagSet bool) {
	defer wg.Done()
	if gatewayActive(gw, userFlagSet) {
		queue <- queryGateway(gw, userFlagSet)
	}
}
