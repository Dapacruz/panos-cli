package globalProtect

import (
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
	"sort"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/rodaine/table"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

var (
	wg            sync.WaitGroup
	gateways      []string
	user          string
	password      string
	connectedUser string
	stats         bool
)

type haState struct {
	Enabled string `xml:"result>enabled"`
	State   string `xml:"result>group>local-info>state"`
}

type userSlice struct {
	Gateway string
	Users   []*conUser `xml:"result>entry"`
	Error   string
}

type conUser struct {
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
	Use:   "users [flags] <gateway> [gateway]...",
	Short: "Get connected users",
	Long: `Get connected users

Examples:
  # Print connected users on all gateways in the config file:

    > panos-cli global-protect get users

  # Print connected users on specified gateways and include stats:

    > panos-cli global-protect get users --stats --gateways gw01.example.com,gw02.example.com

  # Print connected users where the username contains 'doe':

    > panos-cli global-protect get users --connected-user "*doe*"`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Println()

		// If no gateways are set by flag or config file, exit
		cGateways := viper.GetStringMapStringSlice("global-protect")["gateways"]
		if len(gateways) == 0 && (len(cGateways) == 0 || (len(cGateways) == 1 && cGateways[0] == "")) {
			cmd.Help()
			log.Fatalf("\nNo GlobalProtect Gateways found in config file %v. Update config file or use the --gateways flag.\n\n", viper.ConfigFileUsed())
		} else if len(gateways) == 0 {
			gateways = cGateways
		}

		// If the apikey and user is not set, prompt for user
		apikey := viper.GetString("apikey")
		cUser := viper.GetString("user")
		if apikey == "" && user == "" && cUser == "" {
			fmt.Fprint(os.Stderr, "PAN User: ")
			fmt.Scanln(&user)
		} else if user == "" {
			user = cUser
		}

		// If the user flag is set, or the password and apikey are not set, prompt for password
		userFlagSet := cmd.Flags().Changed("user")
		if userFlagSet || (viper.GetString("apikey") == "" && password == "") {
			tty, err := os.Open("/dev/tty")
			if err != nil {
				log.Fatal(err, "error allocating terminal")
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
		ch := make(chan userSlice, 100)
		doneCh := make(chan struct{})

		userCount := map[string]int{}
		connectedUserFlagSet := cmd.Flags().Changed("connected-user")
		go printResults(ch, &errorBuffer, doneCh, userCount, connectedUserFlagSet)

		log.Printf("Getting connected users ...\n\n")

		// Get connected users
		for _, gw := range gateways {
			wg.Add(1)
			go getConnectedUsers(gw, apikey, ch, userFlagSet)
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
			fmt.Fprintf(os.Stderr, "\nConnected Users per gateway:\n\n")
			for _, k := range keys {
				if k == "total" {
					continue
				}
				log.Printf("%v: %v\n", k, userCount[k])
			}
			log.Println("\nTotal Connected Users:", userCount["total"])
		}

		// Print errors
		if errorBuffer.String() != "" {
			log.Printf("\n%s\n", errorBuffer.String())
		}

		// Print summary
		elapsed := time.Since(start)
		log.Printf("\n\n Completed in %.3f seconds\n", elapsed.Seconds())
	},
}

func init() {
	getCmd.AddCommand(getUsersCmd)

	getUsersCmd.Flags().StringVar(&user, "user", user, "PAN admin user")
	getUsersCmd.Flags().StringVar(&password, "password", password, "password for PAN user")
	getUsersCmd.Flags().StringSliceVarP(&gateways, "gateways", "g", gateways, "GlobalProtect gateways (comma separated)")
	getUsersCmd.Flags().StringVarP(&connectedUser, "connected-user", "c", connectedUser, "find connected user (wildcards supported)")
	getUsersCmd.Flags().BoolVarP(&stats, "stats", "s", false, "show connected user statistics")
}

func printResults(ch <-chan userSlice, error *bytes.Buffer, done chan<- struct{}, userCount map[string]int, connectedUserFlagSet bool) {
	// Print connected users
	headerFmt := color.New(color.FgBlue, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgHiYellow).SprintfFunc()

	tbl := table.New("Username", "Domain", "Computer", "Client", "Virtual IP", "Public IP", "Login Time", "Gateway")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

	var connectedUsers []*conUser
	for users := range ch {
		if users.Error != "" {
			error.WriteString(users.Error)
		} else {
			for _, user := range users.Users {
				// Print user
				if connectedUserFlagSet {
					if m, _ := wildcard.Match(connectedUser, user.Username); m {
						connectedUsers = append(connectedUsers, user)
					}
				} else {
					connectedUsers = append(connectedUsers, user)
				}
				userCount[user.Gateway] += 1
				userCount["total"] += 1
			}
		}

		sort.Slice(connectedUsers, func(i, j int) bool {
			return connectedUsers[i].Username < connectedUsers[j].Username
		})

		for _, user := range connectedUsers {
			tbl.AddRow(user.Username, user.Domain, user.Computer, user.Client, user.VirtualIP, user.PublicIP, user.LoginTime, user.Gateway)
		}
	}

	tbl.Print()

	done <- struct{}{}
}

func queryGateway(gw, apikey string, userFlagSet bool) userSlice {
	var connectedUsers userSlice

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	url := fmt.Sprintf("https://%s/api/", gw)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		connectedUsers.Error = fmt.Sprintf("%s: %v\n\n", gw, err)
		return connectedUsers
	}

	q := req.URL.Query()
	q.Add("type", "op")
	q.Add("cmd", "<show><global-protect-gateway><current-user></current-user></global-protect-gateway></show>")
	if !userFlagSet && apikey != "" {
		q.Add("key", apikey)
	} else {
		creds := fmt.Sprintf("%s:%s", user, password)
		credsEnc := base64.StdEncoding.EncodeToString([]byte(creds))
		req.Header.Set("Authorization", fmt.Sprintf("Basic %s", credsEnc))
	}

	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		connectedUsers.Error = fmt.Sprintf("%s: %v\n\n", gw, err)
		return connectedUsers
	}
	if resp.StatusCode != 200 {
		log.Fatal(resp.Status)
	}

	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		connectedUsers.Error = fmt.Sprintf("%s: %v\n\n", gw, err)
		return connectedUsers
	}

	err = xml.Unmarshal([]byte(respBody), &connectedUsers)
	if err != nil {
		connectedUsers.Error = fmt.Sprintf("%s: %v\n\n", gw, err)
		return connectedUsers
	}

	for _, user := range connectedUsers.Users {
		user.Gateway = gw
	}

	return connectedUsers
}

func gatewayActive(gw, apikey string, userFlagSet bool) (bool, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	url := fmt.Sprintf("https://%s/api/", gw)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}

	q := req.URL.Query()
	q.Add("type", "op")
	q.Add("cmd", "<show><high-availability><state></state></high-availability></show>")
	if !userFlagSet && apikey != "" {
		q.Add("key", apikey)
	} else {
		creds := fmt.Sprintf("%s:%s", user, password)
		credsEnc := base64.StdEncoding.EncodeToString([]byte(creds))
		req.Header.Set("Authorization", fmt.Sprintf("Basic %s", credsEnc))
	}

	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	if resp.StatusCode != 200 {
		log.Fatal(resp.Status)
	}

	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	var haState haState
	err = xml.Unmarshal([]byte(respBody), &haState)
	if err != nil {
		return false, err
	}

	if haState.Enabled == "no" || haState.State == "active" {
		return true, nil
	}

	return false, nil
}

func getConnectedUsers(gw, apikey string, ch chan<- userSlice, userFlagSet bool) {
	defer wg.Done()

	if active, err := gatewayActive(gw, apikey, userFlagSet); err != nil {
		ch <- userSlice{
			Gateway: gw,
			Error:   err.Error(),
		}
	} else if active {
		ch <- queryGateway(gw, apikey, userFlagSet)
	}
}
