package firewall

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
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/exp/slices"
	"golang.org/x/term"
)

var (
	xpath      string
	configType string
)

type innerXML struct {
	InnerXML string `xml:",innerxml"`
}

type configuration struct {
	Host   string
	Config innerXML `xml:"result"`
}

// getConfigXmlCmd represents the 'config xml' command
var getConfigXmlCmd = &cobra.Command{
	Use:   "xml [flags] <firewall> [firewall]...",
	Short: "Get firewall XML formatted config",
	Long: `Get firewall XML formatted config

Examples:
  # Print running configuration of 'fw01.example.com' and 'fw02.example.com':

    > panos-cli firewall get config xml fw01.example.com fw02.example.com

  # Print running configuration of firewalls returned from the 'panos-cli panorama get firewalls' command:

    > panos-cli panorama get firewalls --terse | panos-cli firewall get config xml

  # Print running configuration at specified XPath:

    > panos-cli firewall get config xml --xpath 'mgt-config' fw01.example.com

  # Print effective running configuration at specified XPath:

    > panos-cli firewall get config xml --type 'effective-running' --xpath 'mgt-config' fw01.example.com

  # Print running and candidate configuration differences:

    > panos-cli firewall get config xml --type 'diff' fw01.example.com`,
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

		if !slices.Contains([]string{"candidate", "diff", "effective-running", "merged", "pushed-shared-policy", "pushed-template", "running", "synced", "synced-diff"}, configType) {
			cmd.Help()
			fmt.Printf("\ninvalid configuration type\n")
			os.Exit(1)
		}

		if !slices.Contains([]string{"effective-running", "running"}, configType) && xpath != "." {
			cmd.Help()
			fmt.Printf("\nxpath should only be used with configuration types 'effective-running' and 'running'\n")
			os.Exit(1)
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

		ch := make(chan configuration, 10)
		doneCh := make(chan struct{})

		go printConfigXml(ch, doneCh)

		wg.Add(len(hosts))
		for _, fw := range hosts {
			go getConfigXml(ch, fw, userFlagSet, xpath)
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
	getConfigCmd.AddCommand(getConfigXmlCmd)

	getConfigXmlCmd.Flags().StringVarP(&xpath, "xpath", "x", ".", "xpath of the node to retrieve (for use with configuration types 'effective-running' and 'running')")
	getConfigXmlCmd.Flags().StringVarP(&configType, "type", "t", "running", "type of configuration to retrieve (candidate, diff, effective-running, merged, pushed-shared-policy, pushed-template, running, synced, synced-diff)")
}

func getConfigXml(ch chan<- configuration, fw string, userFlagSet bool, xpath string) {
	defer wg.Done()

	var cmd string
	if slices.Contains([]string{"effective-running", "running"}, configType) {
		cmd = fmt.Sprintf("<show><config><%s><xpath>%s</xpath></%s></config></show>", configType, xpath, configType)
	} else {
		cmd = fmt.Sprintf("<show><config><%s></%s></config></show>", configType, configType)
	}

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

	// Get configuration
	q := req.URL.Query()
	q.Add("type", "op")
	q.Add("cmd", cmd)
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
		log.Fatalf("%s (%s)", resp.Status, fw)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		red.Fprintf(os.Stderr, "fail\n\n")
		panic(err)
	}

	resp.Body.Close()

	config := configuration{Host: fw}
	err = xml.Unmarshal(respBody, &config)
	if err != nil {
		panic(err)
	}

	ch <- config
}

func printConfigXml(ch <-chan configuration, doneCh chan<- struct{}) {
	for {
		if session, chanIsOpen := <-ch; chanIsOpen {
			green.Printf("\n*** %s ***\n\n", session.Host)
			fmt.Printf("%s\n\n", session.Config.InnerXML)
			blue.Printf("################################################################################\n\n")
		} else {
			doneCh <- struct{}{}
			return
		}
	}
}
