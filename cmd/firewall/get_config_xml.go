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
	Error  string
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

    > panos-cli firewall get config xml --type 'effective-running' --xpath 'mgt-config' fw01.example.com`,
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

		if !slices.Contains([]string{"candidate", "effective-running", "merged", "pushed-shared-policy", "pushed-template", "running", "synced", "synced-diff"}, configType) {
			cmd.Help()
			log.Fatalf("\ninvalid configuration type\n\n")
		}

		if !slices.Contains([]string{"effective-running", "running"}, configType) && xpath != "." {
			cmd.Help()
			log.Fatalf("\nxpath should only be used with configuration types 'effective-running' and 'running'\n\n")
		}

		// If the user flag is not set or the user is not set, prompt for user
		if viper.GetString("user") == "" && user == "" {
			fmt.Fprintf(os.Stderr, "PAN User: ")
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
		ch := make(chan configuration, 10)
		doneCh := make(chan struct{})

		go printConfigXml(ch, &errorBuffer, doneCh)

		wg.Add(len(hosts))
		for _, fw := range hosts {
			go getConfigXml(ch, fw, userFlagSet, xpath)
		}
		wg.Wait()
		close(ch)
		<-doneCh

		// Print errors
		log.Println(errorBuffer.String())

		// Print summary
		elapsed := time.Since(start)
		log.Printf(" Completed in %.3f seconds\n", elapsed.Seconds())
	},
}

func init() {
	getConfigCmd.AddCommand(getConfigXmlCmd)

	getConfigXmlCmd.Flags().StringVar(&user, "user", user, "PAN admin user")
	getConfigXmlCmd.Flags().StringVar(&password, "password", password, "password for PAN user")
	getConfigXmlCmd.Flags().StringVarP(&xpath, "xpath", "x", ".", "xpath of the node to retrieve (for use with configuration types 'effective-running' and 'running')")
	getConfigXmlCmd.Flags().StringVarP(&configType, "type", "t", "running", "type of configuration to retrieve (candidate, effective-running, merged, pushed-shared-policy, pushed-template, running, synced, synced-diff)")
}

func getConfigXml(ch chan<- configuration, fw string, userFlagSet bool, xpath string) {
	defer wg.Done()

	config := configuration{Host: fw}
	defer func() {
		ch <- config
	}()

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
		config.Error = fmt.Sprintf("%s: %v\n\n", fw, err)
		return
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
		config.Error = fmt.Sprintf("%s: %v\n\n", fw, err)
		return
	}
	if resp.StatusCode != 200 {
		config.Error = fmt.Sprintf("%s: response status code: %s\n\n", fw, resp.Status)
		return
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		config.Error = fmt.Sprintf("%s: %v\n\n", fw, err)
		return
	}

	resp.Body.Close()

	err = xml.Unmarshal(respBody, &config)
	if err != nil {
		config.Error = fmt.Sprintf("%s: %v\n\n", fw, err)
		return
	}
}

func printConfigXml(ch <-chan configuration, error *bytes.Buffer, done chan<- struct{}) {
	for session := range ch {
		if session.Error != "" {
			error.WriteString(session.Error)
		} else {
			green.Printf("\n*** %s ***\n\n", session.Host)
			fmt.Printf("%s\n\n", session.Config.InnerXML)
			blue.Printf("################################################################################\n\n")
		}
	}
	done <- struct{}{} // Notify when done
}
