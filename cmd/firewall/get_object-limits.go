package firewall

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/antchfx/xmlquery"
	"github.com/fatih/color"
	"github.com/rodaine/table"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

type objectLimits struct {
	Firewall      string
	Address       objectLimit
	AddressGroup  objectLimit
	Service       objectLimit
	ServiceGroup  objectLimit
	PolicyRule    objectLimit
	PbfPolicyRule objectLimit
	NatPolicyRule objectLimit
	QosPolicyRule objectLimit
	Error         string
}

type objectLimit struct {
	Limit       int64
	Used        int64
	Remaining   int64
	PercentUsed string
}

// getInterfacesCmd represents the getObjectLimits command
var getObjectLimitsCmd = &cobra.Command{
	Use:   "object-limits",
	Short: "Get firewall object limits",
	Long: `Get firewall object limits

Examples:
# Print object limits of 'fw01.example.com' and 'fw02.example.com':

  > panos-cli firewall get object-limits fw01.example.com fw02.example.com

# Print object limits of firewalls returned from the 'panos-cli panorama get firewalls' command:

  > panos-cli panorama get firewalls --terse | panos-cli firewall get object-limits`,
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
				log.Fatalf("error allocating terminal\n\n")
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
		ch := make(chan objectLimits, 10)
		doneCh := make(chan struct{})

		go printObjectLimits(ch, &errorBuffer, doneCh)

		wg.Add(len(hosts))
		for _, fw := range hosts {
			go getObjectLimits(ch, fw, userFlagSet)
		}
		wg.Wait()
		close(ch)
		<-doneCh

		// Print errors
		if errorBuffer.String() != "" {
			log.Printf("\n%s\n", errorBuffer.String())
		} else {
			log.Printf("\n\n")
		}

		// Print summary
		elapsed := time.Since(start)
		log.Printf(" Completed in %.3f seconds\n", elapsed.Seconds())
	},
}

func init() {
	getCmd.AddCommand(getObjectLimitsCmd)

	getObjectLimitsCmd.Flags().StringVar(&user, "user", user, "PAN admin user")
	getObjectLimitsCmd.Flags().StringVar(&password, "password", password, "password for PAN user")
}

func getObjectLimits(ch chan<- objectLimits, fw string, userFlagSet bool) {
	defer wg.Done()

	objLimits := objectLimits{Firewall: fw}
	defer func() {
		ch <- objLimits
	}()

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	url := fmt.Sprintf("https://%s/api/", fw)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		objLimits.Error = fmt.Sprintf("%s: %v\n\n", fw, err)
		return
	}

	// Get interface operational data
	q := req.URL.Query()
	q.Add("type", "op")
	q.Add("cmd", "<show><system><state><filter>cfg.general.max*</filter></state></system></show>")
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
		objLimits.Error = fmt.Sprintf("%s: %v\n\n", fw, err)
		return
	}
	if resp.StatusCode != 200 {
		red.Fprintf(os.Stderr, "fail\n\n")
		log.Fatalf("%s (%s)", resp.Status, fw)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		objLimits.Error = fmt.Sprintf("%s: %v\n\n", fw, err)
		return
	}

	resp.Body.Close()

	// Convert response to slice
	respSlice := strings.Split(string(respBody), "\n")

	// Remove last element
	respSlice = respSlice[:len(respSlice)-1]

	// Parse response and convert to map
	limitMap := make(map[string]int64)
	regex := regexp.MustCompile(`(<response status="success"><result><!\[CDATA\[)?cfg.general.max-`)
	for _, obj := range respSlice {
		// Remove unwated leading text
		obj = regex.ReplaceAllString(obj, "")
		// Split object and limit
		splitObject := strings.SplitN(obj, ": ", 2)
		object := splitObject[0]
		// Convert limit to int64
		limit, _ := strconv.ParseInt(splitObject[1], 0, 64)
		limitMap[object] = limit
	}

	// Get firewall configuration
	q = req.URL.Query()
	q.Add("type", "op")
	q.Add("cmd", "<show><config><effective-running></effective-running></config></show>")
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
		objLimits.Error = fmt.Sprintf("%s: %v\n\n", fw, err)
		return
	}
	if resp.StatusCode != 200 {
		red.Fprintf(os.Stderr, "fail\n\n")
		log.Fatal(resp.Status)
	}

	respBody, err = io.ReadAll(resp.Body)
	if err != nil {
		objLimits.Error = fmt.Sprintf("%s: %v\n\n", fw, err)
		return
	}

	resp.Body.Close()

	// Get current object counts
	doc, _ := xmlquery.Parse(strings.NewReader(string(respBody)))
	usedMap := make(map[string]int64)
	usedMap["address"] = int64(len(xmlquery.Find(doc, "//address/entry")))
	usedMap["address-group"] = int64(len(xmlquery.Find(doc, "//address-group/entry")))
	usedMap["service"] = int64(len(xmlquery.Find(doc, "//service/entry")))
	usedMap["service-group"] = int64(len(xmlquery.Find(doc, "//service-group/entry")))
	usedMap["policy-rule"] = int64(len(xmlquery.Find(doc, "//security/rules/entry")))
	usedMap["nat-policy-rule"] = int64(len(xmlquery.Find(doc, "//nat/rules/entry")))
	usedMap["pbf-policy-rule"] = int64(len(xmlquery.Find(doc, "//pbf/rules/entry")))
	usedMap["qos-policy-rule"] = int64(len(xmlquery.Find(doc, "//qos/rules/entry")))

	// Populate a struct with the data
	objLimits.Address = objectLimit{
		Limit:       limitMap["address"],
		Used:        usedMap["address"],
		Remaining:   limitMap["address"] - usedMap["address"],
		PercentUsed: fmt.Sprintf("%d%%", int64(float64(usedMap["address"])/float64(limitMap["address"])*100)),
	}
	objLimits.AddressGroup = objectLimit{
		Limit:       limitMap["address-group"],
		Used:        usedMap["address-group"],
		Remaining:   limitMap["address-group"] - usedMap["address-group"],
		PercentUsed: fmt.Sprintf("%d%%", int64(float64(usedMap["address-group"])/float64(limitMap["address-group"])*100)),
	}
	objLimits.Service = objectLimit{
		Limit:       limitMap["service"],
		Used:        usedMap["service"],
		Remaining:   limitMap["service"] - usedMap["service"],
		PercentUsed: fmt.Sprintf("%d%%", int64(float64(usedMap["service"])/float64(limitMap["service"])*100)),
	}
	objLimits.ServiceGroup = objectLimit{
		Limit:       limitMap["service-group"],
		Used:        usedMap["service-group"],
		Remaining:   limitMap["service-group"] - usedMap["service-group"],
		PercentUsed: fmt.Sprintf("%d%%", int64(float64(usedMap["service-group"])/float64(limitMap["service-group"])*100)),
	}
	objLimits.PolicyRule = objectLimit{
		Limit:       limitMap["policy-rule"],
		Used:        usedMap["policy-rule"],
		Remaining:   limitMap["policy-rule"] - usedMap["policy-rule"],
		PercentUsed: fmt.Sprintf("%d%%", int64(float64(usedMap["policy-rule"])/float64(limitMap["policy-rule"])*100)),
	}
	objLimits.NatPolicyRule = objectLimit{
		Limit:       limitMap["nat-policy-rule"],
		Used:        usedMap["nat-policy-rule"],
		Remaining:   limitMap["nat-policy-rule"] - usedMap["nat-policy-rule"],
		PercentUsed: fmt.Sprintf("%d%%", int64(float64(usedMap["nat-policy-rule"])/float64(limitMap["nat-policy-rule"])*100)),
	}
	objLimits.PbfPolicyRule = objectLimit{
		Limit:       limitMap["pbf-policy-rule"],
		Used:        usedMap["pbf-policy-rule"],
		Remaining:   limitMap["pbf-policy-rule"] - usedMap["pbf-policy-rule"],
		PercentUsed: fmt.Sprintf("%d%%", int64(float64(usedMap["pbf-policy-rule"])/float64(limitMap["pbf-policy-rule"])*100)),
	}
	objLimits.QosPolicyRule = objectLimit{
		Limit:       limitMap["qos-policy-rule"],
		Used:        usedMap["qos-policy-rule"],
		Remaining:   limitMap["qos-policy-rule"] - usedMap["qos-policy-rule"],
		PercentUsed: fmt.Sprintf("%d%%", int64(float64(usedMap["qos-policy-rule"])/float64(limitMap["qos-policy-rule"])*100)),
	}
}

func printObjectLimits(ch <-chan objectLimits, error *bytes.Buffer, done chan<- struct{}) {
	// Print interfaces
	headerFmt := color.New(color.FgBlue, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgHiYellow).SprintfFunc()

	tbl := table.New("Firewall", "Object", "Limit", "Used", "Remaining", "Percent Used")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

	for fw := range ch {
		if fw.Error != "" {
			error.WriteString(fw.Error)
		} else {
			tbl.AddRow(fw.Firewall, "Address", fw.Address.Limit, fw.Address.Used, fw.Address.Remaining, fw.Address.PercentUsed)
			tbl.AddRow(fw.Firewall, "Address Group", fw.AddressGroup.Limit, fw.AddressGroup.Used, fw.AddressGroup.Remaining, fw.AddressGroup.PercentUsed)
			tbl.AddRow(fw.Firewall, "Service", fw.Service.Limit, fw.Service.Used, fw.Service.Remaining, fw.Service.PercentUsed)
			tbl.AddRow(fw.Firewall, "Service Group", fw.ServiceGroup.Limit, fw.ServiceGroup.Used, fw.ServiceGroup.Remaining, fw.ServiceGroup.PercentUsed)
			tbl.AddRow(fw.Firewall, "Security Policy", fw.PolicyRule.Limit, fw.PolicyRule.Used, fw.PolicyRule.Remaining, fw.PolicyRule.PercentUsed)
			tbl.AddRow(fw.Firewall, "PBF Policy", fw.PbfPolicyRule.Limit, fw.PbfPolicyRule.Used, fw.PbfPolicyRule.Remaining, fw.PbfPolicyRule.PercentUsed)
			tbl.AddRow(fw.Firewall, "NAT Policy", fw.NatPolicyRule.Limit, fw.NatPolicyRule.Used, fw.NatPolicyRule.Remaining, fw.NatPolicyRule.PercentUsed)
			tbl.AddRow(fw.Firewall, "QoS Policy", fw.QosPolicyRule.Limit, fw.QosPolicyRule.Used, fw.QosPolicyRule.Remaining, fw.QosPolicyRule.PercentUsed)
		}
	}

	tbl.Print()

	done <- struct{}{}
}
