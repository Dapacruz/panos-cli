//go:build !windows
// +build !windows

package firewall

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	expect "github.com/google/goexpect"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

var (
	hosts        []string
	cmds         []string
	port         string
	keyBasedAuth bool
	promptRE     = regexp.MustCompile(`>`)
	wg           sync.WaitGroup
	signer       ssh.Signer
)

const SESSION_SETUP = "set cli scripting-mode on"

type sessionDetails struct {
	host    string
	results map[string]string
}

// runCommandsCmd represents the runCommands command
var runCommandsCmd = &cobra.Command{
	Use:   "commands [flags] <firewall> [<firewall> ...]",
	Short: "Executes CLI commands via SSH",
	Long: `Executes CLI commands via SSH

Examples:
  > panos-cli firewall run commands
  > panos-cli firewall run commands  -u user`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprintln(os.Stderr)
		if len(cmds) == 0 {
			cmd.Help()
			fmt.Printf("\nno commands specified\n")
			os.Exit(1)
		}

		hosts = cmd.Flags().Args()
		if len(hosts) == 0 {
			if isInputFromPipe() {
				if !keyBasedAuth {
					log.Fatal("key based auth is required when reading hosts from stdin")
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

		if !keyBasedAuth && viper.GetString("user") == "" && user == "" {
			fmt.Fprint(os.Stderr, "PAN User: ")
			fmt.Scanln(&user)
		} else if user == "" {
			user = viper.GetString("user")
		}

		// If the password flag is not set, prompt for password
		if !keyBasedAuth && password == "" {
			fmt.Fprintf(os.Stderr, "Password (%s): ", user)
			bytepw, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				panic(err)
			}
			password = string(bytepw)
			fmt.Fprintf(os.Stderr, "\n\n")
		}

		if keyBasedAuth {
			file, err := os.ReadFile(filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa"))
			if err != nil {
				log.Fatal(err)
			}

			signer, err = ssh.ParsePrivateKey(file)
			if err != nil {
				log.Fatal(err)
			}
		}

		start := time.Now()

		ch := make(chan sessionDetails, 10)
		doneCh := make(chan struct{})

		go printResults(ch, doneCh)

		for _, host := range hosts {
			wg.Add(1)
			go runCommands(ch, host)
		}
		wg.Wait()
		close(ch)
		<-doneCh

		elapsed := time.Since(start)

		fmt.Printf(" Complete: %d command(s) executed on %d host(s) in %.3f seconds\n", len(cmds), len(hosts), elapsed.Seconds())
	},
}

func init() {
	runCmd.AddCommand(runCommandsCmd)

	runCommandsCmd.Flags().StringVar(&user, "user", user, "PAN admin user")
	runCommandsCmd.Flags().StringVar(&password, "password", password, "password for PAN user")
	runCommandsCmd.Flags().StringSliceVarP(&cmds, "commands", "c", cmds, "comma separated set of commands to execute")
	runCommandsCmd.Flags().BoolVarP(&keyBasedAuth, "key-based-auth", "k", false, "use key-based authentication")
	runCommandsCmd.Flags().StringVarP(&port, "port", "p", "22", "port to connect to on host")
	runCommandsCmd.Flags().IntVarP(&timeout, "timeout", "t", 10, "timeout in seconds for each command")
}

func isInputFromPipe() bool {
	fileInfo, _ := os.Stdin.Stat()
	return fileInfo.Mode()&os.ModeCharDevice == 0
}

// runCommands executes commands on a host
func runCommands(ch chan<- sessionDetails, host string) {
	defer wg.Done()

	session := sessionDetails{
		host:    host,
		results: make(map[string]string),
	}
	sessionTimeout := time.Duration(timeout) * time.Second

	// Set auth method
	var authMethod ssh.AuthMethod
	if keyBasedAuth {
		authMethod = ssh.PublicKeys(signer)
	} else {
		authMethod = ssh.Password(password)
	}

	// Connect to host
	sshClt, err := ssh.Dial("tcp", net.JoinHostPort(host, port), &ssh.ClientConfig{
		User: viper.GetString("user"),
		Auth: []ssh.AuthMethod{authMethod},
		// allow any host key to be used (non-prod)
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		log.Fatalf("ssh.Dial(%q) failed: %v", host, err)
	}
	defer sshClt.Close()

	// Start SSH session
	e, _, err := expect.SpawnSSH(sshClt, sessionTimeout)
	if err != nil {
		log.Fatal(err)
	}
	defer e.Close()

	// Wait for prompt after login
	_, _, err = e.Expect(promptRE, sessionTimeout)
	if err != nil {
		log.Fatal(err)
	}

	// Set up session
	err = e.Send(SESSION_SETUP + "\n")
	if err != nil {
		log.Fatal(err)
	}
	_, _, err = e.Expect(promptRE, sessionTimeout)
	if err != nil {
		log.Fatal(err)
	}

	// Execute commands
	for _, cmd := range cmds {
		err = e.Send(cmd + "\n")
		if err != nil {
			log.Fatal(err)
		}
		result, _, err := e.Expect(promptRE, sessionTimeout)
		if err != nil {
			log.Fatal(err)
		}
		session.results[cmd] = result
	}

	ch <- session
}

// printResults prints the results
func printResults(ch <-chan sessionDetails, doneCh chan<- struct{}) {
	for {
		if session, chanIsOpen := <-ch; chanIsOpen {
			green.Printf("\n*** %s ***\n\n\n", session.host)
			for cmd, result := range session.results {
				yellow.Printf("*** %s ***\n", cmd)
				fmt.Printf("%s\n\n", trimOutput(result))
			}
			blue.Printf("################################################################################\n\n\n")
		} else {
			doneCh <- struct{}{}
			return
		}
	}
}

// trimOutput removes the echoed command and the prompt from the output
func trimOutput(output string) string {
	lines := strings.Split(output, "\n")
	return strings.Join(lines[1:len(lines)-1], "\n")
}
