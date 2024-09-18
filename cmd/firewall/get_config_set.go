//go:build !windows
// +build !windows

package firewall

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

var configFilter string

// getConfigSetCmd represents the 'config set' command
var getConfigSetCmd = &cobra.Command{
	Use:   "set [flags] <firewall> [firewall]...",
	Short: "Get firewall set formatted config",
	Long: `Get firewall set formatted config

Examples:
  # Print set configuration of 'fw01.example.com' and 'fw02.example.com':

    > panos-cli firewall get config set fw01.example.com fw02.example.com

  # Print set configuration of firewalls returned from the 'panos-cli panorama get firewalls' command:

    > panos-cli panorama get firewalls --terse | panos-cli firewall get config set --key-based-auth

  # Print set configuration and filter for 'mgt-config':

    > panos-cli firewall get config set --filter 'mgt-config' fw01.example.com`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprintln(os.Stderr)
		hosts = cmd.Flags().Args()
		if len(hosts) == 0 {
			if isInputFromPipe() {
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

		// Retrieve password from standard input
		if passwordStdin {
			if isInputFromPipe() {
				// Read password from stdin
				scanner := bufio.NewScanner(bufio.NewReader(os.Stdin))
				for scanner.Scan() {
					password = scanner.Text()
				}
			} else {
				cmd.Help()
				fmt.Printf("\nunable to retrieve password from standard input\n")
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
		if !keyBasedAuth && viper.GetString("password") == "" && password == "" {
			tty, err := os.Open("/dev/tty")
			if err != nil {
				log.Fatal(err, "error allocating terminal")
			}
			fd := int(tty.Fd())
			fmt.Fprintf(os.Stderr, "Password (%s): ", user)
			bytepw, err := term.ReadPassword(int(fd))
			if err != nil {
				panic(err)
			}
			tty.Close()
			password = string(bytepw)
			fmt.Fprintf(os.Stderr, "\n\n")
		} else if password == "" {
			password = viper.GetString("password")
		}

		if keyBasedAuth {
			file, err := os.ReadFile(filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa"))
			if err != nil {
				log.Fatal(err)
			}

			signer, err = ssh.ParsePrivateKey(file)
			if err != nil {
				if err.Error() == "ssh: this private key is passphrase protected" {
					tty, err := os.Open("/dev/tty")
					if err != nil {
						log.Fatal(err, "error allocating terminal")
					}
					fd := int(tty.Fd())
					fmt.Fprintf(os.Stderr, "SSH Private Key Passphrase: ")
					passphrase, err := term.ReadPassword(fd)
					if err != nil {
						log.Fatal(err)
					}
					tty.Close()
					fmt.Fprintf(os.Stderr, "\n\n")
					signer, err = ssh.ParsePrivateKeyWithPassphrase(file, passphrase)
					if err != nil {
						log.Fatal(err)
					}
				} else {
					log.Fatal(err)
				}
			}
		}

		cmds = []string{"set cli config-output-format set", "configure"}
		if configFilter != "" {
			cmds = append(cmds, fmt.Sprintf(`show | match '%s'`, configFilter))
		} else {
			cmds = append(cmds, "show")
		}

		start := time.Now()

		ch := make(chan sessionDetails, 100)
		doneCh := make(chan struct{})

		go printConfigSet(ch, doneCh)

		for _, host := range hosts {
			wg.Add(1)
			go runCommands(ch, host)
		}
		wg.Wait()
		close(ch)
		<-doneCh

		// Print summary
		elapsed := time.Since(start)
		fmt.Fprintf(os.Stderr, " Completed in %.3f seconds\n", elapsed.Seconds())
	},
}

func init() {
	getConfigCmd.AddCommand(getConfigSetCmd)

	getConfigSetCmd.Flags().StringVar(&user, "user", user, "PAN admin user")
	getConfigSetCmd.Flags().StringVar(&password, "password", password, "password for PAN user")
	getConfigSetCmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "receive password from standard input")
	getConfigSetCmd.Flags().BoolVarP(&keyBasedAuth, "key-based-auth", "k", false, "use key-based authentication")
	getConfigSetCmd.Flags().StringVarP(&port, "port", "p", "22", "port to connect to on host")
	getConfigSetCmd.Flags().IntVarP(&expectTimeout, "expect-timeout", "e", 30, "expect timeout in seconds for each command")
	getConfigSetCmd.Flags().IntVarP(&sshTimeout, "ssh-timeout", "S", 30, "SSH timeout in seconds")
	getConfigSetCmd.Flags().BoolVarP(&ignoreHostKey, "insecure", "K", false, "ignore host key checking")
	getConfigSetCmd.Flags().StringVarP(&configFilter, "filter", "f", configFilter, "filter configuration output")
}

// printConfigSet prints the results
func printConfigSet(ch <-chan sessionDetails, doneCh chan<- struct{}) {
	for {
		if session, chanIsOpen := <-ch; chanIsOpen {
			green.Printf("\n*** %s ***\n\n", session.host)
			fmt.Printf("%s\n\n", trimConfigSetOutput(session.results[cmds[2]]))
			blue.Printf("################################################################################\n\n")
		} else {
			doneCh <- struct{}{}
			return
		}
	}
}

// trimOutput removes the echoed command and the prompt from the output
func trimConfigSetOutput(output string) string {
	lines := strings.Split(output, "\n")
	return strings.Join(lines[1:len(lines)-2], "\n")
}
