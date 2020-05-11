package common

import (
	"fmt"
	"github.com/kevinburke/ssh_config"
	"github.com/mitchellh/go-homedir"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// recall that a single client allows for many sessions.
var sshClientCache map[string]*ssh.Client
var sshClientConfigCache map[string]*ssh.ClientConfig
var sshClientHostnames map[string]struct {
	HostName string
	Port string
}
var rcOnce = &sync.Once{}

func parseHostDetails(hostname string) (user, host, path string) {
	hostname = strings.TrimSpace(hostname)
	hostname = strings.TrimPrefix(hostname, "ssh:")

	// first part will be the host and username, second part will be the root path.
	info := strings.Split(hostname, ":")

	if x := strings.Index(info[0], "@"); x != -1 {
		userhostPair := strings.Split(info[0], "@")

		user = userhostPair[0]
		host = userhostPair[1]
	} else {
		host = info[0]
	}

	path = info[1]

	return
}

// Hosts is read as a list in case of a SSH->SSH transfer. That's a pending option.
// Furthermore, we map hostnames to paths, for convenience.
func readSSHConfig(inputs []string) map[string]string {
	hosts := make([]string, 0)
	pairs := make(map[string]string)
	for _,v := range inputs {
		user, host, path := parseHostDetails(v)

		hosts = append(hosts, host)
		pairs[host] = path

		if user != "" {
			sshClientConfigCache[host] = &ssh.ClientConfig{User: user}
		}
	}

	rcOnce.Do(func() {
		//ssh_config.
		home, err := homedir.Dir()

		if err != nil {
			return
		}

		_, err = os.Stat(filepath.Join(home, ".ssh/config"))

		if err != nil {
			return
		}

		f, err := os.Open(filepath.Join(home, ".ssh/config"))

		if err != nil {
			return
		}

		cfg, err := ssh_config.Decode(f)

		if err != nil {
			return
		}

		for _,cfg := range cfg.Hosts {
			for _,v := range cfg.Patterns {
				if v == nil {
					continue
				}

				for _, host := range hosts {
					matches, _ := filepath.Match(v.String(), host)

					if matches {
						sshClientConfigCache[host] = convertSSHHost(cfg, host)
					}
				}
			}
		}

		getHostInfo := func(hostname string) (hn, port string) {
			if x, ok := sshClientHostnames[hostname]; ok {
				return x.HostName, x.Port
			} else {
				return hostname, "21"
			}
		}

		for host, cfg := range sshClientConfigCache {
			//ssh.Dial("tcp", )
			hn, port := getHostInfo(host)

			client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", hn, port), cfg)

			if err != nil {
				GetLifecycleMgr().Error("could not connect to " + host + ": " + err.Error())
			}

			sshClientCache[host] = client
		}
	})

	return pairs
}

var gssapiOnce = &sync.Once{}

func logGSSAPIOnce() {
	gssapiOnce.Do(func() {
		GetLifecycleMgr().Info("GSSAPI auth is currently not supported. A next best will be attempted.")
	})
}

var hostkeyOnce = &sync.Once{}

func logHostKeyOnce() {
	hostkeyOnce.Do(func() {
		GetLifecycleMgr().Info("Host key auth is currently not supported. A next best will be attempted.")
	})
}

// We ignore everything but auth, and max sessions here.
func convertSSHHost(host *ssh_config.Host, hostname string) (out *ssh.ClientConfig) {
	out = &ssh.ClientConfig{}

	if cfg, ok := sshClientConfigCache[hostname]; ok {
		out = cfg
	}

	identitiesOnly := false // defaults to no
	// GSSAPI is not included because we don't support it.
	var preferredAuth []string
	challengeResponse := true // defaults to yes
	passwordAuth := true // defaults to yes
	identityFiles := make([]string, 0)



	for _,v := range host.Nodes {
		str := v.String()

		cfgItem := strings.Split(strings.TrimSpace(str), " ")

		if len(cfgItem) < 2 || strings.HasPrefix(cfgItem[0], "#") {
			continue
		}

		switch cfgItem[0] {
		case "User":
			out.User = cfgItem[1]
		case "ChallengeResponseAuthentication":
			challengeResponse = cfgItem[1] == "yes"
		case "PasswordAuthentication":
			passwordAuth = cfgItem[1] == "yes"
		case "IdentityFile":
			// Since this is IN ADDITION TO the SSH agent identities, we need to add all of those later.
			identityFiles = append(identityFiles, cfgItem[1])
		case "IdentitiesOnly":
			identitiesOnly = cfgItem[1] == "yes"
		case "GSSAPIAuthentication":
			// TODO: Do I add a library that supports such a thing?
			logGSSAPIOnce()
		case "PreferredAuthentications":
			preferredAuth = strings.Split(strings.Join(cfgItem[2:], ""), ",")

			for k,v := range preferredAuth {
				preferredAuth[k] = strings.TrimSpace(v)
			}
		case "Port":
			if x, ok := sshClientHostnames[hostname]; ok {
				x.Port = cfgItem[1]
				sshClientHostnames[hostname] = x
			} else {
				sshClientHostnames[hostname] = struct{
					HostName string
					Port string
				}{
					Port: cfgItem[1],
				}
			}
		case "Hostname":
			if x, ok := sshClientHostnames[hostname]; ok {
				x.HostName = cfgItem[1]
				sshClientHostnames[hostname] = x
			} else {
				sshClientHostnames[hostname] = struct{
					HostName string
					Port string
				}{
					HostName: cfgItem[1],
				}
			}
		}
	}

	sshKeyring := agent.NewKeyring()

	if len(preferredAuth) == 0 {
		preferredAuth = []string{"publickey", "keyboard-interactive", "password"}
	}

	out.Auth = make([]ssh.AuthMethod, 0)
	// We need to list the auth options.
	for _,v := range preferredAuth {
		switch v {
		case "hostbased":
			logHostKeyOnce()
		case "gssapi-with-mic":
			logGSSAPIOnce()
		case "publickey":
			// todo: get and parse list of signers
			signers := make([]ssh.Signer, 0)

			if !identitiesOnly {
				l, err := sshKeyring.Signers()

				if err != nil {
					GetLifecycleMgr().Info("Couldn't access SSH agent, checking if config supplied signers: " + err.Error())
				}

				signers = append(signers, l...)
			}

			for _,v := range identityFiles {
				key, err := ioutil.ReadFile(v)

				if err != nil {
					GetLifecycleMgr().Info("Couldn't read SSH key " + v + ", moving on: " + err.Error())
					continue
				}

				signer, err := ssh.ParsePrivateKey(key)

				if err != nil {
					GetLifecycleMgr().Info("Couldn't read SSH key " + v + ", moving on: " + err.Error())
					continue
				}

				signers = append(signers, signer)
			}

			out.Auth = append(out.Auth, ssh.PublicKeys(signers...))

		// major security todo for the below two: Disable echoing intelligently.
		case "keyboard-interactive":
			if !challengeResponse {
				continue
			}

			out.Auth = append(out.Auth, ssh.KeyboardInteractive(
				func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
					if len(questions) > 0 {
						for _, v := range questions {
							resp := GetLifecycleMgr().Prompt(fmt.Sprintf("Question from host %s: %s", hostname, v), PromptDetails{
								PromptType:             EPromptType.SSHChallengeResponse(),
								ResponseOptions:        nil,
								ArbitraryChallengeText: "Response",
								PromptTarget:           hostname,
							})

							answers = append(answers, resp.ResponseString)
						}
					} else {
						GetLifecycleMgr().Info(fmt.Sprintf("%s: %s", user, instruction))
					}

					return
				}))
		case "password":
			if !passwordAuth {
				continue
			}

			out.Auth = append(out.Auth, ssh.PasswordCallback(func() (secret string, err error) {
				resp := GetLifecycleMgr().Prompt("Password required for host " + hostname, PromptDetails{
					PromptType:             EPromptType.SSHPassword(),
					ResponseOptions:        nil,
					ArbitraryChallengeText: "Password",
					PromptTarget:           hostname,
				})

				return resp.ResponseString, nil
			}))
		}
	}

	return
}
