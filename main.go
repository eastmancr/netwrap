/*
   Copyright 2025 Netwrap Contributors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Config holds the run configuration for the netwrap session.
type Config struct {
	NetworkName  string
	Command      []string
	PortMappings []PortMapping
	IsScript     bool
	CreatedNS    bool
	SubnetID     int
	SessionID    string
	NSName       string
	VethHost     string
	VethNS       string
	HostIP       string
	NSIP         string
}

// PortMapping defines a forwarding rule from a host port to a container port.
type PortMapping struct {
	HostPort   string
	ClientPort string
	Protocol   string // "tcp" or "udp"
}

func main() {
	if err := run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				os.Exit(status.ExitStatus())
			}
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "netwrap: %v\n", err)
		os.Exit(1)
	}
}

// run is the main entry point logic. It handles:
// 1. Parsing arguments and flags (once).
// 2. Checking for help flag.
// 3. Checking for root privileges (re-execs with sudo if needed).
// 4. Setting up or joining the network namespace.
// 5. Starting TCP proxies for port forwarding.
// 6. Executing the target command inside the namespace.
// 7. Handling signals and cleanup.
func run() error {
	flags, cmd, err := parseRawArgs(os.Args[1:])
	if err != nil {
		return err
	}

	for _, f := range flags {
		if f == "-h" || f == "--help" || f == "help" {
			usage()
			return nil
		}
	}

	if !hasPrivileges() {
		// Attempt to elevate
		// We preserve environment variables if possible, but the executing user will need the sudoers SETENV permission for this to work seamlessly.
		// File capabilities with setcap are insufficient because netwrap executes the ip command, which does not inherit file capabilities.
		sudoPath, err := exec.LookPath("sudo")
		if err != nil {
			return fmt.Errorf("sudo required but not found")
		}
		args := append([]string{"sudo", "-E"}, os.Args...)
		// Replace current process with sudo
		return syscall.Exec(sudoPath, args, os.Environ())
	}

	checkCmd("ip")

	config, err := buildConfig(flags, cmd)
	if err != nil {
		return err
	}

	if err := setupNetwork(config); err != nil {
		return fmt.Errorf("setup network: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	defer cleanup(config)

	var wg sync.WaitGroup
	for _, pm := range config.PortMappings {
		wg.Add(1)
		go func(mapping PortMapping) {
			defer wg.Done()
			if err := startProxy(ctx, mapping, config.NSIP); err != nil {
				fmt.Fprintf(os.Stderr, "proxy error %s:%s->%s: %v\n", mapping.Protocol, mapping.HostPort, mapping.ClientPort, err)
			}
		}(pm)
	}

	cmdExec := exec.Command("ip", "netns", "exec", config.NSName)
	cmdExec.Args = append(cmdExec.Args, config.Command...)
	cmdExec.Stdin = os.Stdin
	cmdExec.Stdout = os.Stdout
	cmdExec.Stderr = os.Stderr

	if err := cmdExec.Start(); err != nil {
		return fmt.Errorf("failed to start command: %w", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmdExec.Wait()
	}()

	select {
	case err := <-done:
		cancel()
		return err
	case <-ctx.Done():
		if cmdExec.Process != nil {
			cmdExec.Process.Signal(syscall.SIGTERM)
		}
		return ctx.Err()
	}
}

func usage() {
	fmt.Println(`Usage: netwrap [OPTIONS] PROGRAM [ARGS]
       netwrap SCRIPT_FILE

Run a program in an isolated network namespace.

Options:
  -h, --help             Show this help message
  -n, --network=NAME     Join/create a named shared network
  -HOST:CLIENT[/PROTO]   Map port (default TCP). E.g. -8080:80 or -53:53/udp
  --                     End of netwrap options

Script Mode:
  Use as a shebang interpreter. Lines before the command are arguments
  (without dashes).

See 'man netwrap' for more details.`)
}

// parseRawArgs splits raw arguments into netwrap flags and the program command.
func parseRawArgs(args []string) ([]string, []string, error) {
	if len(args) == 0 {
		return nil, nil, fmt.Errorf("no program specified")
	}

	// Check for script mode
	info, err := os.Stat(args[0])
	if err == nil && !info.IsDir() {
		return parseScript(args[0])
	}

	// CLI mode
	for i := 0; i < len(args); i++ {
		arg := args[i]

		if arg == "--" {
			return args[:i], args[i+1:], nil
		}

		if arg == "-h" || arg == "--help" || arg == "help" {
			continue
		}

		if strings.HasPrefix(arg, "-n=") || strings.HasPrefix(arg, "--network=") {
			continue
		}
		if arg == "-n" || arg == "--network" {
			if i+1 < len(args) {
				i++
			}
			continue
		}

		if strings.HasPrefix(arg, "-") && strings.Contains(arg, ":") {
			continue
		}

		// Found first non-flag argument (the program)
		return args[:i], args[i:], nil
	}

	// Everything was flags
	return args, nil, nil
}

func buildConfig(flags []string, command []string) (*Config, error) {
	c := &Config{}

	b := make([]byte, 2)
	rand.Read(b)
	c.SessionID = hex.EncodeToString(b)

	c.Command = command

	// If we have no command, it's an error because we have already checked for --help
	if len(c.Command) == 0 {
		return nil, fmt.Errorf("no program specified")
	}

	if err := processFlags(c, flags); err != nil {
		return nil, err
	}

	return c, nil
}

func processFlags(c *Config, flags []string) error {
	for i := 0; i < len(flags); i++ {
		arg := flags[i]

		if strings.HasPrefix(arg, "-n=") || strings.HasPrefix(arg, "--network=") {
			parts := strings.SplitN(arg, "=", 2)
			c.NetworkName = parts[1]
			continue
		}
		if arg == "-n" || arg == "--network" {
			if i+1 < len(flags) {
				c.NetworkName = flags[i+1]
				i++
			}
			continue
		}

		if strings.Contains(arg, ":") {
			raw := strings.TrimLeft(arg, "-")
			parts := strings.SplitN(raw, ":", 2)
			if len(parts) == 2 {
				hostPort := parts[0]
				rest := parts[1]

				if _, err := strconv.Atoi(hostPort); err != nil {
					return fmt.Errorf("invalid host port: %s", hostPort)
				}

				var clientPort string
				var protocol string = "tcp" // default

				j := 0
				for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
					j++
				}

				clientPort = rest[:j]
				if clientPort == "" {
					return fmt.Errorf("missing client port in mapping %s", raw)
				}

				if j < len(rest) {
					// Not end of string. Skip 1 char.
					j++
					protoPart := strings.TrimSpace(rest[j:])
					protoPart = strings.ToLower(protoPart)
					switch protoPart {
					case "tcp":
						protocol = "tcp"
					case "udp":
						protocol = "udp"
					default:
						return fmt.Errorf("invalid protocol '%s' in mapping %s", protoPart, raw)
					}
				}

				if _, err := strconv.Atoi(clientPort); err != nil {
					return fmt.Errorf("invalid client port: %s", clientPort)
				}

				c.PortMappings = append(c.PortMappings, PortMapping{
					HostPort:   hostPort,
					ClientPort: clientPort,
					Protocol:   protocol,
				})
				continue
			}
		}
	}
	return nil
}

// parseScript reads a file and extracts arguments and the command.
func parseScript(path string) ([]string, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}

	cmdStart := len(lines)
	for i := len(lines) - 1; i >= 0; i-- {
		prevIdx := i - 1
		if prevIdx < 0 {
			cmdStart = 0
			break
		}
		if !strings.HasSuffix(lines[prevIdx], "\\") {
			cmdStart = i
			break
		}
	}

	var rawFlags []string
	for i := 0; i < cmdStart; i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		if strings.Contains(line, "=") {
			re := regexp.MustCompile(`\s*=\s*`)
			line = re.ReplaceAllString(line, "=")
		}

		if !strings.HasPrefix(line, "-") {
			line = "-" + line
		}
		rawFlags = append(rawFlags, line)
	}

	var cmdParts []string
	for i := cmdStart; i < len(lines); i++ {
		part := strings.TrimSuffix(lines[i], "\\")
		part = strings.TrimSpace(part)
		if part != "" {
			fields := strings.Fields(part)
			cmdParts = append(cmdParts, fields...)
		}
	}

	return rawFlags, cmdParts, nil
}

// hasPrivileges checks if the current process has the ability to configure networking.
func hasPrivileges() bool {
	if os.Geteuid() == 0 {
		return true
	}

	name := fmt.Sprintf("nw-probe-%d", os.Getpid())
	cmd := exec.Command("ip", "link", "add", name, "type", "dummy")
	if err := cmd.Run(); err != nil {
		return false
	}

	exec.Command("ip", "link", "del", name).Run()
	return true
}

func checkCmd(name string) {
	if _, err := exec.LookPath(name); err != nil {
		fmt.Fprintf(os.Stderr, "netwrap: %s is required but not found\n", name)
		os.Exit(1)
	}
}

func cleanup(c *Config) {
	if c.CreatedNS && c.NSName != "" {
		exec.Command("ip", "netns", "del", c.NSName).Run()
	}
}

func setupNetwork(c *Config) error {
	if c.NetworkName != "" {
		c.NSName = c.NetworkName
		err := exec.Command("ip", "netns", "pids", c.NSName).Run()
		if err == nil {
			c.CreatedNS = false
			out, err := exec.Command("ip", "netns", "exec", c.NSName, "ip", "-4", "addr", "show").Output()
			if err != nil {
				return fmt.Errorf("failed to get ip of existing ns: %w", err)
			}
			c.NSIP = extractIP(string(out))
			if c.NSIP == "" {
				return fmt.Errorf("could not find IP in existing namespace")
			}
		} else {
			c.CreatedNS = true
		}
	} else {
		c.NSName = fmt.Sprintf("netwrap-%s", c.SessionID)
		c.CreatedNS = true
	}

	if c.CreatedNS {
		c.VethHost = fmt.Sprintf("veth-host-%s", c.SessionID)
		c.VethNS = fmt.Sprintf("veth-ns-%s", c.SessionID)

		out, _ := exec.Command("ip", "addr", "show").Output()
		outStr := string(out)
		for i := 1; i < 255; i++ {
			if !strings.Contains(outStr, fmt.Sprintf("10.200.%d.1", i)) {
				c.SubnetID = i
				break
			}
		}
		if c.SubnetID == 0 {
			return fmt.Errorf("no free subnet found")
		}

		c.HostIP = fmt.Sprintf("10.200.%d.1", c.SubnetID)
		c.NSIP = fmt.Sprintf("10.200.%d.2", c.SubnetID)

		runCmd("ip", "netns", "add", c.NSName)
		runCmd("ip", "link", "add", c.VethHost, "type", "veth", "peer", "name", c.VethNS)
		runCmd("ip", "link", "set", c.VethNS, "netns", c.NSName)
		runCmd("ip", "addr", "add", c.HostIP+"/24", "dev", c.VethHost)
		runCmd("ip", "link", "set", c.VethHost, "up")
		runCmd("ip", "netns", "exec", c.NSName, "ip", "addr", "add", c.NSIP+"/24", "dev", c.VethNS)
		runCmd("ip", "netns", "exec", c.NSName, "ip", "link", "set", c.VethNS, "up")
		runCmd("ip", "netns", "exec", c.NSName, "ip", "link", "set", "lo", "up")
	} else {
		out, _ := exec.Command("ip", "netns", "exec", c.NSName, "ip", "-4", "addr", "show").Output()
		c.NSIP = extractIP(string(out))
		if c.NSIP == "" {
			return fmt.Errorf("could not find IP in joined namespace")
		}
	}
	return nil
}

func extractIP(output string) string {
	for line := range strings.SplitSeq(output, "\n") {
		if strings.Contains(line, "10.200.") {
			for f := range strings.FieldsSeq(line) {
				if strings.Contains(f, "10.200.") {
					return strings.Split(f, "/")[0]
				}
			}
		}
	}
	return ""
}

func runCmd(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

func startProxy(ctx context.Context, mapping PortMapping, targetIP string) error {
	if mapping.Protocol == "udp" {
		return startProxyUDP(ctx, mapping, targetIP)
	}
	return startProxyTCP(ctx, mapping, targetIP)
}

func startProxyTCP(ctx context.Context, mapping PortMapping, targetIP string) error {
	listener, err := net.Listen("tcp", ":"+mapping.HostPort)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return nil
		}
		go handleConn(conn, targetIP, mapping.ClientPort)
	}
}

func handleConn(client net.Conn, targetIP, targetPort string) {
	defer client.Close()

	target, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", targetIP, targetPort), 2*time.Second)
	if err != nil {
		return
	}
	defer target.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(target, client)
		if t, ok := target.(*net.TCPConn); ok {
			t.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(client, target)
		if c, ok := client.(*net.TCPConn); ok {
			c.CloseWrite()
		}
	}()

	wg.Wait()
}

func startProxyUDP(ctx context.Context, mapping PortMapping, targetIP string) error {
	addr, err := net.ResolveUDPAddr("udp", ":"+mapping.HostPort)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	for {
		buffer := make([]byte, 4096)
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			return nil
		}

		go handleUDPPacket(conn, clientAddr, targetIP, mapping.ClientPort, buffer[:n])
	}
}

// UDP NAT Table
var udpSessions sync.Map // map[string]*net.UDPConn

func handleUDPPacket(serverConn *net.UDPConn, clientAddr *net.UDPAddr, targetIP, targetPort string, data []byte) {
	clientKey := clientAddr.String()

	val, ok := udpSessions.Load(clientKey)
	var targetConn *net.UDPConn

	if !ok {
		targetAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%s", targetIP, targetPort))
		if err != nil {
			// fmt.Fprintf(os.Stderr, "udp resolve error: %v\n", err)
			return
		}

		// DialUDP handles random port allocation
		targetConn, err = net.DialUDP("udp", nil, targetAddr)
		if err != nil {
			// fmt.Fprintf(os.Stderr, "udp dial error: %v\n", err)
			return
		}

		udpSessions.Store(clientKey, targetConn)

		go func() {
			buf := make([]byte, 4096)
			for {
				targetConn.SetReadDeadline(time.Now().Add(30 * time.Second))
				n, _, err := targetConn.ReadFromUDP(buf)
				if err != nil {
					udpSessions.Delete(clientKey)
					targetConn.Close()
					return
				}
				serverConn.WriteToUDP(buf[:n], clientAddr)
			}
		}()
	} else {
		targetConn = val.(*net.UDPConn)
	}

	targetConn.Write(data)
	targetConn.SetReadDeadline(time.Now().Add(30 * time.Second))
}

// vim:ts=4
