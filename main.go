package main

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"html/template"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// VERSION is the current version of the tool
const VERSION = "0.2.2 ReconRaptor" 
const AUTHORS = "IG:theehiv3 Alias:0xbv1 | Github:0xb0rn3"

// Config for the tool's configuration
type Config struct {
	TargetHost       string `json:"target_host"`
	TargetFile       string `json:"target_file"`
	PortRange        string `json:"port_range"`
	ScanTimeout      int    `json:"scan_timeout"`
	MaxConcurrency   int    `json:"max_concurrency"`
	OutputFile       string `json:"output_file"`
	UDPScan          bool   `json:"udp_scan"`
	VulnMapping      bool   `json:"vuln_mapping"`
	TopologyMapping  bool   `json:"topology_mapping"`
	NVDAPIKey        string `json:"nvd_api_key"`
	NmapResultsFile  string `json:"nmap_results_file"`
	OnlyOpenPorts    bool   `json:"only_open_ports"`
	CVEPluginFile    string `json:"cve_plugin_file"`
	PingSweep        bool   `json:"ping_sweep"`
	PingSweepPorts   string `json:"ping_sweep_ports"`
	PingSweepTimeout int    `json:"ping_sweep_timeout"`
}

// EnhancedScanResult with vulnerability data and OS guess
type EnhancedScanResult struct {
	Host            string        `json:"host"`
	Port            int           `json:"port"`
	Protocol        string        `json:"protocol"`
	State           string        `json:"state"`
	Service         string        `json:"service,omitempty"`
	Version         string        `json:"version,omitempty"`
	ResponseTime    time.Duration `json:"response_time"`
	Timestamp       time.Time     `json:"timestamp"`
	Vulnerabilities []string      `json:"vulnerabilities,omitempty"`
	OSGuess         string        `json:"os_guess,omitempty"`
}

// NmapRun represents the root XML structure
type NmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []NmapHost `xml:"host"`
}

// NmapHost represents a host in nmap results
type NmapHost struct {
	Address NmapAddress `xml:"address"`
	Ports   NmapPorts   `xml:"ports"`
}

// NmapAddress represents host address
type NmapAddress struct {
	Addr string `xml:"addr,attr"`
}

// NmapPorts contains port information
type NmapPorts struct {
	Ports []NmapPort `xml:"port"`
}

// NmapPort represents individual port data
type NmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    NmapState   `xml:"state"`
	Service  NmapService `xml:"service"`
}

// NmapState represents port state
type NmapState struct {
	State string `xml:"state,attr"`
}

// NmapService represents service information
type NmapService struct {
	Name    string `xml:"name,attr"`
	Version string `xml:"version,attr"`
}

var (
	config = Config{
		TargetHost:       "",
		TargetFile:       "",
		PortRange:        "1-1000",
		ScanTimeout:      500,
		MaxConcurrency:   100,
		OutputFile:       "scan_results",
		UDPScan:          false,
		VulnMapping:      false,
		TopologyMapping:  false,
		NVDAPIKey:        "",
		NmapResultsFile:  "",
		OnlyOpenPorts:    true,
		CVEPluginFile:    "",
		PingSweep:        false,
		PingSweepPorts:   "80,443,22,3389",
		PingSweepTimeout: 300,
	}
	results      []EnhancedScanResult
	mutex        sync.Mutex
	wg           sync.WaitGroup
	sem          chan struct{}
	scannedPorts int64
	vulnDB       = map[string][]string{
		"http Apache 2.4.49": {"CVE-2021-41773", "CVE-2021-42013"},
		"ssh OpenSSH 7.6":    {"CVE-2018-15473"},
	}
	nvdCache     = sync.Map{}
	customCVEs   = make(map[string][]string)
	httpClient   = &http.Client{Timeout: 10 * time.Second}
	limiter      = rate.NewLimiter(rate.Every(30*time.Second/5), 5)
	serviceToCPE = map[string]struct{ Vendor, Product string }{
		"http":          {"apache", "httpd"}, // Example, actual product can vary
		"https":         {"apache", "httpd"}, // Example
		"ssh":           {"openssh", "openssh"},
		"ftp":           {"proftpd", "proftpd"}, // Example
		"mysql":         {"oracle", "mysql"},
		"dns":           {"isc", "bind"},
		"smtp":          {"postfix", "postfix"},
		"redis":         {"redis", "redis"},
		"rdp":           {"microsoft", "remote_desktop_services"},
		"ms-wbt-server": {"microsoft", "remote_desktop_services"},
		"microsoft-ds":  {"microsoft", "windows"}, // For SMB
		"netbios-ssn":   {"microsoft", "windows"}, // For SMB
		"winrm":         {"microsoft", "windows_remote_management"},
	}
)

func main() {
	printBanner()
	loadConfigFromEnv()
	parseCommandLineFlags()
	loadCustomCVEs()

	if (config.TargetHost != "" || config.TargetFile != "") && config.PortRange != "" {
		if config.NmapResultsFile == "" || (config.NmapResultsFile != "" && (config.TargetHost != "" || config.TargetFile != "")) {
			fmt.Println("ℹ️  Target and ports provided, attempting direct scan...")
			if validateConfig() {
				results = runUltraFastScan()
				if config.VulnMapping && len(results) > 0 {
					performVulnerabilityMapping()
				}
				if config.TopologyMapping && len(results) > 0 {
					generateTopologyMap()
				}
				if len(results) > 0 {
					displayResults()
					saveResults()
				} else {
					fmt.Println("ℹ️  Direct scan completed. No open ports matching criteria found on live hosts (if ping sweep was enabled).")
				}
				fmt.Println("👋 Exiting ReconRaptor v" + VERSION)
				return
			} else {
				fmt.Println("❌ Direct scan aborted due to invalid configuration. Falling back to interactive menu.")
			}
		}
	}

	if config.NmapResultsFile != "" && !(config.TargetHost != "" || config.TargetFile != "") {
		fmt.Printf("ℹ️  Nmap results file '%s' provided, attempting direct parse...\n", config.NmapResultsFile)
		parseNmapResults()
		if len(results) > 0 {
			saveResults()
		}
		fmt.Println("👋 Exiting ReconRaptor v" + VERSION)
		return
	}

	for {
		showMenu()
		choice := getUserChoice()
		switch choice {
		case 1:
			if validateConfig() {
				results = runUltraFastScan()
			} else {
				fmt.Println("❌ Scan aborted due to invalid configuration.")
			}
		case 2:
			configureSettings()
		case 3:
			displayResults()
		case 4:
			saveResults()
		case 5:
			parseNmapResults()
		case 6:
			performVulnerabilityMapping()
		case 7:
			generateTopologyMap()
		case 8:
			exportResults()
		case 9:
			fmt.Println("👋 Exiting ReconRaptor v" + VERSION)
			return
		case 10:
			cidr := askForString("🔍 Enter CIDR/Target to debug parsing (e.g., 192.168.1.0/24): ")
			debugCIDRParsing(cidr)
		default:
			fmt.Println("❌ Invalid option.")
		}
	}
}

func printBanner() {
	fmt.Printf(`
██████╗ ██████╗  ██████╗ ██████╗ ███╗   ██╗██████╗  ██████╗  ██████╗ 
██╔══██╗╚════██╗██╔════╝██╔═████╗████╗  ██║██╔══██╗██╔═████╗██╔════╝ 
██████╔╝ █████╔╝██║     ██║██╔██║██╔██╗ ██║██║  ██║██║██╔██║██║  ███╗
██╔══██╗ ╚═══██╗██║     ████╔╝██║██║╚██╗██║██║  ██║████╔╝██║██║   ██║
██║  ██║██████╔╝╚██████╗╚██████╔╝██║ ╚████║██████╔╝╚██████╔╝╚██████╔╝
╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝  ╚═════╝  ╚═════╝ 𓃦

       Advanced RedTeaming Network Recon Tool v%s
                    By %s
`, VERSION, AUTHORS)
}

func showMenu() {
	fmt.Println("\n=== ReconRaptor 𓃦 - Advanced Network Recon Tool ===")
	fmt.Println("1. 🚀 Run Ultra-Fast Scan (with optional Ping Sweep)")
	fmt.Println("2. 🛠️  Configure Settings")
	fmt.Println("3. 📋 Display Results")
	fmt.Println("4. 💾 Save Results")
	fmt.Println("5. 📄 Parse Nmap Results")
	fmt.Println("6. 🔍 Perform Vulnerability Mapping")
	fmt.Println("7. 🌐 Generate Network Topology")
	fmt.Println("8. 📤 Export Results")
	fmt.Println("9. ❌ Exit")
	fmt.Print("Choose an option: ")
}

func getUserChoice() int {
	var choiceStr string
	fmt.Scanln(&choiceStr)
	choice, err := strconv.Atoi(choiceStr)
	if err != nil {
		return -1 // Invalid input
	}
	return choice
}

func askForBool(prompt string) bool {
	fmt.Print(prompt)
	var input string
	fmt.Scanln(&input)
	return strings.ToLower(input) == "true" || strings.ToLower(input) == "y"
}

func askForString(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func configureSettings() {
	for {
		fmt.Println("\n=== ⚙️ Enhanced Settings ===")
		fmt.Printf(" 1. 🎯 Target Host: %s\n", config.TargetHost)
		fmt.Printf(" 2. 📁 Target File: %s\n", config.TargetFile)
		fmt.Printf(" 3. 🔢 Port Range: %s\n", config.PortRange)
		fmt.Printf(" 4. ⏱️ Scan Timeout (ms): %d\n", config.ScanTimeout)
		fmt.Printf(" 5. 🔄 Max Concurrency: %d\n", config.MaxConcurrency)
		fmt.Printf(" 6. 📄 Output File: %s\n", config.OutputFile)
		fmt.Printf(" 7. 🛡️ UDP Scan: %t\n", config.UDPScan)
		fmt.Printf(" 8. 🔍 Vulnerability Mapping: %t\n", config.VulnMapping)
		fmt.Printf(" 9. 🌐 Topology Mapping: %t\n", config.TopologyMapping)
		fmt.Printf("10. 🔑 NVD API Key: %s\n", maskAPIKey(config.NVDAPIKey))
		fmt.Printf("11. 📁 Nmap Results File: %s\n", config.NmapResultsFile)
		fmt.Printf("12. 🎯 Only Open Ports (Display/Nmap Parse): %t\n", config.OnlyOpenPorts)
		fmt.Printf("13. 📄 CVE Plugin File: %s\n", config.CVEPluginFile)
		fmt.Printf("14. 📡 Ping Sweep Enabled: %t\n", config.PingSweep)
		fmt.Printf("15. 🎯 Ping Sweep Ports: %s\n", config.PingSweepPorts)
		fmt.Printf("16. ⏱️ Ping Sweep Timeout (ms): %d\n", config.PingSweepTimeout)
		fmt.Println(" 0. ◀️ Back to main menu")
		fmt.Print("⚙️ Choose a setting to edit: ")

		choice := getUserChoice()
		switch choice {
		case 1:
			config.TargetHost = askForString("🎯 Enter target host(s) (comma-separated or CIDR): ")
		case 2:
			config.TargetFile = askForString("📁 Enter target file path: ")
		case 3:
			config.PortRange = askForString("🔢 Enter port range (e.g., 1-1000): ")
		case 4:
			fmt.Print("⏱️ Enter scan timeout (ms): ")
			var scanTimeout int
			fmt.Scanln(&scanTimeout)
			if scanTimeout > 0 {
				config.ScanTimeout = scanTimeout
			}
		case 5:
			fmt.Print("🔄 Enter max concurrency: ")
			var maxConcurrency int
			fmt.Scanln(&maxConcurrency)
			if maxConcurrency > 0 {
				config.MaxConcurrency = maxConcurrency
			}
		case 6:
			config.OutputFile = askForString("📄 Enter output file name: ")
		case 7:
			config.UDPScan = askForBool("🛡️ Enable UDP scanning? (true/false): ")
		case 8:
			config.VulnMapping = askForBool("🔍 Enable vulnerability mapping? (true/false): ")
		case 9:
			config.TopologyMapping = askForBool("🌐 Enable network topology mapping? (true/false): ")
		case 10:
			config.NVDAPIKey = askForString("🔑 Enter NVD API Key: ")
		case 11:
			config.NmapResultsFile = askForString("📁 Enter Nmap results file path: ")
		case 12:
			config.OnlyOpenPorts = askForBool("🎯 Show only open ports in display/Nmap parse? (true/false): ")
		case 13:
			config.CVEPluginFile = askForString("📄 Enter CVE plugin file path: ")
		case 14:
			config.PingSweep = askForBool(fmt.Sprintf("📡 Enable TCP Ping Sweep (current: %t)? (true/false): ", config.PingSweep))
		case 15:
			config.PingSweepPorts = askForString(fmt.Sprintf("🎯 Enter ports for TCP Ping Sweep (current: %s): ", config.PingSweepPorts))
		case 16:
			fmt.Printf("⏱️ Enter Ping Sweep timeout per port (ms) (current: %d): ", config.PingSweepTimeout)
			var psTimeout int
			fmt.Scanln(&psTimeout)
			if psTimeout > 0 {
				config.PingSweepTimeout = psTimeout
			}
		case 0:
			return
		default:
			fmt.Println("❌ Invalid choice.")
		}
	}
}

func maskAPIKey(key string) string {
	if len(key) == 0 {
		return "Not set"
	}
	if len(key) <= 8 {
		return strings.Repeat("*", len(key))
	}
	return key[:4] + strings.Repeat("*", len(key)-8) + key[len(key)-4:]
}

func parsePortRange(portRangeStr string) []int {
	var ports []int
	seen := make(map[int]bool)
	ranges := strings.Split(portRangeStr, ",")
	for _, r := range ranges {
		r = strings.TrimSpace(r)
		if strings.Contains(r, "-") {
			parts := strings.SplitN(r, "-", 2)
			if len(parts) == 2 {
				start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
				if err1 == nil && err2 == nil && start > 0 && end > 0 && start <= 65535 && end <= 65535 && start <= end {
					for i := start; i <= end; i++ {
						if !seen[i] {
							ports = append(ports, i)
							seen[i] = true
						}
					}
				} else {
					fmt.Printf("⚠️  Warning: Invalid port range values in '%s'. Must be 1-65535.\n", r)
				}
			} else {
				fmt.Printf("⚠️  Warning: Invalid port range format '%s'.\n", r)
			}
		} else {
			port, err := strconv.Atoi(r)
			if err == nil && port > 0 && port <= 65535 {
				if !seen[port] {
					ports = append(ports, port)
					seen[port] = true
				}
			} else {
				fmt.Printf("⚠️  Warning: Invalid port number '%s'. Must be 1-65535.\n", r)
			}
		}
	}
	return ports
}

func parseTargets(targets string, targetFile string) []string {
	var parsedTargets []string
	tempTargets := []string{}

	if targetFile != "" {
		fmt.Printf("📁 Reading targets from file: %s\n", targetFile)
		file, err := os.Open(targetFile)
		if err != nil {
			fmt.Printf("❌ Error opening target file: %v\n", err)
			// Continue to parse TargetHost if provided
		} else {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			lineNum := 0
			for scanner.Scan() {
				lineNum++
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					tempTargets = append(tempTargets, line)
				}
			}
			if err := scanner.Err(); err != nil {
				fmt.Printf("❌ Error reading target file: %v\n", err)
			}
		}
	}

	if targets != "" {
		parts := strings.Split(targets, ",")
		for _, part := range parts {
			trimmedPart := strings.TrimSpace(part)
			if trimmedPart != "" {
				tempTargets = append(tempTargets, trimmedPart)
			}
		}
	}

	seen := make(map[string]bool)
	for _, targetEntry := range tempTargets {
		expanded := parseSingleTarget(targetEntry)
		for _, t := range expanded {
			if !seen[t] {
				parsedTargets = append(parsedTargets, t)
				seen[t] = true
			}
		}
	}

	if len(parsedTargets) > 0 {
		fmt.Printf("📊 Total unique targets to process (after CIDR expansion & deduplication): %d\n", len(parsedTargets))
	}
	return parsedTargets
}

func parseSingleTarget(target string) []string {
	target = strings.TrimSpace(target)
	if strings.Contains(target, "/") {
		ip, ipnet, err := net.ParseCIDR(target)
		if err != nil {
			// Try to parse as single IP if CIDR fails (e.g. hostname with '/')
			if parsedIP := net.ParseIP(target); parsedIP != nil {
				return []string{parsedIP.String()}
			}
			// Assume it's a hostname or invalid
			return []string{target}
		}

		var ips []string
		// Iterate through IP addresses in CIDR range
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
			ips = append(ips, ip.String())
			// Safety break for extremely large ranges (though CIDR parsing should handle this)
			// This specific loop might be slow for large IPv6 ranges.
			// Consider a more optimized way or Nmap's host generation if performance on huge CIDRs is key.
			if len(ips) >= 65536 { // Limit to a /16 equivalent for safety in this simple iteration
				fmt.Printf("⚠️  Warning: CIDR %s is very large, limiting to first %d IPs from expansion.\n", target, len(ips))
				break
			}
		}

		// For typical IPv4 CIDRs (/25 to /30), remove network and broadcast if they are part of the generated list
		// and the network is not a /31 or /32
		ones, bits := ipnet.Mask.Size()
		if bits == 32 && ones < 31 && len(ips) > 2 {
			if len(ips) > 0 && ips[0] == ipnet.IP.Mask(ipnet.Mask).String() { // Network address
				ips = ips[1:]
			}
			if len(ips) > 0 { // Broadcast address
				lastIP := make(net.IP, len(ipnet.IP))
				copy(lastIP, ipnet.IP)
				for i := range ipnet.Mask {
					lastIP[i] = ipnet.IP[i] | ^ipnet.Mask[i]
				}
				if ips[len(ips)-1] == lastIP.String() {
					ips = ips[:len(ips)-1]
				}
			}
		}
		return ips
	}

	// Handle single IP or hostname
	if parsedIP := net.ParseIP(target); parsedIP != nil {
		return []string{parsedIP.String()}
	}
	return []string{target} // Assume it's a hostname
}

// incIP increments an IP address.
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// isHostAliveTCP checks if a host is responsive on any of the specified TCP ports.
func isHostAliveTCP(host string, ports []int, timeout time.Duration) bool {
	if len(ports) == 0 {
		return true // No ports to check, assume alive or let port scan fail
	}
	for _, port := range ports {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		dialer := net.Dialer{}
		conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
		cancel() // Ensure cancel is called
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

func scanTCPPort(host string, port int) *EnhancedScanResult {
	timeout := time.Duration(config.ScanTimeout) * time.Millisecond
	start := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))

	if err != nil {
		return nil
	}
	defer conn.Close()

	result := &EnhancedScanResult{
		Host:         host,
		Port:         port,
		Protocol:     "tcp",
		State:        "open",
		ResponseTime: time.Since(start),
		Timestamp:    time.Now().UTC(),
	}

	serviceDetectionTimeout := timeout / 2
	if serviceDetectionTimeout < 100*time.Millisecond {
		serviceDetectionTimeout = 100 * time.Millisecond
	}
	result.Service, result.Version = detectServiceWithTimeout(conn, port, "tcp", serviceDetectionTimeout)
	result.OSGuess = guessOS(result)

	return result
}

func scanUDPPort(host string, port int) *EnhancedScanResult {
	timeout := time.Duration(config.ScanTimeout) * time.Millisecond
	start := time.Now()

	// For UDP, DialTimeout is generally preferred as it can attempt resolution and connection.
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil // Cannot reach host or resolve
	}
	defer conn.Close()

	probe := getUDPProbe(port)
	// Set a deadline for the write operation
	conn.SetWriteDeadline(time.Now().Add(timeout / 3)) // Shorter timeout for write
	_, err = conn.Write(probe)
	if err != nil {
		return nil // Write error
	}

	buffer := make([]byte, 2048) // Increased buffer for some UDP services
	// Set a deadline for the read operation
	readDeadlineTimeout := timeout / 2
	if readDeadlineTimeout < 100*time.Millisecond { // Minimum reasonable read timeout for UDP
		readDeadlineTimeout = 100 * time.Millisecond
	}
	conn.SetReadDeadline(time.Now().Add(readDeadlineTimeout))

	n, err := conn.Read(buffer)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// For common UDP ports, a timeout might indicate "open|filtered"
			if isCommonUDPPort(port) {
				result := &EnhancedScanResult{
					Host:         host,
					Port:         port,
					Protocol:     "udp",
					State:        "open|filtered",
					ResponseTime: time.Since(start),
					Timestamp:    time.Now().UTC(),
				}
				// Attempt service detection even for open|filtered, might get default
				serviceDetectionTimeout := readDeadlineTimeout / 2
				if serviceDetectionTimeout < 50*time.Millisecond {
					serviceDetectionTimeout = 50 * time.Millisecond
				}
				result.Service, result.Version = detectServiceWithTimeout(nil, port, "udp", serviceDetectionTimeout)
				result.OSGuess = guessOS(result)
				return result
			}
		}
		return nil // Other read errors or timeout on non-common port
	}

	if n > 0 {
		result := &EnhancedScanResult{
			Host:         host,
			Port:         port,
			Protocol:     "udp",
			State:        "open",
			ResponseTime: time.Since(start),
			Timestamp:    time.Now().UTC(),
		}
		serviceDetectionTimeout := readDeadlineTimeout / 2
		if serviceDetectionTimeout < 50*time.Millisecond {
			serviceDetectionTimeout = 50 * time.Millisecond
		}

		// Specific check for DNS before generic detection
		if port == 53 && n >= 12 { // DNS header is 12 bytes
			isResponse := (buffer[2] & 0x80) != 0 // QR bit (1 = response)
			opCode := (buffer[2] >> 3) & 0x0F    // Opcode
			responseCode := buffer[3] & 0x0F     // RCODE
			if isResponse && opCode == 0 {       // Standard query response
				result.Service = "dns"
				if responseCode == 0 {
					result.Version = "response NOERROR"
				} else {
					result.Version = fmt.Sprintf("response RCODE %d", responseCode)
				}
			}
		}

		detectedService, detectedVersion := detectServiceWithTimeout(nil, port, "udp", serviceDetectionTimeout)
		// Prefer specific detection (like DNS) if already set and valid
		if result.Service == "dns" && strings.HasPrefix(result.Version, "response") {
			// Keep it
		} else if detectedService != "unknown" { // Otherwise, use generic detection if it found something
			result.Service = detectedService
			result.Version = detectedVersion
		}
		// If still "unknown", it will remain from the default map in detectService.

		result.OSGuess = guessOS(result)
		return result
	}
	return nil
}

type ServiceProbe struct {
	Name    string
	Probe   []byte
	Matcher func([]byte) (string, string) // Returns service, version
}

var enhancedProbes = map[int]ServiceProbe{
	22: {
		Name:  "SSH",
		Probe: []byte("SSH-2.0-ReconRaptor\r\n"), // Simple probe
		Matcher: func(response []byte) (string, string) {
			respStr := string(response)
			// SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1
			if strings.HasPrefix(respStr, "SSH-") {
				lines := strings.SplitN(respStr, "\r\n", 2) // Get the first line
				return "ssh", strings.TrimSpace(lines[0])
			}
			return "ssh", "unknown"
		},
	},
	25: {
		Name:  "SMTP",
		Probe: []byte("EHLO reconraptor.local\r\n"),
		Matcher: func(response []byte) (string, string) {
			respStr := string(response)
			// Look for "220" greeting
			if strings.Contains(respStr, "220 ") {
				lines := strings.Split(respStr, "\r\n")
				for _, line := range lines {
					if strings.HasPrefix(line, "220 ") {
						// 220 mx.google.com ESMTP ...
						return "smtp", strings.TrimSpace(strings.TrimPrefix(line, "220 "))
					}
				}
				return "smtp", "220 greeting" // Generic if specific banner not parsed
			}
			return "smtp", "unknown"
		},
	},
	// Note: Port 80 (HTTP) and 443 (HTTPS) are often better handled by specific HTTP/TLS logic.
	// The HTTPProbe below is a fallback. For 443, this basic probe won't do TLS.
}

// Helper function to extract server header from HTTP response
func extractServerHeader(response string) string {
	lines := strings.Split(response, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			return strings.TrimSpace(line[len("Server:"):])
		}
	}
	return "" // Return empty if not found, "unknown" will be default
}

type HTTPProbe struct{}

func (p *HTTPProbe) Detect(conn net.Conn) (string, string) { // Returns service, version
	// Send a HEAD request. Some servers might not like HEAD, or might require Host.
	// Use a short timeout for this specific probe.
	conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	_, err := conn.Write([]byte("HEAD / HTTP/1.1\r\nHost: reconraptor\r\nUser-Agent: ReconRaptor-Scanner\r\nConnection: close\r\n\r\n"))
	if err != nil {
		return "http", "unknown (write_fail)"
	}

	buffer := make([]byte, 2048) // Buffer for response headers
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buffer)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "http", "timeout" // Server connected but didn't respond in time
		}
		// EOF might happen if server closes connection right after sending response (or no response)
		if err == io.EOF && n > 0 { // Process data if some was read before EOF
			response := string(buffer[:n])
			if strings.HasPrefix(response, "HTTP/") {
				server := extractServerHeader(response)
				if server != "" {
					return "http", server
				}
				return "http", "generic HTTP response"
			}
		}
		return "http", "unknown (read_fail)"
	}

	response := string(buffer[:n])
	if strings.HasPrefix(response, "HTTP/") {
		server := extractServerHeader(response)
		if server != "" {
			return "http", server
		}
		return "http", "generic HTTP response"
	}
	// If it's not HTTP, but we got a response on an HTTP port, it's unusual.
	return "unknown", "non-HTTP response on HTTP port"
}

func detectServiceWithTimeout(conn net.Conn, port int, protocol string, timeout time.Duration) (string, string) {
	// Default service mapping (expanded)
	defaultServices := map[int]string{
		21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp",
		80: "http", 110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
		138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap",
		389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps", 514: "syslog",
		587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s", 1080: "socks",
		1433: "mssql", 1521: "oracle", 1723: "pptp", 2049: "nfs", 3000: "http-alt",
		3268: "globalcatLDAP", 3269: "globalcatLDAPssl", 3306: "mysql", 3389: "ms-wbt-server", // RDP
		5060: "sip", 5061: "sips", 5222: "xmpp-client", 5353: "mdns", 5432: "postgresql",
		5900: "vnc", 5985: "winrm", 5986: "winrm-ssl", 6379: "redis", 8000: "http-alt",
		8080: "http-proxy", 8443: "https-alt", 27017: "mongodb",
	}

	detectedService, defaultExists := defaultServices[port]
	if !defaultExists {
		detectedService = "unknown"
	}
	detectedVersion := "unknown"

	if protocol == "tcp" && conn != nil {
		// Set overall deadline for detection attempt on this connection
		conn.SetDeadline(time.Now().Add(timeout))
		defer conn.SetDeadline(time.Time{}) // Clear deadline

		// Try specific probe from enhancedProbes
		if probe, exists := enhancedProbes[port]; exists {
			conn.SetWriteDeadline(time.Now().Add(timeout / 2)) // Timeout for writing probe
			if _, err := conn.Write(probe.Probe); err == nil {
				buffer := make([]byte, 4096)
				conn.SetReadDeadline(time.Now().Add(timeout / 2)) // Timeout for reading response
				if n, errRead := conn.Read(buffer); errRead == nil && n > 0 {
					return probe.Matcher(buffer[:n])
				}
			}
		}

		// Fallback to HTTP probe for common HTTP/HTTPS ports if not specifically handled
		isHTTPPort := (port == 80 || port == 8080 || port == 8000 || port == 3000)
		isHTTPSPort := (port == 443 || port == 8443) // Basic HTTP probe won't do TLS for HTTPS

		if isHTTPPort { // For HTTPS ports, HTTPProbe is not ideal without TLS handling.
			// If enhancedProbes had a 443 entry, it would take precedence.
			// If we are here for port 443, it means no specific probe matched,
			// and we are falling back. An HTTP HEAD to 443 will usually fail or be incorrect.
			return (&HTTPProbe{}).Detect(conn)
		}
		if isHTTPSPort && detectedService == "https" { // If it's a known HTTPS port by default
			// Our basic HTTPProbe won't establish TLS.
			// Return "https" and "unknown" as version, rather than trying an HTTP probe.
			return "https", "requires TLS handshake"
		}
	} else if protocol == "udp" {
		// For UDP, conn is often nil or not useful for generic banner grabbing here.
		// Specific UDP probes (like DNS in scanUDPPort) handle their own logic.
		// Return the default mapped service for UDP if no earlier specific detection.
		return detectedService, "unknown (UDP)"
	}

	// If no specific probe matched or it's not TCP with a conn, return default.
	return detectedService, detectedVersion
}

func getUDPProbe(port int) []byte {
	switch port {
	case 53: // DNS Standard Query (example.com A record)
		return []byte{
			0xAA, 0xBB, /* Transaction ID */
			0x01, 0x00, /* Flags: 0x0100 Standard query */
			0x00, 0x01, /* Questions: 1 */
			0x00, 0x00, /* Answer RRs: 0 */
			0x00, 0x00, /* Authority RRs: 0 */
			0x00, 0x00, /* Additional RRs: 0 */
			0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, /* Name: example */
			0x03, 0x63, 0x6f, 0x6d, /* Name: com */
			0x00,       /* Null terminator */
			0x00, 0x01, /* Type: A */
			0x00, 0x01, /* Class: IN */
		}
	case 123: // NTP Client Request
		// Basic NTP v3 client request packet
		return []byte{0x1B, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	case 161: // SNMPv1 GetRequest (public community, sysDescr.0)
		return []byte{
			0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
			0xa0, 0x19, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01,
			0x00, 0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05,
			0x00,
		} // OID for sysDescr.0: 1.3.6.1.2.1.1.1.0
	default:
		return []byte("ReconRaptor UDP Probe") // Generic probe
	}
}

func isCommonUDPPort(port int) bool {
	commonPorts := []int{
		53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 1900, 4500, 5353,
	}
	for _, p := range commonPorts {
		if p == port {
			return true
		}
	}
	return false
}

func guessOS(result *EnhancedScanResult) string {
	serviceLower := strings.ToLower(result.Service)
	versionLower := strings.ToLower(result.Version)

	if strings.Contains(serviceLower, "http") {
		if strings.Contains(versionLower, "iis") || strings.Contains(versionLower, "microsoft-httpapi") {
			return "Windows"
		} else if strings.Contains(versionLower, "apache") {
			// Apache can run on Windows, but more common on Linux. Check for clues.
			if strings.Contains(versionLower, "win32") || strings.Contains(versionLower, "win64") {
				return "Windows"
			}
			return "Linux/Unix"
		} else if strings.Contains(versionLower, "nginx") {
			return "Linux/Unix"
		}
	}
	if strings.Contains(serviceLower, "ssh") {
		if strings.Contains(versionLower, "openssh") && !strings.Contains(versionLower, "windows") { // OpenSSH for Windows exists
			return "Linux/Unix"
		} else if strings.Contains(versionLower, "dropbear") {
			return "Linux/Embedded"
		}
	}
	if serviceLower == "ms-wbt-server" || serviceLower == "rdp" { // RDP
		return "Windows"
	}
	if serviceLower == "microsoft-ds" || serviceLower == "netbios-ssn" { // SMB/CIFS
		return "Windows" // Could be Samba on Linux, but Windows is primary
	}
	if serviceLower == "winrm" || strings.Contains(serviceLower, "ws-management") {
		return "Windows"
	}

	// Guess based on common Windows ports if service/version is generic
	switch result.Port {
	case 135, 139, 445, 3389, 5985, 5986:
		// If OS is still unknown, these ports strongly suggest Windows
		if result.OSGuess == "" || result.OSGuess == "Unknown" {
			return "Windows (likely)"
		}
	}
	return "Unknown"
}

func queryNVD(cpe string) ([]string, error) {
	if err := limiter.Wait(context.Background()); err != nil {
		return nil, fmt.Errorf("rate limiter error: %w", err)
	}

	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=%s&resultsPerPage=100", cpe) // Get up to 100
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create NVD request: %w", err)
	}

	req.Header.Set("User-Agent", "ReconRaptor/"+VERSION)
	if config.NVDAPIKey != "" {
		req.Header.Set("apiKey", config.NVDAPIKey)
		// Adjust limiter if API key is present (assuming higher rate limit)
		// This simple adjustment assumes only one state for the limiter.
		// If API key can be added/removed mid-session affecting different calls,
		// this needs to be managed more carefully or the limiter re-initialized.
		// For now, let's assume it's set at start or not at all for a given mapping run.
		if limiter.Limit() < 1 { // If current limit is less than 1 req/sec (approx 50/30s)
			limiter.SetLimit(rate.Every(30 * time.Second / 50)) // 50 req / 30 sec
			limiter.SetBurst(50)
		}
	} else {
		// Ensure it's the base rate if no key
		limiter.SetLimit(rate.Every(30 * time.Second / 5)) // 5 req / 30 sec
		limiter.SetBurst(5)
		fmt.Println("⚠️  Warning: No NVD API key. Rate limited. See: https://nvd.nist.gov/developers/request-an-api-key")
	}
	
	var cves []string
	maxRetries := 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		resp, err := httpClient.Do(req)
		if err != nil {
			if attempt == maxRetries-1 {
				return nil, fmt.Errorf("NVD request failed after %d attempts: %w", maxRetries, err)
			}
			time.Sleep(time.Duration(math.Pow(2, float64(attempt))) * time.Second) // Exponential backoff
			continue
		}

		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close() // Close body immediately after read or on error
		if readErr != nil {
			return nil, fmt.Errorf("failed to read NVD response body: %w", readErr)
		}
		
		if resp.StatusCode == http.StatusOK {
			var nvdResp struct {
				Vulnerabilities []struct {
					CVE struct {
						ID string `json:"id"`
					} `json:"cve"`
				} `json:"vulnerabilities"`
				// TotalResults int `json:"totalResults"` // Can check this if pagination is needed
			}
			if err := json.Unmarshal(body, &nvdResp); err != nil {
				return nil, fmt.Errorf("failed to parse NVD JSON: %w. Body: %s", err, string(body))
			}
			for _, vuln := range nvdResp.Vulnerabilities {
				cves = append(cves, vuln.CVE.ID)
			}
			return cves, nil
		} else if resp.StatusCode == http.StatusNotFound {
			return []string{}, nil // No CVEs found for this CPE is not an error
		} else if resp.StatusCode == http.StatusForbidden {
			errorMsg := "NVD API access forbidden (403)"
			if config.NVDAPIKey == "" {
				errorMsg += " - an API key is highly recommended or required."
			} else {
				errorMsg += " - check your API key or request quota."
			}
			errorMsg += fmt.Sprintf(" Response: %s", string(body))
			return nil, fmt.Errorf(errorMsg)
		} else if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == 429 {
			retryAfterStr := resp.Header.Get("Retry-After")
			var waitTime time.Duration
			if retryAfterSec, errConv := strconv.Atoi(retryAfterStr); errConv == nil {
				waitTime = time.Duration(retryAfterSec) * time.Second
			} else {
				waitTime = time.Duration(math.Pow(2, float64(attempt+1))) * time.Second // Exponential backoff
			}
			if waitTime > 60*time.Second { waitTime = 60*time.Second } // Cap wait time
			
			fmt.Printf("⏳ NVD API rate limited (%d). Waiting %v before retry %d/%d for CPE: %s\n", resp.StatusCode, waitTime, attempt+1, maxRetries, cpe)
			time.Sleep(waitTime)
			if attempt == maxRetries-1 {
				return nil, fmt.Errorf("NVD API rate limit exceeded after %d retries. CPE: %s. Body: %s", maxRetries, cpe, string(body))
			}
			continue // Retry
		} else { // Other HTTP errors
			if attempt == maxRetries-1 {
				return nil, fmt.Errorf("NVD API error, status %d for CPE %s. Body: %s", resp.StatusCode, cpe, string(body))
			}
			time.Sleep(time.Duration(math.Pow(2, float64(attempt))) * time.Second) // Exponential backoff
		}
	}
	return nil, fmt.Errorf("NVD query failed after max retries for CPE: %s", cpe)
}


func findSimilarKey(key string) string {
	parts := strings.Fields(strings.ToLower(key)) // Split by space, lowercase
	if len(parts) < 1 {
		return ""
	}
	serviceName := parts[0]
	// versionPart := ""
	// if len(parts) > 1 {
	// 	versionPart = strings.Join(parts[1:], " ")
	// }

	var bestMatch string
	highestSimilarity := -1 // Use -1 to ensure any match is better

	for dbKey := range vulnDB {
		dbKeyLower := strings.ToLower(dbKey)
		dbParts := strings.Fields(dbKeyLower)
		if len(dbParts) < 1 {
			continue
		}
		dbServiceName := dbParts[0]
		// dbVersionPart := ""
		// if len(dbParts) > 1 {
		// 	dbVersionPart = strings.Join(dbParts[1:], " ")
		// }

		currentSimilarity := 0
		if serviceName == dbServiceName {
			currentSimilarity += 10 // Strong match for service name
			// Simple substring match for version for now
			// This could be improved with semantic version comparison
			// For example, "Apache 2.4" should match "Apache 2.4.51"
			// For now, direct key match is primary. This is for very fuzzy.
			// if versionPart != "" && dbVersionPart != "" {
			// 	if strings.Contains(versionPart, dbVersionPart) || strings.Contains(dbVersionPart, versionPart) {
			// 		currentSimilarity += 5
			// 	}
			// }
		}

		if currentSimilarity > highestSimilarity {
			highestSimilarity = currentSimilarity
			bestMatch = dbKey
		}
	}

	if highestSimilarity >= 10 { // Require at least service name match
		return bestMatch
	}
	return ""
}

func loadCustomCVEs() {
	if config.CVEPluginFile == "" {
		return
	}
	file, err := os.Open(config.CVEPluginFile)
	if err != nil {
		fmt.Printf("❌ Error opening CVE plugin file '%s': %v\n", config.CVEPluginFile, err)
		return
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		fmt.Printf("❌ Error reading CVE plugin file '%s': %v\n", config.CVEPluginFile, err)
		return
	}
	// Expect format: {"service version": ["CVE-...", ...]}
	// e.g., {"Apache httpd 2.4.50": ["CVE-XXXX-YYYY"], "OpenSSH 8.2": ["CVE-..."]}
	if err := json.Unmarshal(data, &customCVEs); err != nil {
		fmt.Printf("❌ Error parsing CVE plugin JSON from '%s': %v\n", config.CVEPluginFile, err)
		fmt.Println("   Ensure it's a map of 'product version': ['CVE-ID', ...]")
		return
	}
	fmt.Printf("✅ Loaded %d custom CVE mappings from %s\n", len(customCVEs), config.CVEPluginFile)
}

func runUltraFastScan() []EnhancedScanResult {
	fmt.Println("🚀 Starting optimized ultra-fast scan...")
	results = nil // Clear previous results for a new scan
	atomic.StoreInt64(&scannedPorts, 0)

	initialHosts := parseTargets(config.TargetHost, config.TargetFile)
	if len(initialHosts) == 0 {
		fmt.Println("❌ No valid targets found. Please check your target configuration.")
		return nil
	}

	var liveHosts []string
	if config.PingSweep {
		fmt.Println("🔎 Performing TCP Ping Sweep to identify live hosts...")
		pingPortsToTry := parsePortRange(config.PingSweepPorts)
		if len(pingPortsToTry) == 0 {
			fmt.Println("⚠️ No valid ports specified for ping sweep, defaulting to 80,443,22,3389.")
			pingPortsToTry = []int{80, 443, 22, 3389} // Fallback default
		}
		tcpPingTimeout := time.Duration(config.PingSweepTimeout) * time.Millisecond
		if tcpPingTimeout <= 0 {
			fmt.Println("⚠️ Invalid ping sweep timeout, defaulting to 300ms.")
			tcpPingTimeout = 300 * time.Millisecond
		}

		var pingWg sync.WaitGroup
		var liveHostsMutex sync.Mutex
		pingSemMax := config.MaxConcurrency
		if pingSemMax > 200 { pingSemMax = 200 }
		if pingSemMax <= 0 { pingSemMax = 50 }
		pingSem := make(chan struct{}, pingSemMax)
		
		fmt.Printf("📡 Pinging %d hosts on TCP ports %v with timeout %v (concurrency: %d)...\n", len(initialHosts), pingPortsToTry, tcpPingTimeout, pingSemMax)
		
		var pingedCountAtomic int64
		totalToPing := len(initialHosts)
		pingProgressTicker := time.NewTicker(1 * time.Second)
		var displayMutexPing sync.Mutex

		go func() {
			for range pingProgressTicker.C {
				current := atomic.LoadInt64(&pingedCountAtomic)
				if totalToPing == 0 { continue }
				percentage := float64(current) / float64(totalToPing) * 100
				
				liveHostsMutex.Lock()
				foundLive := len(liveHosts)
				liveHostsMutex.Unlock()

				displayMutexPing.Lock()
				// \r to return to beginning of line, \033[K to clear to end of line
				fmt.Printf("\r\033[K📡 Ping Sweep: %d/%d (%.1f%%) | Live: %d found", current, totalToPing, percentage, foundLive)
				displayMutexPing.Unlock()
				if current >= int64(totalToPing) { // Stop condition for ticker
					pingProgressTicker.Stop()
					return
				}
			}
		}()

		for _, host := range initialHosts {
			pingWg.Add(1)
			go func(h string) {
				defer pingWg.Done()
				pingSem <- struct{}{}
				defer func() { <-pingSem }()
				if isHostAliveTCP(h, pingPortsToTry, tcpPingTimeout) {
					liveHostsMutex.Lock()
					liveHosts = append(liveHosts, h)
					liveHostsMutex.Unlock()
				}
				atomic.AddInt64(&pingedCountAtomic, 1)
			}(host)
		}
		pingWg.Wait()
		// Ensure ticker is stopped if it hasn't already by reaching total
		pingProgressTicker.Stop() 
		// Allow a moment for the final progress update from the goroutine to render
		time.Sleep(150 * time.Millisecond) 

		finalLiveCount := len(liveHosts)
		displayMutexPing.Lock()
		fmt.Printf("\r\033[K📡 Ping Sweep Complete. Found %d live hosts out of %d initial targets.\n", finalLiveCount, totalToPing)
		displayMutexPing.Unlock()

		if finalLiveCount == 0 {
			fmt.Println("❌ No live hosts found after ping sweep. Aborting port scan.")
			return nil
		}
	} else {
		liveHosts = initialHosts
		// fmt.Println("ℹ️ Ping sweep disabled. Proceeding with all specified targets.")
	}

	hostsToScan := liveHosts
	portsToScan := parsePortRange(config.PortRange)
	if len(portsToScan) == 0 {
		fmt.Println("❌ No valid ports found. Please check your port range configuration.")
		return nil
	}
	if len(hostsToScan) == 0 { // Should be caught by ping sweep logic if enabled
		fmt.Println("❌ No hosts to scan.")
		return nil
	}


	totalScansPerProtocol := int64(len(hostsToScan) * len(portsToScan))
	totalOperations := totalScansPerProtocol
	if config.UDPScan {
		totalOperations *= 2
	}
	
	fmt.Printf("📊 Scanning %d live hosts across %d ports. Total TCP scan points: %d. Total operations (TCP+UDP if enabled): %d\n",
		len(hostsToScan), len(portsToScan), totalScansPerProtocol, totalOperations)

	if totalOperations == 0 {
		fmt.Println("ℹ️ No scan operations to perform.")
		return nil
	}
	
	if totalOperations > 50000 && len(hostsToScan) > 10 { // Adjust threshold for warning
		fmt.Printf("⚠️  Large scan detected (%d operations). This may take significant time.\n", totalOperations)
		if !askForBool("Continue? (y/N): ") {
			fmt.Println("❌ Scan cancelled by user.")
			return nil
		}
	}

	sem = make(chan struct{}, config.MaxConcurrency)
	startScanTime := time.Now()
	scanProgressTicker := time.NewTicker(1 * time.Second)
	defer scanProgressTicker.Stop()
	var displayMutexScan sync.Mutex

	go func() {
		for range scanProgressTicker.C {
			current := atomic.LoadInt64(&scannedPorts)
			if totalOperations == 0 { continue }
			if current >= totalOperations { // Stop condition for ticker
				scanProgressTicker.Stop()
				return
			}
			if current > 0 {
				percentage := float64(current) / float64(totalOperations) * 100
				elapsed := time.Since(startScanTime)
				rate := 0.0
				if elapsed.Seconds() > 0 {
					rate = float64(current) / elapsed.Seconds()
				}
				var eta time.Duration
				if rate > 0 && current < totalOperations {
					eta = time.Duration(float64(totalOperations-current)/rate) * time.Second
				}
				
				mutex.Lock() // Protect access to 'results' for len()
				foundOpenCount := len(results)
				mutex.Unlock()

				displayMutexScan.Lock()
				fmt.Printf("\r\033[K🔍 Port Scan: %d/%d (%.1f%%) | Rate: %.0f ops/s | ETA: %v | Found: %d open",
					current, totalOperations, percentage, rate, eta.Round(time.Second), foundOpenCount)
				displayMutexScan.Unlock()
			}
		}
	}()

	// Prioritize common ports
	commonPorts := []int{80, 443, 21, 22, 23, 25, 53, 110, 135, 139, 143, 445, 993, 995, 1723, 3306, 3389, 5900, 5985, 8080}
	priorityPorts := []int{}
	regularPorts := []int{}
	portSet := make(map[int]bool)
	for _, p := range portsToScan { portSet[p] = true }
	for _, p := range commonPorts {
		if portSet[p] {
			priorityPorts = append(priorityPorts, p)
			delete(portSet, p)
		}
	}
	for p := range portSet { regularPorts = append(regularPorts, p) }
	orderedPorts := append(priorityPorts, regularPorts...)


	for _, host := range hostsToScan {
		for _, port := range orderedPorts {
			wg.Add(1)
			go scanPortWithRecovery(host, port, &displayMutexScan)
		}
	}

	wg.Wait()
	scanProgressTicker.Stop() // Explicitly stop after wait
	time.Sleep(150 * time.Millisecond) // Allow final progress update to render

	finalScannedCount := atomic.LoadInt64(&scannedPorts)
	if finalScannedCount > totalOperations { finalScannedCount = totalOperations } // Cap for display
	
	mutex.Lock()
	finalOpenCount := len(results)
	mutex.Unlock()

	displayMutexScan.Lock()
	fmt.Printf("\r\033[K🔍 Port Scan Complete: %d/%d operations. Found %d open ports/services.                             \n", finalScannedCount, totalOperations, finalOpenCount)
	displayMutexScan.Unlock()

	elapsedScanTime := time.Since(startScanTime)
	fmt.Printf("✅ Port scan completed in %v\n", elapsedScanTime.Round(time.Second))
	if totalOperations > 0 && elapsedScanTime.Seconds() > 0 {
		fmt.Printf("⚡ Average scan rate: %.0f operations/second\n", float64(totalOperations)/elapsedScanTime.Seconds())
	}

	if finalOpenCount > 0 {
		serviceCount := make(map[string]int)
		for _, res := range results { // Iterate over the collected results
			if strings.ToLower(res.State) == "open" || strings.Contains(strings.ToLower(res.State), "open|filtered") {
				serviceKey := res.Service
				if serviceKey == "" { serviceKey = "unknown_service"}
				serviceCount[serviceKey]++
			}
		}
		if len(serviceCount) > 0 {
			fmt.Println("🎯 Top services discovered:")
			// Could sort services by count here for better display
			for service, count := range serviceCount {
				fmt.Printf("    %s: %d\n", service, count)
			}
		}
	}
	return results
}

func scanPortWithRecovery(host string, port int, displayMutex *sync.Mutex) {
	defer wg.Done()
	defer func() {
		if r := recover(); r != nil {
			displayMutex.Lock()
			fmt.Printf("\n❌ Panic recovered while scanning %s:%d: %v\n", host, port, r)
			displayMutex.Unlock()
		}
		<-sem // Release semaphore slot
	}()

	sem <- struct{}{} // Acquire semaphore slot

	if resultTCP := scanTCPPort(host, port); resultTCP != nil {
		// Vulnerability mapping will be done in a separate phase if enabled
		mutex.Lock()
		results = append(results, *resultTCP)
		mutex.Unlock()
		
		displayMutex.Lock()
		fmt.Printf("\r\033[K✅ Found TCP: %s:%d (%s %s)\n", host, port, resultTCP.Service, resultTCP.Version)
		displayMutex.Unlock()
	}
	atomic.AddInt64(&scannedPorts, 1)

	if config.UDPScan {
		if resultUDP := scanUDPPort(host, port); resultUDP != nil {
			mutex.Lock()
			results = append(results, *resultUDP)
			mutex.Unlock()
			
			displayMutex.Lock()
			fmt.Printf("\r\033[K✅ Found UDP: %s:%d (%s %s)\n", host, port, resultUDP.Service, resultUDP.Version)
			displayMutex.Unlock()
		}
		atomic.AddInt64(&scannedPorts, 1)
	}
}

func validateConfig() bool {
	fmt.Println("🔧 Validating configuration...")
	isValid := true
	if config.TargetHost == "" && config.TargetFile == "" {
		fmt.Println("❌ No target specified. Please set target host or target file.")
		isValid = false
	}
	if len(parsePortRange(config.PortRange)) == 0 && config.NmapResultsFile == "" { // Only require ports if not just parsing Nmap
		fmt.Println("❌ Invalid or no port range specified for scanning.")
		isValid = false
	}
	if config.TargetFile != "" {
		if _, err := os.Stat(config.TargetFile); os.IsNotExist(err) {
			fmt.Printf("❌ Target file does not exist: %s\n", config.TargetFile)
			isValid = false
		}
	}
	if config.ScanTimeout < 50 || config.ScanTimeout > 10000 {
		fmt.Println("⚠️  Warning: Scan timeout should generally be between 50ms and 10000ms. Current:", config.ScanTimeout, "ms")
	}
	if config.MaxConcurrency < 1 || config.MaxConcurrency > 10000 {
		fmt.Println("⚠️  Warning: Max concurrency should generally be between 1 and 10000. Current:", config.MaxConcurrency)
	}
	if config.PingSweep {
		if len(parsePortRange(config.PingSweepPorts)) == 0 {
			fmt.Println("❌ Ping sweep enabled but no valid ping sweep ports specified.")
			isValid = false
		}
		if config.PingSweepTimeout <= 0 {
			fmt.Println("❌ Ping sweep enabled but ping sweep timeout is invalid.")
			isValid = false
		}
	}
	if config.VulnMapping && config.NVDAPIKey == "" {
		fmt.Println("⚠️  Vulnerability mapping is enabled, but no NVD API key is set. This will severely limit NVD queries.")
	}

	if isValid {
		fmt.Println("✅ Configuration validation complete.")
	} else {
		fmt.Println("❌ Configuration validation failed.")
	}
	return isValid
}

func debugCIDRParsing(cidr string) {
	fmt.Printf("🔍 Debug: Parsing CIDR/Target '%s'\n", cidr)
	ips := parseSingleTarget(cidr)
	fmt.Printf("📊 Generated %d IP addresses:\n", len(ips))
	displayCount := len(ips)
	if displayCount > 20 {
		displayCount = 20
	}
	for i := 0; i < displayCount; i++ {
		fmt.Printf("  %d: %s\n", i+1, ips[i])
	}
	if len(ips) > 20 {
		fmt.Printf("  ... and %d more\n", len(ips)-20)
	}
}

func parseNmapResults() {
	if config.NmapResultsFile == "" {
		config.NmapResultsFile = askForString("📁 Enter Nmap XML results file path: ")
		if config.NmapResultsFile == "" {
			fmt.Println("❌ No Nmap file specified.")
			return
		}
	}
	file, err := os.Open(config.NmapResultsFile)
	if err != nil {
		fmt.Printf("❌ Error opening Nmap file '%s': %v\n", config.NmapResultsFile, err)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		fmt.Printf("❌ Error reading Nmap file '%s': %v\n", config.NmapResultsFile, err)
		return
	}

	var nmapRun NmapRun
	if err := xml.Unmarshal(data, &nmapRun); err != nil {
		fmt.Printf("❌ Error parsing Nmap XML from '%s': %v\n", config.NmapResultsFile, err)
		return
	}
	
	newResults := []EnhancedScanResult{}
	parsedCount := 0
	for _, host := range nmapRun.Hosts {
		if host.Address.Addr == "" { continue }
		for _, port := range host.Ports.Ports {
			// Apply OnlyOpenPorts filter here
			isConsideredOpen := strings.ToLower(port.State.State) == "open" || 
								 (port.Protocol == "udp" && strings.Contains(strings.ToLower(port.State.State), "open|filtered"))

			if !config.OnlyOpenPorts || isConsideredOpen {
				result := EnhancedScanResult{
					Host:      host.Address.Addr,
					Port:      port.PortID,
					Protocol:  port.Protocol,
					State:     port.State.State,
					Service:   port.Service.Name,
					Version:   strings.TrimSpace(port.Service.Version),
					Timestamp: time.Now().UTC(), // Timestamp of parsing
				}
				// OS Guess from Nmap XML requires parsing <os> tags, which is more complex.
				// For now, we'll use our internal guessOS or it remains blank.
				result.OSGuess = guessOS(&result) // Attempt our own guess
				
				// Vulnerability mapping will be done in performVulnerabilityMapping phase
				newResults = append(newResults, result)
				parsedCount++
			}
		}
	}
	results = newResults // Replace existing results
	fmt.Printf("✅ Parsed %d ports from Nmap results file: %s (respecting 'OnlyOpenPorts': %t)\n", parsedCount, config.NmapResultsFile, config.OnlyOpenPorts)
	if len(results) > 0 {
		displayResults()
		if config.VulnMapping { // Offer to run vuln mapping after parsing
			if askForBool("🔍 Perform vulnerability mapping on parsed Nmap results? (y/N): ") {
				performVulnerabilityMapping()
			}
		}
	} else {
		fmt.Println("ℹ️ No ports matched the criteria from the Nmap file.")
	}
}

func mapVulnerabilities(result *EnhancedScanResult) {
	// This function is called per result *during* performVulnerabilityMapping, not during the scan.
	if !config.VulnMapping { // Should be checked by caller, but double-check
		return
	}

	serviceKey := strings.ToLower(strings.TrimSpace(result.Service))
	versionKey := strings.TrimSpace(result.Version)
	productKey := fmt.Sprintf("%s %s", result.Service, result.Version) // For custom CVEs

	// 1. Check custom CVE database (case-sensitive match on productKey from result)
	if cves, found := customCVEs[productKey]; found {
		result.Vulnerabilities = cves
		return // Found in custom DB, stop here
	}
	// Try with lowercase service name too for custom DB flexibility
	lowerServiceProductKey := fmt.Sprintf("%s %s", serviceKey, versionKey)
	if cves, found := customCVEs[lowerServiceProductKey]; found {
		result.Vulnerabilities = cves
		return
	}


	// 2. NVD Lookup (if service is known and version is present)
	if versionKey == "" || versionKey == "unknown" || serviceKey == "unknown" || serviceKey == "" {
		result.Vulnerabilities = []string{"Version/Service unknown - NVD lookup skipped"}
		return
	}
	
	// Create CPE string
	// Standard CPE format: cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*
	// Vendor and product from serviceToCPE are already lowercase. Version should be exact from detection.
	cpeInfo, cpeMapExists := serviceToCPE[serviceKey]
	if !cpeMapExists {
		// Try to guess CPE for common software not explicitly in serviceToCPE
		// This is very basic. A more robust solution would involve a larger CPE dictionary or smarter parsing.
		if strings.Contains(serviceKey, "apache") && (strings.Contains(serviceKey, "httpd") || serviceKey == "http" || serviceKey == "https") {
			cpeInfo = struct{Vendor,Product string}{"apache", "http_server"} // NVD uses http_server for Apache httpd
		} else if strings.Contains(serviceKey, "openssh") {
			cpeInfo = struct{Vendor,Product string}{"openssh", "openssh"}
		} else if strings.Contains(serviceKey, "nginx") {
			cpeInfo = struct{Vendor,Product string}{"nginx", "nginx"}
		} else if strings.Contains(serviceKey, "mysql") {
			cpeInfo = struct{Vendor,Product string}{"oracle", "mysql"} // or "mysql", "mysql"
		} else {
			result.Vulnerabilities = []string{fmt.Sprintf("Service '%s' not in CPE map", result.Service)}
			return
		}
	}

	// Clean version for CPE: NVD is picky. Often, "OpenSSH_8.2p1" becomes "8.2p1".
	// This needs careful handling. For now, use versionKey as is.
	// Some products prefix versions (e.g. "Apache Tomcat 9.0.50" -> version "9.0.50")
	cpeVersion := versionKey
	// Example cleaning: if version is "OpenSSH_8.2p1 Debian-10+deb11u1", NVD might want "8.2p1"
	if strings.HasPrefix(versionKey, cpeInfo.Product+" ") { // e.g. "Apache httpd 2.4.50"
		cpeVersion = strings.TrimPrefix(versionKey, cpeInfo.Product+" ")
	} else if strings.HasPrefix(strings.ToLower(versionKey), cpeInfo.Product+"-") { // e.g. "openssh-server-8.2p1"
        cpeVersion = strings.TrimPrefix(strings.ToLower(versionKey), cpeInfo.Product+"-")
    }
    // Remove common suffixes like "(Ubuntu)", "Debian" etc.
    if idx := strings.Index(cpeVersion, " "); idx != -1 {
        cpeVersion = cpeVersion[:idx]
    }
    if idx := strings.Index(cpeVersion, "("); idx != -1 {
        cpeVersion = cpeVersion[:idx]
    }


	cpeString := fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*",
		cpeInfo.Vendor, cpeInfo.Product, strings.ToLower(cpeVersion)) // NVD often prefers lowercase versions in CPEs

	// Check NVD cache first
	nvdCacheKey := cpeString
	if cachedVulns, found := nvdCache.Load(nvdCacheKey); found {
		if cvs, ok := cachedVulns.([]string); ok {
			result.Vulnerabilities = cvs
			return
		}
	}

	nvdCVEs, err := queryNVD(cpeString)
	if err != nil {
		result.Vulnerabilities = []string{fmt.Sprintf("NVD lookup error: %s", err.Error())}
		nvdCache.Store(nvdCacheKey, result.Vulnerabilities) // Cache error to avoid re-query
		return
	}
	nvdCache.Store(nvdCacheKey, nvdCVEs) // Cache successful result (even if empty)
	
	if len(nvdCVEs) > 0 {
		result.Vulnerabilities = nvdCVEs
	} else {
		// 3. If NVD found nothing, try local fuzzy match (vulnDB)
		// vulnDB expects keys like "http Apache 2.4.49"
		fuzzyKey := fmt.Sprintf("%s %s", result.Service, versionKey) // Use original case service name for vulnDB
		if similar := findSimilarKey(fuzzyKey); similar != "" {
			if localCVEs, found := vulnDB[similar]; found {
				result.Vulnerabilities = append([]string{"(Local DB Match):"}, localCVEs...)
				return
			}
		}
		result.Vulnerabilities = []string{"No known vulnerabilities found (NVD/Local)"}
	}
}


func performVulnerabilityMapping() {
	if len(results) == 0 {
		fmt.Println("❌ No scan results available to map vulnerabilities.")
		return
	}
	if !config.VulnMapping {
		fmt.Println("ℹ️ Vulnerability mapping is disabled in settings.")
		return
	}

	if config.NVDAPIKey == "" {
		fmt.Println("⚠️  NVD API Key not set. Vulnerability mapping quality via NVD will be severely reduced or fail.")
		fmt.Println("   Consider setting NVD_API_KEY environment variable or using the --nvd-key flag / interactive setting.")
		if !askForBool("Continue vulnerability mapping without NVD API key? (y/N): ") {
			return
		}
	}

	fmt.Println("🔍 Mapping vulnerabilities for available results...")
	var mappedCountAtomic int32
	var wgVuln sync.WaitGroup
	// Limit concurrent NVD API calls. NVD's own limiter is primary, but this adds a layer.
	vulnSemMax := 10 // Max concurrent goroutines for mapVulnerabilities
	if config.NVDAPIKey == "" {
		vulnSemMax = 2 // Fewer concurrent if no API key due to stricter rate limits
	}
	vulnSem := make(chan struct{}, vulnSemMax)

	tempResults := make([]EnhancedScanResult, len(results))
	copy(tempResults, results) // Work on a copy to avoid modifying results while iterating if it's complex

	totalToMap := len(tempResults)
	mapProgressTicker := time.NewTicker(1 * time.Second)
	defer mapProgressTicker.Stop()
	var displayMutexMap sync.Mutex

	go func() {
		for range mapProgressTicker.C {
			current := atomic.LoadInt32(&mappedCountAtomic)
			if totalToMap == 0 {continue}
			if current >= int32(totalToMap) {
				mapProgressTicker.Stop()
				return
			}
			percentage := float64(current) / float64(totalToMap) * 100
			displayMutexMap.Lock()
			fmt.Printf("\r\033[K🔍 Vulnerability Mapping: %d/%d (%.1f%%)", current, totalToMap, percentage)
			displayMutexMap.Unlock()
		}
	}()


	for i := range tempResults {
		wgVuln.Add(1)
		go func(idx int) {
			defer wgVuln.Done()
			vulnSem <- struct{}{}
			defer func() { <-vulnSem }()
			
			// Pass a pointer to the element in tempResults
			mapVulnerabilities(&tempResults[idx])
			atomic.AddInt32(&mappedCountAtomic, 1)
		}(i)
	}
	wgVuln.Wait()
	mapProgressTicker.Stop() // Ensure ticker stops
	time.Sleep(150 * time.Millisecond) // Allow final print

	// Update original results slice with the mapped data
	mutex.Lock()
	results = tempResults
	mutex.Unlock()

	finalMappedCount := atomic.LoadInt32(&mappedCountAtomic)
	displayMutexMap.Lock()
	fmt.Printf("\r\033[K✅ Vulnerability mapping completed for %d results.                                \n", finalMappedCount)
	displayMutexMap.Unlock()
	
	displayResults() // Show updated results
}

func generateTopologyMap() {
	if len(results) == 0 {
		fmt.Println("❌ No scan results available. Run a scan first.")
		return
	}
	fmt.Println("🌐 Generating network topology map...")
	var dotGraph strings.Builder
	dotGraph.WriteString("digraph NetworkTopology {\n")
	dotGraph.WriteString("  rankdir=LR;\n")
	dotGraph.WriteString("  node [shape=record, style=\"rounded,filled\", fillcolor=\"#E6F5FF\"];\n") // Light blue
	dotGraph.WriteString("  edge [style=dashed, color=gray40];\n")

	hostServices := make(map[string]map[string][]string) // host -> {service_name -> [port/proto, ...]}

	for _, result := range results {
		isConsideredOpen := strings.ToLower(result.State) == "open" ||
			(result.Protocol == "udp" && strings.Contains(strings.ToLower(result.State), "open|filtered"))
		if isConsideredOpen {
			if _, ok := hostServices[result.Host]; !ok {
				hostServices[result.Host] = make(map[string][]string)
			}
			serviceKey := result.Service
			if serviceKey == "" || serviceKey == "unknown" {
				serviceKey = fmt.Sprintf("port_%d", result.Port) // Generic for unknown services
			}
			portProto := fmt.Sprintf("%d/%s", result.Port, result.Protocol)
			hostServices[result.Host][serviceKey] = append(hostServices[result.Host][serviceKey], portProto)
		}
	}
	
	for host, servicesMap := range hostServices {
		var serviceDetails []string
		for service, portsProtos := range servicesMap {
			// Sort ports for consistent output, though not strictly necessary
			// sort.Strings(portsProtos)
			serviceDetails = append(serviceDetails, fmt.Sprintf("<%s> %s: %s", sanitizeForDotID(service), service, strings.Join(portsProtos, ", ")))
		}
		// Node ID needs to be DOT compliant (no special chars like '.')
		nodeID := sanitizeForDotID(host)
		label := fmt.Sprintf("{%s|%s}", host, strings.Join(serviceDetails, "\\n"))
		dotGraph.WriteString(fmt.Sprintf("  \"%s\" [id=\"%s_node\" label=\"%s\"];\n", nodeID, nodeID, label))
	}

	// Placeholder for potential future edge generation based on discovered relationships
	// e.g., if result.Version indicated a client connection to another scanned host.
	// For now, it's a host-centric map.

	dotGraph.WriteString("}\n")
	filename := fmt.Sprintf("%s_topology.dot", strings.ReplaceAll(config.OutputFile, ".", "_"))
	err := os.WriteFile(filename, []byte(dotGraph.String()), 0644)
	if err != nil {
		fmt.Printf("❌ Failed to write topology file '%s': %v\n", filename, err)
		return
	}
	fmt.Printf("✅ Network topology map (DOT format) saved to %s\n", filename)
	fmt.Printf("💡 Use Graphviz: dot -Tpng %s -o %s.png\n", filename, strings.TrimSuffix(filename, ".dot"))
}

// sanitizeForDotID creates a DOT-compliant ID string.
func sanitizeForDotID(input string) string {
	// Replace non-alphanumeric characters (except underscore) with underscore
	sanitized := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		return '_'
	}, input)
	// Ensure it doesn't start with a number if it's purely numeric after sanitization
	if len(sanitized) > 0 && (sanitized[0] >= '0' && sanitized[0] <= '9') {
		isNumeric := true
		for _, char := range sanitized {
			if !(char >= '0' && char <= '9') {
				isNumeric = false
				break
			}
		}
		if isNumeric {
			return "id_" + sanitized
		}
	}
	return sanitized
}


func displayResults() {
	mutex.Lock() // Protect results slice during filtering and display
	defer mutex.Unlock()

	if len(results) == 0 {
		fmt.Println("❌ No results to display. Run a scan or parse Nmap results first.")
		return
	}

	displayData := results
	if config.OnlyOpenPorts {
		filteredResults := []EnhancedScanResult{}
		for _, result := range results {
			isConsideredOpen := strings.ToLower(result.State) == "open" ||
				(result.Protocol == "udp" && strings.Contains(strings.ToLower(result.State), "open|filtered"))
			if isConsideredOpen {
				filteredResults = append(filteredResults, result)
			}
		}
		displayData = filteredResults
	}

	if len(displayData) == 0 {
		if config.OnlyOpenPorts {
			fmt.Println("ℹ️  No open (or open|filtered) ports to display based on current filter.")
		} else {
			fmt.Println("ℹ️  No results to display (all results might be filtered out or non-open).")
		}
		return
	}

	fmt.Printf("\n📊 Scan Results (%d entries matching filter):\n", len(displayData))
	// Host (20) | Port (5) | Proto (5) | State (12) | Service (20) | Version (30) | Vulns (18) | OS (15)
	fmt.Println("┌──────────────────────┬───────┬───────┬──────────────┬──────────────────────┬────────────────────────────────┬────────────────────┬─────────────────┐")
	fmt.Println("│ Host                 │ Port  │ Proto │ State        │ Service              │ Version                        │ Vulnerabilities    │ OS Guess        │")
	fmt.Println("├──────────────────────┼───────┼───────┼──────────────┼──────────────────────┼────────────────────────────────┼────────────────────┼─────────────────┤")

	for _, result := range displayData {
		vulnStr := "N/A"
		if config.VulnMapping && len(result.Vulnerabilities) > 0 {
			if len(result.Vulnerabilities) == 1 &&
				(result.Vulnerabilities[0] == "No known vulnerabilities found (NVD/Local)" ||
					strings.HasPrefix(result.Vulnerabilities[0], "Version/Service unknown") ||
					strings.HasPrefix(result.Vulnerabilities[0], "Service '") || // "Service 'x' not in CPE map"
					strings.HasPrefix(result.Vulnerabilities[0], "NVD lookup error")) {
				vulnStr = result.Vulnerabilities[0]
			} else if strings.HasPrefix(result.Vulnerabilities[0], "(Local DB Match):") {
                 if len(result.Vulnerabilities) > 1 { // (Local DB Match): + CVEs
					vulnStr = fmt.Sprintf("%d CVEs (Local DB)", len(result.Vulnerabilities)-1)
                 } else {
                    vulnStr = "Local DB (No CVEs)"
                 }
			} else {
				cveCount := 0
				for _, v := range result.Vulnerabilities {
					if strings.HasPrefix(v, "CVE-") { // Count actual CVEs
						cveCount++
					}
				}
				if cveCount > 0 {
					vulnStr = fmt.Sprintf("%d CVEs", cveCount)
				} else if len(result.Vulnerabilities) > 0 { // Has entries but no "CVE-" prefix
                    vulnStr = "Info found" // Generic for other vulnerability info
                } else {
                    vulnStr = "None Found"
                }
			}
		} else if config.VulnMapping && len(result.Vulnerabilities) == 0 {
			// This case might not be hit if mapVulnerabilities always populates something
			vulnStr = "Not checked/No info"
		}


		fmt.Printf("│ %-20s │ %-5d │ %-5s │ %-12s │ %-20s │ %-30s │ %-18s │ %-15s │\n",
			truncateString(result.Host, 20), result.Port, result.Protocol,
			truncateString(result.State, 12), truncateString(result.Service, 20),
			truncateString(result.Version, 30), truncateString(vulnStr, 18),
			truncateString(result.OSGuess, 15))
	}
	fmt.Println("└──────────────────────┴───────┴───────┴──────────────┴──────────────────────┴────────────────────────────────┴────────────────────┴─────────────────┘")
}

func truncateString(s string, maxLen int) string {
	if len(s) > maxLen {
		if maxLen > 3 {
			return s[:maxLen-3] + "..."
		}
		return s[:maxLen] // If maxLen is too small for "..."
	}
	return s
}

func saveResults() {
	mutex.Lock() // Protect results slice
	defer mutex.Unlock()
	if len(results) == 0 {
		fmt.Println("❌ No results to save.")
		return
	}
	filename := fmt.Sprintf("%s.json", config.OutputFile)
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("❌ Error marshaling results to JSON: %v\n", err)
		return
	}
	if err := os.WriteFile(filename, data, 0644); err != nil {
		fmt.Printf("❌ Error writing JSON file '%s': %v\n", filename, err)
		return
	}
	fmt.Printf("✅ JSON results saved to %s\n", filename)
}

func exportResults() {
	mutex.Lock() // Protect results slice
	currentResults := make([]EnhancedScanResult, len(results))
	copy(currentResults, results)
	mutex.Unlock()

	if len(currentResults) == 0 {
		fmt.Println("❌ No results to export.")
		return
	}

	fmt.Println("📤 Choose export format:")
	fmt.Println("1. JSON (Default save format)")
	fmt.Println("2. CSV")
	fmt.Println("3. XML")
	fmt.Println("4. HTML Report")
	fmt.Print("Choose format: ")
	choice := getUserChoice()

	// Pass currentResults to export functions to ensure consistency
	switch choice {
	case 1:
		exportJSON(currentResults)
	case 2:
		exportCSV(currentResults)
	case 3:
		exportXML(currentResults)
	case 4:
		exportHTML(currentResults)
	default:
		fmt.Println("❌ Invalid choice.")
	}
}

func exportJSON(dataToExport []EnhancedScanResult) {
	// This effectively re-uses the logic of saveResults but with potentially filtered data
	// or could just call saveResults() if always exporting the global `results`.
	// For consistency, let's make it explicit it's saving what's passed.
	filename := fmt.Sprintf("%s_export.json", config.OutputFile) // Different name to avoid overwrite
	data, err := json.MarshalIndent(dataToExport, "", "  ")
	if err != nil {
		fmt.Printf("❌ Error marshaling results to JSON for export: %v\n", err)
		return
	}
	if err := os.WriteFile(filename, data, 0644); err != nil {
		fmt.Printf("❌ Error writing exported JSON file '%s': %v\n", filename, err)
		return
	}
	fmt.Printf("✅ JSON results exported to %s\n", filename)
}

func exportCSV(dataToExport []EnhancedScanResult) {
	filename := fmt.Sprintf("%s.csv", config.OutputFile)
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("❌ Error creating CSV file '%s': %v\n", filename, err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	header := []string{"Host", "Port", "Protocol", "State", "Service", "Version", "ResponseTime(ms)", "Timestamp", "Vulnerabilities", "OSGuess"}
	writer.WriteString(strings.Join(header, ",") + "\n")

	for _, result := range dataToExport {
		vulnStr := strings.ReplaceAll(strings.Join(result.Vulnerabilities, "; "), "\"", "\"\"") // Basic CSV escaping for quotes
		record := []string{
			escapeCSVField(result.Host),
			strconv.Itoa(result.Port),
			escapeCSVField(result.Protocol),
			escapeCSVField(result.State),
			escapeCSVField(result.Service),
			escapeCSVField(result.Version),
			strconv.FormatInt(result.ResponseTime.Milliseconds(), 10),
			result.Timestamp.Format(time.RFC3339),
			escapeCSVField(vulnStr),
			escapeCSVField(result.OSGuess),
		}
		writer.WriteString(strings.Join(record, ",") + "\n")
	}
	writer.Flush()
	fmt.Printf("✅ CSV results exported to %s\n", filename)
}

// escapeCSVField handles commas and quotes in CSV fields.
func escapeCSVField(field string) string {
	if strings.Contains(field, ",") || strings.Contains(field, "\"") || strings.Contains(field, "\n") {
		return "\"" + strings.ReplaceAll(field, "\"", "\"\"") + "\""
	}
	return field
}

func exportXML(dataToExport []EnhancedScanResult) {
	filename := fmt.Sprintf("%s.xml", config.OutputFile)
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("❌ Error creating XML file '%s': %v\n", filename, err)
		return
	}
	defer file.Close()

	type XMLScanResult struct {
		XMLName        xml.Name `xml:"ScanResult"` // Renamed for clarity
		Host           string   `xml:"Host"`
		Port           int      `xml:"Port"`
		Protocol       string   `xml:"Protocol"`
		State          string   `xml:"State"`
		Service        string   `xml:"Service,omitempty"`
		Version        string   `xml:"Version,omitempty"`
		ResponseTimeMs int64    `xml:"ResponseTimeMs"`
		Timestamp      string   `xml:"Timestamp"` // String for XML simplicity
		OSGuess        string   `xml:"OSGuess,omitempty"`
		Vulnerabilities *struct { // Pointer to allow empty tag if no vulns
			Vulnerability []string `xml:"Vulnerability,omitempty"`
		} `xml:"Vulnerabilities,omitempty"`
	}
	
	type XMLRoot struct {
		XMLName   xml.Name `xml:"ReconRaptorResults"`
		ScanInfo struct {
			ToolVersion     string `xml:"ToolVersion"`
			ExportTimestamp string `xml:"ExportTimestamp"`
			Target          string `xml:"Target,omitempty"`
			FilterOpenOnly  bool   `xml:"FilterOpenOnly"`
		} `xml:"ScanInfo"`
		Results []XMLScanResult `xml:"HostResults>Result"` // Nested structure for clarity
	}

	xmlData := XMLRoot{}
	xmlData.ScanInfo.ToolVersion = VERSION
	xmlData.ScanInfo.ExportTimestamp = time.Now().Format(time.RFC3339)
	xmlData.ScanInfo.FilterOpenOnly = config.OnlyOpenPorts // Reflect filter state
	if config.TargetHost != "" {
		xmlData.ScanInfo.Target = config.TargetHost
	} else if config.TargetFile != "" {
		xmlData.ScanInfo.Target = "File: " + config.TargetFile
	} else if config.NmapResultsFile != "" {
		xmlData.ScanInfo.Target = "Nmap File: " + config.NmapResultsFile
	}


	for _, res := range dataToExport {
		xmlRes := XMLScanResult{
			Host:           res.Host,
			Port:           res.Port,
			Protocol:       res.Protocol,
			State:          res.State,
			Service:        res.Service,
			Version:        res.Version,
			ResponseTimeMs: res.ResponseTime.Milliseconds(),
			Timestamp:      res.Timestamp.Format(time.RFC3339),
			OSGuess:        res.OSGuess,
		}
		if len(res.Vulnerabilities) > 0 {
			xmlRes.Vulnerabilities = &struct{Vulnerability []string `xml:"Vulnerability,omitempty"`}{
				Vulnerability: res.Vulnerabilities,
			}
		}
		xmlData.Results = append(xmlData.Results, xmlRes)
	}

	encoder := xml.NewEncoder(file)
	encoder.Indent("", "  ")
	file.WriteString(xml.Header)
	if err := encoder.Encode(xmlData); err != nil {
		fmt.Printf("❌ Error marshaling results to XML: %v\n", err)
		return
	}
	fmt.Printf("✅ XML results exported to %s\n", filename)
}


func exportHTML(dataToExport []EnhancedScanResult) {
    filename := fmt.Sprintf("%s.html", config.OutputFile)
    file, err := os.Create(filename)
    if err != nil {
        fmt.Printf("❌ Error creating HTML file '%s': %v\n", filename, err)
        return
    }
    defer file.Close()

    type HTMLReportData struct {
        ToolVersion     string
        ExportTimestamp string
        TargetInfo      string
        Results         []EnhancedScanResult
		FilterOpenOnly  bool
		TotalResults    int
    }

    reportData := HTMLReportData{
        ToolVersion:     VERSION,
        ExportTimestamp: time.Now().Format("January 2, 2006 15:04:05 MST"),
        Results:         dataToExport, // Use the passed data
		FilterOpenOnly:  config.OnlyOpenPorts,
		TotalResults:    len(dataToExport),
    }
	if config.TargetHost != "" {
		reportData.TargetInfo = config.TargetHost
	} else if config.TargetFile != "" {
		reportData.TargetInfo = "File: " + config.TargetFile
	} else if config.NmapResultsFile != "" {
		reportData.TargetInfo = "Nmap File: " + config.NmapResultsFile
	} else {
		reportData.TargetInfo = "N/A"
	}

    htmlTemplate := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ReconRaptor Scan Report - {{.TargetInfo}}</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background-color: #f0f2f5; color: #333; line-height: 1.6; }
        .container { max-width: 1200px; margin: 20px auto; padding: 20px; background-color: #fff; box-shadow: 0 0 15px rgba(0,0,0,0.1); border-radius: 8px; }
        h1, h2 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; margin-top: 0; }
        .header { background-color: #3498db; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
        .header h1 { color: white; border-bottom: none; margin: 0; font-size: 2em; }
		.summary { background-color: #eaf5ff; padding: 20px; border-left: 5px solid #3498db; margin-bottom:25px; border-radius: 5px;}
        .summary p { margin: 5px 0; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; font-size: 0.9em; }
        th, td { border: 1px solid #ddd; padding: 10px 12px; text-align: left; }
        th { background-color: #3498db; color: white; font-weight: 600; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f1f1f1; }
        .footer { text-align: center; margin-top: 30px; font-size: 0.9em; color: #777; padding: 15px; background-color: #ecf0f1; border-radius: 0 0 8px 8px;}
        .no-results { padding: 20px; background-color: #fff0f0; border: 1px solid #e9c6c6; color: #721c24; border-radius: 5px; text-align: center; font-weight: bold;}
        .vuln-list { list-style-type: none; padding-left: 0; margin: 0;}
        .vuln-list li { padding: 1px 0; font-size: 0.95em; }
		.vuln-list li:not(:last-child) { border-bottom: 1px dotted #eee; margin-bottom: 2px; padding-bottom: 2px;}
		.tag { display: inline-block; padding: 2px 6px; font-size: 0.8em; border-radius: 3px; margin-right: 5px; }
		.tag-open { background-color: #2ecc71; color: white; } /* Green */
		.tag-open-filtered { background-color: #f39c12; color: white; } /* Orange */
		.tag-closed { background-color: #e74c3c; color: white; } /* Red */
		.tag-unknown { background-color: #95a5a6; color: white; } /* Gray */
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>ReconRaptor Scan Report</h1>
        </div>

        <div class="summary">
            <h2>Scan Summary</h2>
            <p><strong>Target(s):</strong> {{.TargetInfo}}</p>
            <p><strong>Tool Version:</strong> {{.ToolVersion}}</p>
            <p><strong>Report Generated:</strong> {{.ExportTimestamp}}</p>
            <p><strong>Total Results Displayed:</strong> {{.TotalResults}}</p>
            {{if .FilterOpenOnly}}<p><strong>Filter Active:</strong> Showing only open / open|filtered ports.</p>{{else}}<p><strong>Filter Active:</strong> Showing all collected port states.</p>{{end}}
        </div>

        <h2>Detailed Scan Results</h2>
        {{if .Results}}
        <table>
            <thead>
                <tr>
                    <th>Host</th>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Version</th>
                    <th>Vulnerabilities</th>
                    <th>OS Guess</th>
                    <th>Scan Timestamp</th>
                </tr>
            </thead>
            <tbody>
                {{range .Results}}
                <tr>
                    <td>{{.Host}}</td>
                    <td>{{.Port}}</td>
                    <td>{{.Protocol}}</td>
                    <td>
						{{if eq (lower .State) "open"}}<span class="tag tag-open">{{.State}}</span>
						{{else if contains (lower .State) "open|filtered"}}<span class="tag tag-open-filtered">{{.State}}</span>
						{{else if contains (lower .State) "closed"}}<span class="tag tag-closed">{{.State}}</span>
						{{else}}<span class="tag tag-unknown">{{.State}}</span>{{end}}
					</td>
                    <td>{{.Service}}</td>
                    <td>{{.Version}}</td>
                    <td>
                        {{if .Vulnerabilities}}
                        <ul class="vuln-list">
                            {{range .Vulnerabilities}}
                            <li>{{.}}</li>
                            {{end}}
                        </ul>
                        {{else}}
                            N/A
                        {{end}}
                    </td>
                    <td>{{.OSGuess}}</td>
                    <td>{{.Timestamp.Format "2006-01-02 15:04:05"}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>
        {{else}}
        <p class="no-results">No results match the current criteria.</p>
        {{end}}
    </div>
    <div class="footer">
        Report generated by ReconRaptor (v{{.ToolVersion}})
    </div>
</body>
</html>
`
    // Helper function for lowercase in template
    funcMap := template.FuncMap{
        "lower":    strings.ToLower,
        "contains": strings.Contains,
    }

    tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
    if err != nil {
        fmt.Printf("❌ Error parsing HTML template: %v\n", err)
        return
    }

    if err := tmpl.Execute(file, reportData); err != nil {
        fmt.Printf("❌ Error executing HTML template: %v\n", err)
        return
    }

    fmt.Printf("✅ HTML report exported to %s\n", filename)
}


func loadConfigFromEnv() {
	if val := os.Getenv("NVD_API_KEY"); val != "" && config.NVDAPIKey == "" {
		config.NVDAPIKey = val
		fmt.Println("ℹ️  Loaded NVD_API_KEY from environment variable.")
	}
	if val := os.Getenv("RECONRAPTOR_TARGET_HOST"); val != "" && config.TargetHost == "" { config.TargetHost = val }
	if val := os.Getenv("RECONRAPTOR_TARGET_FILE"); val != "" && config.TargetFile == "" { config.TargetFile = val }
	if val := os.Getenv("RECONRAPTOR_PORTS"); val != "" && config.PortRange == "" { config.PortRange = val } // Only if not set by default/flag
	if val := os.Getenv("RECONRAPTOR_OUTPUT"); val != "" && config.OutputFile == "scan_results" { config.OutputFile = val }
	
	// Example for new Ping Sweep env vars (add if desired)
	// if val := os.Getenv("RECONRAPTOR_PING_SWEEP"); val != "" { config.PingSweep, _ = strconv.ParseBool(val) }
	// if val := os.Getenv("RECONRAPTOR_PING_PORTS"); val != "" { config.PingSweepPorts = val }
	// if val := os.Getenv("RECONRAPTOR_PING_TIMEOUT"); val != "" { config.PingSweepTimeout, _ = strconv.Atoi(val) }
}

func parseCommandLineFlags() {
	flag.StringVar(&config.TargetHost, "target", config.TargetHost, "Target host(s) (comma-separated or CIDR). Env: RECONRAPTOR_TARGET_HOST")
	flag.StringVar(&config.TargetFile, "target-file", config.TargetFile, "File containing list of targets. Env: RECONRAPTOR_TARGET_FILE")
	flag.StringVar(&config.PortRange, "ports", config.PortRange, "Port range (e.g., 1-1000, 80, 443). Env: RECONRAPTOR_PORTS")
	flag.IntVar(&config.ScanTimeout, "timeout", config.ScanTimeout, "Scan timeout in milliseconds per port.")
	flag.IntVar(&config.MaxConcurrency, "concurrency", config.MaxConcurrency, "Maximum concurrent scans.")
	flag.StringVar(&config.OutputFile, "output", config.OutputFile, "Base name for output files (e.g., scan_results -> scan_results.json).")
	flag.BoolVar(&config.UDPScan, "udp", config.UDPScan, "Enable UDP scanning.")
	flag.BoolVar(&config.VulnMapping, "vuln", config.VulnMapping, "Enable vulnerability mapping using NVD.")
	flag.BoolVar(&config.TopologyMapping, "topology", config.TopologyMapping, "Enable network topology map generation (basic).")
	flag.StringVar(&config.NVDAPIKey, "nvd-key", config.NVDAPIKey, "NVD API key (overrides env var NVD_API_KEY).")
	flag.StringVar(&config.NmapResultsFile, "nmap-file", config.NmapResultsFile, "Import Nmap XML results file.")
	flag.BoolVar(&config.OnlyOpenPorts, "open-only", config.OnlyOpenPorts, "Display and process (from Nmap) only open/open|filtered ports.")
	flag.StringVar(&config.CVEPluginFile, "cve-plugin", config.CVEPluginFile, "Path to a custom CVE JSON file (map of 'service version': ['CVEs']).")

	// Ping Sweep Flags
	flag.BoolVar(&config.PingSweep, "ping-sweep", config.PingSweep, "Enable TCP ping sweep to find live hosts before port scanning.")
	flag.StringVar(&config.PingSweepPorts, "ping-ports", config.PingSweepPorts, "Comma-separated ports for TCP ping sweep (e.g., 80,443).")
	flag.IntVar(&config.PingSweepTimeout, "ping-timeout", config.PingSweepTimeout, "Timeout in milliseconds for TCP ping sweep attempts per port.")
	
	flag.Usage = func() {
        fmt.Fprintf(os.Stderr, "ReconRaptor (v%s) - Advanced RedTeaming Network Recon Tool\nBy %s\n\nUsage: %s [options]\n\nOptions:\n", VERSION, AUTHORS, os.Args[0])
        flag.PrintDefaults()
        fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  Direct Scan (TCP Ping Sweep, Port Scan, Vuln Mapping):\n    %s -target 192.168.1.0/24 -ports 1-1024 -ping-sweep -vuln -nvd-key YOUR_API_KEY\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Nmap Parse & Vuln Mapping:\n    %s -nmap-file results.xml -vuln -output nmap_scan\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Interactive Mode:\n    %s\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "More info & docs: https://github.com/0xb0rn3/ReconRaptor (Example URL)\n")
    }

	flag.Parse()
}
