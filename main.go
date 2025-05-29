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
	"math" // Added for exponential backoff calculation
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
	TargetHost      string `json:"target_host"`
	TargetFile      string `json:"target_file"`
	PortRange       string `json:"port_range"`
	ScanTimeout     int    `json:"scan_timeout"`
	MaxConcurrency  int    `json:"max_concurrency"`
	OutputFile      string `json:"output_file"`
	UDPScan         bool   `json:"udp_scan"`
	VulnMapping     bool   `json:"vuln_mapping"`
	TopologyMapping bool   `json:"topology_mapping"`
	NVDAPIKey       string `json:"nvd_api_key"`
	NmapResultsFile string `json:"nmap_results_file"`
	OnlyOpenPorts   bool   `json:"only_open_ports"`
	CVEPluginFile   string `json:"cve_plugin_file"`
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

// Note: The global NVDResponse struct is removed as the new queryNVD uses a local struct for API 2.0.

var (
	config = Config{
		TargetHost:      "",
		TargetFile:      "",
		PortRange:       "1-1000",
		ScanTimeout:     500,
		MaxConcurrency:  100,
		OutputFile:      "scan_results",
		UDPScan:         false,
		VulnMapping:     false,
		TopologyMapping: false,
		NVDAPIKey:       "",
		NmapResultsFile: "",
		OnlyOpenPorts:   true,
		CVEPluginFile:   "",
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
	nvdCache     = sync.Map{} // Thread-safe cache for NVD results
	customCVEs   = make(map[string][]string)
	httpClient   = &http.Client{Timeout: 10 * time.Second}
	limiter      = rate.NewLimiter(rate.Every(30*time.Second/5), 1) // 5 req/30s without API key
	// Predefined mapping of services to CPE vendor and product
	serviceToCPE = map[string]struct{ Vendor, Product string }{
		"http":   {"apache", "httpd"},
		"ssh":    {"openssh", "openssh_server"},
		"ftp":    {"proftpd", "proftpd"},
		"mysql":  {"oracle", "mysql"},
		"dns":    {"isc", "bind"},
		"smtp":   {"postfix", "postfix"},
		"redis":  {"redis", "redis"},
	}
)

func main() {
	printBanner()
	loadConfigFromEnv()
	parseCommandLineFlags() // Parses flags into config struct
	loadCustomCVEs()

	// Scenario 1: Attempt to run a scan directly if target and ports are specified
	if (config.TargetHost != "" || config.TargetFile != "") && config.PortRange != "" {
		// Ensure this isn't primarily an Nmap parsing operation from flags
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
					saveResults() // Auto-save after direct scan
				} else {
					fmt.Println("ℹ️  Direct scan completed. No open ports matching criteria found.")
				}
				fmt.Println("👋 Exiting r3cond0g v" + VERSION)
				return // Exit after direct scan
			} else {
				fmt.Println("❌ Direct scan aborted due to invalid configuration. Falling back to interactive menu.")
			}
		}
	}

	// Scenario 2: Attempt to parse Nmap results directly if file specified and no target scan intended
	if config.NmapResultsFile != "" && !(config.TargetHost != "" || config.TargetFile != "") {
		fmt.Printf("ℹ️  Nmap results file '%s' provided, attempting direct parse...\n", config.NmapResultsFile)
		parseNmapResults() // This function already handles vuln mapping if enabled and displays results
		if len(results) > 0 {
			saveResults() // Auto-save after direct parse
		}
		fmt.Println("👋 Exiting r3cond0g v" + VERSION)
		return // Exit after direct parse
	}

	// Fallback to interactive menu if no direct action was taken
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
			fmt.Println("👋 Exiting r3cond0g v" + VERSION)
			return
		case 10:
			// Hidden debug option
			cidr := askForString("🔍 Enter CIDR to debug (e.g., 192.168.1.0/24): ")
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
	fmt.Println("\n=== r3cond0g𓃦 - Advanced Network Recon Tool ===")
	fmt.Println("1. 🚀 Run Ultra-Fast Scan")
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
	var choice int
	fmt.Scanln(&choice)
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
		fmt.Printf("1. 🎯 Target Host: %s\n", config.TargetHost)
		fmt.Printf("2. 📁 Target File: %s\n", config.TargetFile)
		fmt.Printf("3. 🔢 Port Range: %s\n", config.PortRange)
		fmt.Printf("4. ⏱️ Scan Timeout (ms): %d\n", config.ScanTimeout)
		fmt.Printf("5. 🔄 Max Concurrency: %d\n", config.MaxConcurrency)
		fmt.Printf("6. 📄 Output File: %s\n", config.OutputFile)
		fmt.Printf("7. 🛡️ UDP Scan: %t\n", config.UDPScan)
		fmt.Printf("8. 🔍 Vulnerability Mapping: %t\n", config.VulnMapping)
		fmt.Printf("9. 🌐 Topology Mapping: %t\n", config.TopologyMapping)
		fmt.Printf("10. 🔑 NVD API Key: %s\n", maskAPIKey(config.NVDAPIKey))
		fmt.Printf("11. 📁 Nmap Results File: %s\n", config.NmapResultsFile)
		fmt.Printf("12. 🎯 Only Open Ports: %t\n", config.OnlyOpenPorts)
		fmt.Printf("13. 📄 CVE Plugin File: %s\n", config.CVEPluginFile)
		fmt.Println("0. ◀️ Back to main menu")
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
			fmt.Scanln(&config.ScanTimeout)
		case 5:
			fmt.Print("🔄 Enter max concurrency: ")
			fmt.Scanln(&config.MaxConcurrency)
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
			config.OnlyOpenPorts = askForBool("🎯 Show only open ports? (true/false): ")
		case 13:
			config.CVEPluginFile = askForString("📄 Enter CVE plugin file path: ")
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

func parsePortRange(portRange string) []int {
	var ports []int
	ranges := strings.Split(portRange, ",")
	for _, r := range ranges {
		r = strings.TrimSpace(r)
		if strings.Contains(r, "-") {
			parts := strings.Split(r, "-")
			start, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
			end, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		} else {
			port, _ := strconv.Atoi(r)
			if port > 0 {
				ports = append(ports, port)
			}
		}
	}
	return ports
}

func parseTargets(targets string, targetFile string) []string {
	var ips []string
	if targetFile != "" {
		fmt.Printf("📁 Reading targets from file: %s\n", targetFile)
		file, err := os.Open(targetFile)
		if err != nil {
			fmt.Printf("❌ Error opening target file: %v\n", err)
			return ips
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				parsedIPs := parseSingleTarget(line)
				if len(parsedIPs) == 0 {
					fmt.Printf("⚠️  Warning: Invalid target on line %d: %s\n", lineNum, line)
				} else {
					ips = append(ips, parsedIPs...)
				}
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf("❌ Error reading target file: %v\n", err)
		}
		fmt.Printf("📊 Loaded %d targets from file\n", len(ips))
	} else if targets != "" {
		fmt.Printf("🎯 Parsing target string: %s\n", targets)
		parts := strings.Split(targets, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				parsedIPs := parseSingleTarget(part)
				if len(parsedIPs) == 0 {
					fmt.Printf("⚠️  Warning: Invalid target: %s\n", part)
				} else {
					ips = append(ips, parsedIPs...)
					fmt.Printf("✅ Parsed %d IPs from: %s\n", len(parsedIPs), part)
				}
			}
		}
	}
	return ips
}

func parseSingleTarget(target string) []string {
	if strings.Contains(target, "/") {
		_, ipnet, err := net.ParseCIDR(target)
		if err != nil {
			// If CIDR parsing fails, treat as a single host
			// This handles cases where a hostname might contain a '/'
			// or an invalid CIDR is provided.
			ipAddr := net.ParseIP(target)
			if ipAddr != nil {
				return []string{ipAddr.String()}
			}
			return []string{target} // Return as is if it's not a valid IP either (could be a hostname)
		}
		var ips []string
		networkIP := ipnet.IP.Mask(ipnet.Mask)
		ones, bits := ipnet.Mask.Size()
		hostBits := bits - ones

		// Handle /32 and /31 cases correctly
		if hostBits == 0 { // /32 for IPv4, /128 for IPv6
			ips = append(ips, networkIP.String())
			return ips
		}
		if bits == 32 && hostBits == 1 { // /31 for IPv4
			ip1 := make(net.IP, len(networkIP))
			copy(ip1, networkIP)
			ips = append(ips, ip1.String())

			ip2 := make(net.IP, len(networkIP))
			copy(ip2, networkIP)
			ip2[len(ip2)-1]++
			ips = append(ips, ip2.String())
			return ips
		}


		start := 0
		end := (1 << hostBits)

		// Exclude network and broadcast addresses for typical networks (larger than /31 or /30)
		// For IPv4:
		if bits == 32 && hostBits > 1 { // For IPv4 networks larger than /31
			start = 1 // Skip network address
			end = end -1 // Skip broadcast address
		}
		// For IPv6, typically we don't skip addresses unless it's a very specific setup.
		// The loop below will generate all addresses in the range.

		for i := start; i < end; i++ {
			ip := make(net.IP, len(networkIP))
			copy(ip, networkIP)

			// Add 'i' to the IP address
			// This logic correctly handles carries across byte boundaries
			val := uint64(i)
			for j := len(ip) - 1; j >= 0; j-- {
				 sum := uint64(ip[j]) + (val & 0xff)
				 ip[j] = byte(sum)
				 val >>= 8
				 if val == 0 && sum <= 0xff { // Optimization: if no carry and no more of 'val', break
					 break
				 }
			}

			ips = append(ips, ip.String())
			if len(ips) >= 10000 { // Increased limit slightly
				fmt.Printf("⚠️  Warning: CIDR range too large, limiting to first 10000 IPs\n")
				break
			}
		}
		return ips
	}
	// Handle single IP or hostname
	ipAddr := net.ParseIP(target)
	if ipAddr != nil {
		return []string{ipAddr.String()}
	}
	return []string{target} // Assume it's a hostname
}


func scanTCPPort(host string, port int) *EnhancedScanResult {
	timeout := time.Duration(config.ScanTimeout) * time.Millisecond
	start := time.Now()

	// Use context for better timeout control
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Create a dialer with the context
	dialer := net.Dialer{
		// Timeout field in Dialer is actually for the connection establishment phase.
		// The context's timeout will handle the overall operation including DNS resolution if applicable.
	}

	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		// Don't return anything for closed/filtered ports to reduce noise
		return nil
	}
	defer conn.Close()

	result := &EnhancedScanResult{
		Host:         host,
		Port:         port,
		Protocol:     "tcp",
		State:        "open",
		ResponseTime: time.Since(start),
		Timestamp:    time.Now(),
	}

	// Enhanced service detection with timeout protection
	// Pass a portion of the original timeout for service detection.
	serviceDetectionTimeout := timeout / 2
	if serviceDetectionTimeout < 100*time.Millisecond { // Ensure a minimum timeout for service detection
		serviceDetectionTimeout = 100 * time.Millisecond
	}
	result.Service, result.Version = detectServiceWithTimeout(conn, port, "tcp", serviceDetectionTimeout)
	result.OSGuess = guessOS(result)

	return result
}

func scanUDPPort(host string, port int) *EnhancedScanResult {
	timeout := time.Duration(config.ScanTimeout) * time.Millisecond
	start := time.Now()
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	probe := getUDPProbe(port)
	_, err = conn.Write(probe)
	if err != nil {
		return nil
	}
	buffer := make([]byte, 1024)
	// UDP read timeout should be shorter as responses are often immediate or not at all.
	// It should be less than the overall scan timeout.
	readDeadline := time.Now().Add(timeout / 2)
	if timeout/2 < 50*time.Millisecond { // Ensure a minimum reasonable read deadline
		readDeadline = time.Now().Add(50 * time.Millisecond)
	}
	conn.SetReadDeadline(readDeadline)

	n, err := conn.Read(buffer)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			if isCommonUDPPort(port) {
				result := &EnhancedScanResult{
					Host:         host,
					Port:         port,
					Protocol:     "udp",
					State:        "open|filtered",
					ResponseTime: time.Since(start),
					Timestamp:    time.Now(),
				}
				serviceDetectionTimeout := timeout / 2
				if serviceDetectionTimeout < 50*time.Millisecond {
					serviceDetectionTimeout = 50 * time.Millisecond
				}
				result.Service, result.Version = detectServiceWithTimeout(nil, port, "udp", serviceDetectionTimeout) 
				result.OSGuess = guessOS(result)
				return result
			}
		}
		return nil
	}
	if n > 0 {
		result := &EnhancedScanResult{
			Host:         host,
			Port:         port,
			Protocol:     "udp",
			State:        "open",
			ResponseTime: time.Since(start),
			Timestamp:    time.Now(),
		}
		serviceDetectionTimeout := timeout / 2
		if serviceDetectionTimeout < 50*time.Millisecond {
			serviceDetectionTimeout = 50 * time.Millisecond
		}

		// Specific check for DNS before generic detection
		if port == 53 && n >= 12 { // DNS header is 12 bytes
			isResponse := (buffer[2] & 0x80) != 0 // QR bit (1 = response)
			opCode := (buffer[2] >> 3) & 0x0F    // Opcode
			responseCode := buffer[3] & 0x0F     // RCODE

			if isResponse && opCode == 0 { // Standard query response
				result.Service = "dns"
				if responseCode == 0 {
					result.Version = "response NOERROR"
				} else {
					result.Version = fmt.Sprintf("response RCODE %d", responseCode)
				}
			}
		}
		
		// Call generic service detection; it might overwrite or use the above if logic is refined there
		detectedService, detectedVersion := detectServiceWithTimeout(nil, port, "udp", serviceDetectionTimeout)
		if result.Service == "dns" && strings.HasPrefix(result.Version, "response") {
			// Keep more specific DNS info if already set
		} else {
			result.Service = detectedService
			result.Version = detectedVersion
		}

		result.OSGuess = guessOS(result)
		return result
	}
	return nil
}

type ServiceProbe struct {
	Name    string
	Probe   []byte
	Matcher func([]byte) (string, string)
}

// Add this after my existing probe definitions
var enhancedProbes = map[int]ServiceProbe{
	22: {
		Name:  "SSH",
		Probe: []byte("SSH-2.0-Scanner\r\n"),
		Matcher: func(response []byte) (string, string) {
			resp := string(response)
			if strings.Contains(resp, "SSH-") {
				lines := strings.Split(resp, "\n")
				if len(lines) > 0 {
					return "ssh", strings.TrimSpace(lines[0])
				}
			}
			return "ssh", "unknown"
		},
	},
	25: {
		Name:  "SMTP",
		Probe: []byte("EHLO scanner.local\r\n"),
		Matcher: func(response []byte) (string, string) {
			resp := string(response)
			// SMTP responses can be multiline. Look for common greeting codes.
			// A more robust parser would be needed for all SMTP variations.
			if strings.HasPrefix(resp, "220") { // Check for 220 service ready
				lines := strings.Split(resp, "\r\n") // SMTP uses CRLF
				for _, line := range lines {
					trimmedLine := strings.TrimSpace(line)
					if strings.HasPrefix(trimmedLine, "220") {
						// Extract the part after "220 "
						versionInfo := strings.TrimSpace(strings.TrimPrefix(trimmedLine, "220"))
						return "smtp", versionInfo
					}
				}
				return "smtp", "greeting received" // Generic if specific line not found
			}
			return "smtp", "unknown"
		},
	},
	// Port 80 and other HTTP ports will be handled by the HTTPProbe fallback
	443: { // For HTTPS, service detection often involves TLS handshake, then HTTP
		Name:  "HTTPS",
		Probe: []byte("GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: r3cond0g-scanner\r\nConnection: close\r\n\r\n"),
		Matcher: func(response []byte) (string, string) {
			resp := string(response)
			// This probe might get an HTTP response if sent over an already established TLS session
			// However, sending HTTP GET directly to 443 usually won't work without TLS.
			// True HTTPS detection requires a TLS handshake first.
			// For simplicity here, if we get any HTTP-like response, assume HTTPS.
			if strings.Contains(resp, "HTTP/") {
				return "https", extractServerHeader(resp)
			}
			// If no HTTP response, it's likely HTTPS but the probe was not understood.
			return "https", "unknown (requires TLS)"
		},
	},
}

// Helper function to extract server header from HTTP response
func extractServerHeader(response string) string {
	lines := strings.Split(response, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			// Trim "Server: " prefix and any extra spaces
			return strings.TrimSpace(line[len("Server:"):])
		}
	}
	return "unknown"
}

// HTTPProbe struct and Detect method (from original code, adapted for fallback)
type HTTPProbe struct{}

func (p *HTTPProbe) Detect(conn net.Conn) (string, string) {
	// Set a deadline for the probe operation itself to avoid hanging
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err := conn.Write([]byte("HEAD / HTTP/1.0\r\nHost: r3cond0g\r\nUser-Agent: r3cond0g-scanner\r\nConnection: close\r\n\r\n"))
	if err != nil {
		return "http", "unknown (write failed)"
	}

	buffer := make([]byte, 2048) // Increased buffer size
	conn.SetReadDeadline(time.Now().Add(3 * time.Second)) // Slightly longer read deadline
	n, err := conn.Read(buffer)
	if err != nil {
		// If it's a timeout or EOF, it might still be an HTTP server that didn't like HEAD or just closed.
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "http", "timeout on read"
		}
		if err == io.EOF {
			return "http", "connection closed by peer"
		}
		return "http", "unknown (read failed)"
	}

	response := string(buffer[:n])
	if strings.HasPrefix(response, "HTTP/") {
		return "http", extractServerHeader(response)
	}
	// If it's not starting with HTTP/, it could be another service or an error message.
	// For this probe, we assume it's not a clearly identifiable HTTP server.
	return "unknown", "non-http response"
}


// Enhanced service detection function - replace my existing one
func detectServiceWithTimeout(conn net.Conn, port int, protocol string, timeout time.Duration) (string, string) {
	// Default service mapping (expanded)
	services := map[int]string{
		21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
		80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 137: "netbios-ns",
		138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
		162: "snmptrap", 389: "ldap", 443: "https", 445: "microsoft-ds",
		465: "smtps", 514: "syslog", 587: "submission", 636: "ldaps",
		993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql",
		1521: "oracle", 1723: "pptp", 2049: "nfs", 3000: "http-alt",
		3268: "globalcatLDAP", 3269: "globalcatLDAPssl", 3306: "mysql",
		3389: "rdp", 5060: "sip", 5061: "sips", 5222: "xmpp-client",
		5432: "postgresql", 5900: "vnc", 5985: "winrm", 5986: "winrm-ssl",
		6379: "redis", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
		27017: "mongodb", 123: "ntp", 67: "dhcp-server", 68: "dhcp-client",
	}

	// Get default service name
	service, exists := services[port]
	if !exists {
		service = "unknown"
	}

	// Try enhanced probing for TCP ports if a connection is available
	if protocol == "tcp" && conn != nil {
		// Set overall deadline for this detection attempt
		deadline := time.Now().Add(timeout)
		conn.SetDeadline(deadline) // Apply to both read and write
		defer conn.SetDeadline(time.Time{}) // Clear deadline on exit

		if probe, exists := enhancedProbes[port]; exists {
			// Send probe
			conn.SetWriteDeadline(deadline) // Ensure write has a deadline
			if _, err := conn.Write(probe.Probe); err == nil {
				// Read response
				buffer := make([]byte, 4096) // Standard buffer size for service banners
				conn.SetReadDeadline(deadline) // Ensure read has a deadline
				if n, err := conn.Read(buffer); err == nil && n > 0 {
					return probe.Matcher(buffer[:n])
				} else if err != nil && err != io.EOF && !(netErr_probeRead_check(err))  {
					// If read error is not EOF or timeout, it might indicate a problem or unexpected response
					// Keep default service, but indicate "probe error" for version
					// return service, "probe read error" // This might be too noisy
				}
			} else if !(netErr_probeWrite_check(err)) {
				// return service, "probe write error" // This might be too noisy
			}
		}

		// Fallback to HTTP probe for common HTTP ports
		// Ensure HTTPProbe is only used if not already handled by enhancedProbes more specifically (e.g. port 443)
		if _, isEnhanced := enhancedProbes[port]; !isEnhanced {
			if port == 80 || port == 8080 || port == 3000 || port == 8000 || port == 8443 { // Common HTTP/S ports
				// Note: HTTPProbe is basic. For 8443 (HTTPS), it won't do TLS.
				// If port is 443, it's handled by enhancedProbes which also doesn't do full TLS, but is specific.
				return (&HTTPProbe{}).Detect(conn)
			}
		}
	} else if protocol == "udp" {
		// For UDP, conn is often nil in the current detectServiceWithTimeout call structure
		// We just return the default mapped service. True UDP service detection is more complex.
		// Specific UDP checks (like the DNS one in scanUDPPort) should ideally update result before this.
		return service, "unknown (UDP)"
	}


	return service, "unknown"
}

// Helper to check net.Error for timeout, used in detectServiceWithTimeout
func netErr_probeRead_check(err error) bool {
    if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
        return true
    }
    return false
}
func netErr_probeWrite_check(err error) bool {
    if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
        return true
    }
    return false
}


func getUDPProbe(port int) []byte {
	switch port {
	case 53: // DNS Standard Query
		return []byte{
			0xDB, 0x4B, /* Transaction ID */
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
		return []byte{
			0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		} // Standard NTP client request packet
	case 161: // SNMPv1 GetRequest (public community, sysDescr)
		return []byte{
			0x30, 0x26, // ASN.1 SEQUENCE
			0x02, 0x01, 0x00, // SNMP version 1 (0)
			0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // Community: "public"
			0xa0, 0x19, // PDU type: GetRequest (0)
			0x02, 0x04, 0x00, 0x00, 0x00, 0x00, // Request ID (can be anything)
			0x02, 0x01, 0x00, // Error status: noError (0)
			0x02, 0x01, 0x00, // Error index: 0
			0x30, 0x0b, // Variable bindings (SEQUENCE)
			0x30, 0x09, // VarBind (SEQUENCE)
			0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, // OID: .1.3.6.1.2.1.1.1.0 (sysDescr.0)
			0x05, 0x00, // Value: NULL
		}
	default:
		// Generic probe for other UDP ports, can be a simple string or specific bytes if known.
		return []byte("r3cond0g-probe")
	}
}

func isCommonUDPPort(port int) bool {
	// Expanded list of common UDP ports
	commonUDPPorts := []int{
		53,    // DNS
		67,    // DHCP Server
		68,    // DHCP Client
		69,    // TFTP
		123,   // NTP
		137,   // NetBIOS Name Service
		138,   // NetBIOS Datagram Service
		161,   // SNMP
		162,   // SNMPTRAP
		500,   // ISAKMP (IPsec)
		514,   // Syslog
		1812,  // RADIUS Authentication
		1813,  // RADIUS Accounting
		1900,  // SSDP
		4500,  // IPsec NAT Traversal
		5060,  // SIP
		5353,  // mDNS (Multicast DNS)
		11211, // Memcached
	}
	for _, p := range commonUDPPorts {
		if port == p {
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
			if strings.Contains(versionLower, "win32") || strings.Contains(versionLower, "win64") {
				return "Windows"
			}
			return "Linux/Unix"
		} else if strings.Contains(versionLower, "nginx") {
			return "Linux/Unix" // Nginx is more common on Linux
		}
	}
	if strings.Contains(serviceLower, "ssh") {
		if strings.Contains(versionLower, "openssh") && !strings.Contains(versionLower, "windows") {
			return "Linux/Unix"
		} else if strings.Contains(versionLower, "dropbear") {
			return "Linux/Embedded"
		}
	}
	if serviceLower == "rdp" || (serviceLower == "ms-wbt-server") { // ms-wbt-server is RDP
		return "Windows"
	}
	if serviceLower == "microsoft-ds" || serviceLower == "netbios-ssn" { // SMB/CIFS
		return "Windows" // Often Windows, but Samba can be on Linux
	}
	if serviceLower == "winrm" {
		return "Windows"
	}

	// Check for clues in port numbers if service/version is generic
	switch result.Port {
	case 135, 139, 445, 3389, 5985:
		if result.OSGuess == "" || result.OSGuess == "Unknown" { // Only if not already guessed
			return "Windows (likely)"
		}
	}

	return "Unknown"
}

// Removed old Probe interface and portProbes map as they are superseded by ServiceProbe and enhancedProbes


func queryNVD(cpe string) ([]string, error) {
	// Wait for rate limiter before making request
	if err := limiter.Wait(context.Background()); err != nil {
		return nil, err
	}

	// Use the newer NVD API 2.0 endpoint with proper authentication
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=%s", cpe)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Set proper headers for NVD API 2.0
	req.Header.Set("User-Agent", "r3cond0g/"+VERSION+" (Security Scanner)")
	req.Header.Set("Accept", "application/json")

	// Add API key if provided - this is crucial for avoiding 403 errors
	if config.NVDAPIKey != "" {
		req.Header.Set("apiKey", config.NVDAPIKey)
		// Increase rate limit for authenticated requests (50 requests per 30 seconds)
		// Ensure limiter is updated safely if multiple goroutines could call this, though it seems sequential for now
		// For simplicity, this assignment is okay if performVulnerabilityMapping calls this sequentially.
		// If concurrent calls to queryNVD are possible with different key states, this needs a mutex.
		limiter = rate.NewLimiter(rate.Every(30*time.Second/50), 50) // Burst of 50, 50 req/30s
	} else {
		// Without API key, we're limited (NVD default is 5 req/30s, or 10 with API key paying per call eventually)
		// The problem states 5 req/30s as the base.
		limiter = rate.NewLimiter(rate.Every(30*time.Second/5), 5) // Burst of 5, 5 req/30s
		fmt.Println("⚠️  Warning: No NVD API key configured. Rate limited. https://nvd.nist.gov/developers/request-an-api-key")
	}

	// Implement retry logic with exponential backoff
	for attempts := 0; attempts < 3; attempts++ {
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("HTTP request failed: %v", err)
		}

		// Handle different HTTP status codes appropriately
		switch resp.StatusCode {
		case 429: // Too Many Requests
			// Rate limited - wait and retry
			// Try to get Retry-After header
			retryAfterStr := resp.Header.Get("Retry-After")
			var waitTime time.Duration
			if retryAfterSeconds, err := strconv.Atoi(retryAfterStr); err == nil {
				waitTime = time.Duration(retryAfterSeconds) * time.Second
			} else {
				// Fallback to exponential backoff if Retry-After is not available or invalid
				waitTime = time.Duration(math.Pow(2, float64(attempts))) * time.Second
			}
			fmt.Printf("⏳ NVD API rate limited (429). Waiting %v before retry %d/3\n", waitTime, attempts+1)
			time.Sleep(waitTime)
			resp.Body.Close() // Close body before next attempt
			continue
		case 403: // Forbidden
			resp.Body.Close()
			// Check if it's due to API key issue or other reasons
			bodyBytes, _ := io.ReadAll(resp.Body) // Try to read body for more info
			errorMsg := fmt.Sprintf("NVD API access forbidden (403) - check your API key or request quota. Response: %s", string(bodyBytes))
			if config.NVDAPIKey == "" {
				errorMsg = "NVD API access forbidden (403). An API key is highly recommended. https://nvd.nist.gov/developers/request-an-api-key"
			}
			return nil, fmt.Errorf(errorMsg)
		case 404: // Not Found
			resp.Body.Close()
			// No CVEs found for this CPE, or CPE is malformed, or endpoint error
			// Check body for more specific message if needed
			// For now, assume it means no CVEs found.
			return []string{}, nil // Return empty slice, not an error
		case 200: // OK
			// Success - parse the response
			// Parse the updated NVD 2.0 API response format
			var nvdResp struct {
				// ResultsPerPage  int `json:"resultsPerPage"`
				// StartIndex      int `json:"startIndex"`
				// TotalResults    int `json:"totalResults"`
				// Format          string `json:"format"`
				// Version         string `json:"version"`
				// Timestamp       string `json:"timestamp"`
				Vulnerabilities []struct {
					CVE struct {
						ID string `json:"id"`
						// ... other CVE fields if needed ...
					} `json:"cve"`
				} `json:"vulnerabilities"`
			}

			if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
				resp.Body.Close()
				return nil, fmt.Errorf("failed to parse NVD response JSON: %v", err)
			}
			resp.Body.Close()

			var cves []string
			for _, vuln := range nvdResp.Vulnerabilities {
				cves = append(cves, vuln.CVE.ID)
			}
			return cves, nil
		default: // Other errors
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("NVD API returned status %d. Response: %s", resp.StatusCode, string(bodyBytes))
		}
	}

	return nil, fmt.Errorf("max retries exceeded for NVD API")
}

func findSimilarKey(key string) string {
	parts := strings.Split(key, " ")
	if len(parts) < 2 {
		return ""
	}
	service := parts[0]
	// Version might have multiple parts, e.g., "Apache 2.4.49" -> service="Apache", versionParts=["2.4.49"]
	// Or "OpenSSH 7.6p1" -> service="OpenSSH", versionParts=["7.6p1"]

	// Attempt to match based on service and major.minor version
	// This is a simple heuristic and might need refinement
	var bestMatch string
	highestSimilarity := 0

	for dbKey := range vulnDB {
		dbParts := strings.Split(dbKey, " ")
		if len(dbParts) < 2 {
			continue
		}
		dbService := dbParts[0]
		// dbVersion := strings.Join(dbParts[1:], " ")

		currentSimilarity := 0
		if strings.EqualFold(service, dbService) {
			currentSimilarity += 5 // Strong match for service name

			// Try to match version components
			// Example: key "http Apache 2.4.49", dbKey "http Apache 2.4.50"
			// This is a very basic similarity check
			if len(parts) > 1 && len(dbParts) > 1 {
				 versionPartKey := parts[1] // e.g., "Apache" from "http Apache..."
				 versionPartDb := dbParts[1] // e.g., "Apache" from "http Apache..."
				 if strings.EqualFold(versionPartKey, versionPartDb) {
					 currentSimilarity += 3
				 }
				 if len(parts) > 2 && len(dbParts) > 2 {
					 numericVersionKey := parts[2] // e.g., "2.4.49"
					 numericVersionDb := dbParts[2] // e.g., "2.4.50"

					 keyVerMajorMinor := strings.Join(strings.Split(numericVersionKey, ".")[:2], ".")
					 dbVerMajorMinor := strings.Join(strings.Split(numericVersionDb, ".")[:2], ".")
					 if keyVerMajorMinor == dbVerMajorMinor {
						 currentSimilarity +=2
					 }
				 }
			}
		}
		if currentSimilarity > highestSimilarity {
			highestSimilarity = currentSimilarity
			bestMatch = dbKey
		}
	}
	if highestSimilarity > 5 { // Require at least a service name match and some version similarity
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
		fmt.Printf("❌ Error opening CVE plugin file: %v\n", err)
		return
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		fmt.Printf("❌ Error reading CVE plugin file: %v\n", err)
		return
	}
	if err := json.Unmarshal(data, &customCVEs); err != nil {
		fmt.Printf("❌ Error parsing CVE plugin file (ensure it's a JSON map of 'service version': ['CVE-XXXX-XXXX']): %v\n", err)
		return
	}
	fmt.Printf("✅ Loaded %d custom CVE mappings from %s\n", len(customCVEs), config.CVEPluginFile)
}

func runUltraFastScan() []EnhancedScanResult {
	fmt.Println("🚀 Starting optimized ultra-fast scan...")

	// Parse and validate targets
	hosts := parseTargets(config.TargetHost, config.TargetFile)
	if len(hosts) == 0 {
		fmt.Println("❌ No valid targets found. Please check your target configuration.")
		return nil
	}

	// Parse and validate ports
	ports := parsePortRange(config.PortRange)
	if len(ports) == 0 {
		fmt.Println("❌ No valid ports found. Please check your port range configuration.")
		return nil
	}

	// Calculate total scan operations
	// Note: This count is for TCP ports. If UDP is also enabled, each port is scanned twice (TCP then UDP).
	// The progress bar will reflect individual port scan attempts (TCP or UDP).
	// So, if UDP is enabled, the actual "operations" seen by the progress bar will be double.
	// Let's adjust totalScans to reflect atomic operations for progress reporting.
	totalScansPerProtocol := int64(len(hosts) * len(ports))
	totalScans := totalScansPerProtocol
	if config.UDPScan {
		totalScans *= 2 // Each port effectively becomes two scan operations (TCP + UDP)
	}


	fmt.Printf("📊 Scanning %d hosts across %d ports. Total TCP scan points: %d. Total operations (TCP+UDP if enabled): %d\n",
		len(hosts), len(ports), totalScansPerProtocol, totalScans)


	// Warn for large scans and get user confirmation
	if totalScans > 50000 { // Threshold for "large scan"
		fmt.Printf("⚠️  Large scan detected (%d operations). This may take significant time.\n", totalScans)
		fmt.Print("Continue? (y/N): ")
		var response string
		fmt.Scanln(&response)
		if !strings.EqualFold(response, "y") && !strings.EqualFold(response, "yes") {
			fmt.Println("❌ Scan cancelled by user.")
			return nil
		}
	}

	// Initialize scanning infrastructure
	sem = make(chan struct{}, config.MaxConcurrency)
	results = nil // Clear previous results
	atomic.StoreInt64(&scannedPorts, 0) // Reset counter
	start := time.Now()

	// Progress reporting goroutine
	progressTicker := time.NewTicker(1 * time.Second) // Update progress every second
	defer progressTicker.Stop()

	var displayMutex sync.Mutex // To protect fmt.Printf for progress updates

	go func() {
		for range progressTicker.C {
			current := atomic.LoadInt64(&scannedPorts)
			if totalScans == 0 { // Avoid division by zero
				continue
			}
			if current > 0 { // Only update if progress has started
				if current > totalScans { current = totalScans } // Cap current at totalScans for display
				percentage := float64(current) / float64(totalScans) * 100
				elapsed := time.Since(start)
				var rate float64
				if elapsed.Seconds() > 0 {
					rate = float64(current) / elapsed.Seconds()
				} else {
					rate = 0
				}
				var eta time.Duration
				if rate > 0 && current < totalScans {
					eta = time.Duration(float64(totalScans-current)/rate) * time.Second
				} else {
					eta = 0
				}
				
				displayMutex.Lock()
				// \r moves cursor to beginning of line. ANSI escape sequence \033[K clears from cursor to end of line.
				fmt.Printf("\r\033[K🔍 Progress: %d/%d (%.1f%%) | Rate: %.0f ops/sec | ETA: %v | Found: %d open",
					current, totalScans, percentage, rate, eta.Round(time.Second), len(results))
				displayMutex.Unlock()
			}
		}
	}()

	// Prioritize common ports for faster results
	commonPorts := []int{80, 443, 22, 21, 25, 53, 135, 139, 445, 993, 995, 3389, 5985, 8080,
						110, 143, 3306, 5432, 6379, 27017, 161, 123} // Added more common ports
	priorityPorts := []int{}
	regularPorts := []int{}

	// Separate common ports from regular ports
	portSet := make(map[int]bool)
	for _, p := range ports {
		portSet[p] = true
	}

	for _, p := range commonPorts {
		if portSet[p] {
			priorityPorts = append(priorityPorts, p)
			delete(portSet, p) // Remove from set so it's not added to regularPorts
		}
	}

	for p := range portSet { // Add remaining ports
		regularPorts = append(regularPorts, p)
	}
	
	// Combine ports: priority first, then regular. This ensures all specified ports are scanned.
	orderedPortsToScan := append(priorityPorts, regularPorts...)


	// Launch goroutines for scanning
	for _, host := range hosts {
		for _, port := range orderedPortsToScan { // Iterate over the combined, ordered list
			wg.Add(1) // Increment WaitGroup counter before launching goroutine
			go scanPortWithRecovery(host, port, &displayMutex) // Pass displayMutex
		}
	}

	// Wait for all scans to complete
	wg.Wait()
	time.Sleep(100 * time.Millisecond) // Brief pause to allow final progress update to render if needed
	progressTicker.Stop()          // Stop the ticker explicitly
	
	currentScanned := atomic.LoadInt64(&scannedPorts) // Ensure final value is loaded
	if currentScanned > totalScans { currentScanned = totalScans } // Cap for display

	displayMutex.Lock() // Ensure final progress line doesn't get overwritten
	fmt.Printf("\r\033[K🔍 Progress: %d/%d (100.0%%) | Scan Complete.                                          \n", currentScanned, totalScans)
	displayMutex.Unlock()


	// Calculate and display final statistics
	elapsed := time.Since(start)
	fmt.Printf("✅ Scan completed in %v\n", elapsed.Round(time.Second))
	fmt.Printf("📊 Found %d open ports/services across %d hosts\n", len(results), len(hosts))

	if totalScans > 0 && elapsed.Seconds() > 0 {
		fmt.Printf("⚡ Average scan rate: %.0f operations/second\n", float64(totalScans)/elapsed.Seconds())
	}

	// Show top services found
	if len(results) > 0 {
		serviceCount := make(map[string]int)
		for _, result := range results {
			if result.State == "open" || strings.Contains(result.State, "open") { // Count open or open|filtered
				serviceCount[result.Service]++
			}
		}

		if len(serviceCount) > 0 {
			fmt.Println("🎯 Top services discovered:")
			// For sorting, can convert map to a slice of structs if needed, but simple iteration is fine for now.
			for service, count := range serviceCount {
				if count > 0 {
					fmt.Printf("    %s: %d ports\n", service, count)
				}
			}
		}
	}
	return results
}


// Wrapper function for port scanning with panic recovery
func scanPortWithRecovery(host string, port int, displayMutex *sync.Mutex) {
	defer wg.Done() // Decrement counter when goroutine finishes
	defer func() {
		if r := recover(); r != nil {
			displayMutex.Lock()
			fmt.Printf("\n❌ Panic recovered while scanning %s:%d: %v\n", host, port, r)
			displayMutex.Unlock()
		}
		<-sem // Release semaphore slot
	}()

	sem <- struct{}{} // Acquire semaphore slot

	// Scan TCP port
	if resultTCP := scanTCPPort(host, port); resultTCP != nil {
		// Map vulnerabilities if enabled
		if config.VulnMapping {
			mapVulnerabilities(resultTCP) // mapVulnerabilities modifies resultTCP directly
		}

		// Thread-safe result storage
		mutex.Lock()
		results = append(results, *resultTCP)
		mutex.Unlock()
		
		displayMutex.Lock()
		// \r\033[K ensures that this line overwrites the progress bar cleanly
		fmt.Printf("\r\033[K✅ Found TCP: %s:%d (%s %s)\n", host, port, resultTCP.Service, resultTCP.Version)
		displayMutex.Unlock()
	}
	atomic.AddInt64(&scannedPorts, 1) // Increment for TCP scan attempt

	// Scan UDP port if enabled
	if config.UDPScan {
		if resultUDP := scanUDPPort(host, port); resultUDP != nil {
			if config.VulnMapping {
				mapVulnerabilities(resultUDP)
			}

			mutex.Lock()
			results = append(results, *resultUDP)
			mutex.Unlock()
			
			displayMutex.Lock()
			fmt.Printf("\r\033[K✅ Found UDP: %s:%d (%s %s)\n", host, port, resultUDP.Service, resultUDP.Version)
			displayMutex.Unlock()
		}
		atomic.AddInt64(&scannedPorts, 1) // Increment for UDP scan attempt
	}
}


func validateConfig() bool {
	fmt.Println("🔧 Validating configuration...")
	isValid := true
	if config.TargetHost == "" && config.TargetFile == "" {
		fmt.Println("❌ No target specified. Please set either target host or target file.")
		isValid = false
	}
	ports := parsePortRange(config.PortRange)
	if len(ports) == 0 {
		fmt.Println("❌ Invalid port range specified.")
		isValid = false
	}
	if config.TargetFile != "" {
		if _, err := os.Stat(config.TargetFile); os.IsNotExist(err) {
			fmt.Printf("❌ Target file does not exist: %s\n", config.TargetFile)
			isValid = false
		}
	}
	if config.ScanTimeout < 50 || config.ScanTimeout > 60000 { // Adjusted min timeout slightly
		fmt.Println("⚠️  Warning: Scan timeout should generally be between 50ms and 60000ms. Current:", config.ScanTimeout, "ms")
	}
	if config.MaxConcurrency < 1 || config.MaxConcurrency > 5000 { // Adjusted max concurrency
		fmt.Println("⚠️  Warning: Max concurrency should generally be between 1 and 5000. Current:", config.MaxConcurrency)
	}
	if config.VulnMapping && config.NVDAPIKey == "" {
		fmt.Println("⚠️  Warning: Vulnerability mapping is enabled, but no NVD API key is set. This will severely limit NVD queries. Consider setting NVD_API_KEY or using the --nvd-key flag, or configure it in settings.")
	}


	if isValid {
		fmt.Println("✅ Configuration validation complete.")
	} else {
		fmt.Println("❌ Configuration validation failed.")
	}
	return isValid
}

func debugCIDRParsing(cidr string) {
	fmt.Printf("🔍 Debug: Parsing CIDR/Target %s\n", cidr)
	ips := parseSingleTarget(cidr)
	fmt.Printf("📊 Generated %d IP addresses:\n", len(ips))
	displayCount := len(ips)
	if displayCount > 20 { // Show a bit more for debugging
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
		fmt.Printf("❌ Error opening Nmap file: %v\n", err)
		return
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		fmt.Printf("❌ Error reading Nmap file: %v\n", err)
		return
	}
	var nmapRun NmapRun
	if err := xml.Unmarshal(data, &nmapRun); err != nil {
		fmt.Printf("❌ Error parsing Nmap XML: %v\n", err)
		return
	}
	
	newResults := []EnhancedScanResult{} // Create a new slice for parsed results
	parsedCount := 0
	for _, host := range nmapRun.Hosts {
		if host.Address.Addr == "" { // Skip hosts with no address
			continue
		}
		for _, port := range host.Ports.Ports {
			if !config.OnlyOpenPorts || strings.ToLower(port.State.State) == "open" {
				result := EnhancedScanResult{
					Host:      host.Address.Addr,
					Port:      port.PortID,
					Protocol:  port.Protocol,
					State:     port.State.State,
					Service:   port.Service.Name,
					Version:   strings.TrimSpace(port.Service.Version), // Trim whitespace from version
					Timestamp: time.Now().UTC(), // Use UTC for consistency
					// ResponseTime is not available from Nmap XML in this simple parse, set to 0 or omit
				}
				// OS Guess from Nmap is more complex, would need to parse <os> tags.
				// For now, OSGuess will be re-evaluated by our guessOS if vuln mapping is on, or remain blank.
				
				if config.VulnMapping { // Perform vulnerability mapping if enabled
					mapVulnerabilities(&result) // mapVulnerabilities modifies result directly
				}
				if result.OSGuess == "" || result.OSGuess == "Unknown" { // If not set by vuln mapping or Nmap
					result.OSGuess = guessOS(&result) // Try our own guessOS
				}
				newResults = append(newResults, result)
				parsedCount++
			}
		}
	}
	results = newResults // Replace existing results with Nmap parsed data
	fmt.Printf("✅ Parsed %d ports from Nmap results file: %s\n", parsedCount, config.NmapResultsFile)
	if len(results) > 0 {
		displayResults() // Optionally display results immediately
	}
}


func mapVulnerabilities(result *EnhancedScanResult) {
	if !config.VulnMapping {
		return
	}

	// Create a service+version key. Normalize service name to lowercase for consistency in map lookups.
	// Version matching can be case-sensitive or require normalization depending on data sources.
	// For CPEs, version numbers are typically case-sensitive if they include letters.
	serviceKey := strings.ToLower(result.Service)
	versionKey := result.Version // Preserve original case for version unless specific normalization is needed

	// Key for customCVEs and nvdCache can be more flexible.
	// Using "service version" (original case for version) for now.
	// key := fmt.Sprintf("%s %s", serviceKey, versionKey) // This variable 'key' was not used, removed.


	// Check custom CVE database first (assumes customCVEs keys are "service version")
	// Normalize lookup key for customCVEs as well if its keys are normalized
	// For now, assume customCVEs keys might be "serviceKey versionKey" or similar.
	// Let's try a few variations for custom key lookup or ensure customCVEs keys are consistently formatted.
	// For simplicity, let's assume customCVEs keys are like "servicelower versionOriginal"
	customLookupKey := fmt.Sprintf("%s %s", strings.ToLower(result.Service), result.Version)
	if vulns, ok := customCVEs[customLookupKey]; ok {
		result.Vulnerabilities = vulns
		return
	}
	// Fallback: try with service name as is (if custom DB uses that)
	customLookupKeyAlt := fmt.Sprintf("%s %s", result.Service, result.Version)
	if vulns, ok := customCVEs[customLookupKeyAlt]; ok {
		result.Vulnerabilities = vulns
		return
	}


	// Check cache to avoid repeated API calls (using the same key structure)
	cacheKey := fmt.Sprintf("%s %s", serviceKey, versionKey) // Consistent cache key
	if cached, found := nvdCache.Load(cacheKey); found {
		if cvs, ok := cached.([]string); ok {
			result.Vulnerabilities = cvs
			return
		}
	}

	// Handle unknown/empty versions gracefully
	if versionKey == "" || strings.ToLower(versionKey) == "unknown" {
		result.Vulnerabilities = []string{"Version detection failed - manual verification needed"}
		return
	}

	// Map service to CPE format (serviceToCPE uses lowercase service names as keys)
	vp, ok := serviceToCPE[serviceKey]
	if !ok {
		result.Vulnerabilities = []string{fmt.Sprintf("Service '%s' not in local CPE mapping database", result.Service)}
		return
	}

	// Construct proper CPE string. CPEs are case-sensitive in parts, esp. product/vendor. Version needs to be exact.
	// Format: cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*
	// Ensure versionKey is clean (e.g., no leading/trailing spaces, though it should be from detection)
	cpe := fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vp.Vendor, vp.Product, versionKey)
	// Sometimes versions in NVD have prefixes like 'v'. This is complex to generalize.
	// For now, we use the detected version as is.

	// Query NVD with proper error handling
	vulns, err := queryNVD(cpe) // queryNVD handles retries and API key usage
	if err != nil {
		// Log error but don't spam console excessively during mass scans.
		// The error from queryNVD is already descriptive.
		result.Vulnerabilities = []string{fmt.Sprintf("Vulnerability lookup error: %s", err.Error())}
		// Optionally, cache this error state for a short period to avoid re-querying failing CPEs too fast
		// nvdCache.Store(cacheKey, result.Vulnerabilities) // Cache the error message to avoid retries
		return
	}

	// Cache the result for future use (even if empty, to show it was queried)
	nvdCache.Store(cacheKey, vulns)
	result.Vulnerabilities = vulns

	// If no CVEs found from NVD, try fuzzy matching with local vulnDB
	if len(vulns) == 0 {
		// vulnDB matching key is typically "service version" string
		// Create a lookup key matching vulnDB's expected format.
		// Assuming vulnDB keys are like "http Apache 2.4.49" (original service name, space, version)
		fuzzyLookupKey := fmt.Sprintf("%s %s", result.Service, versionKey)
		if similarKey := findSimilarKey(fuzzyLookupKey); similarKey != "" {
			if fallbackVulns, ok := vulnDB[similarKey]; ok {
				// Prepend to distinguish from direct NVD results
				combinedVulns := []string{"(fuzzy match from local DB):"}
				combinedVulns = append(combinedVulns, fallbackVulns...)
				result.Vulnerabilities = combinedVulns // Replace, or append based on desired behavior
			}
		}
	}
	
	// If still no vulnerabilities found after all checks, indicate this.
	if len(result.Vulnerabilities) == 0 {
		result.Vulnerabilities = []string{"No known vulnerabilities found"}
	}
}


func performVulnerabilityMapping() {
	if len(results) == 0 {
		fmt.Println("❌ No scan results available. Run a scan or parse Nmap results first.")
		return
	}
	if config.NVDAPIKey == "" {
		fmt.Println("⚠️  NVD API Key not set. Vulnerability mapping quality will be reduced.")
		apiKey := askForString("🔑 Enter NVD API Key (or press Enter to skip for this session): ")
		if apiKey != "" {
			config.NVDAPIKey = apiKey
		}
	}

	fmt.Println("🔍 Mapping vulnerabilities for available results...")
	var mappedCount int32
	var wgVuln sync.WaitGroup
	// Using a semaphore to limit concurrent calls to mapVulnerabilities, esp. if queryNVD is slow
	// NVD API has its own rate limiter, but this can prevent overwhelming local resources or too many pending HTTP requests
	vulnSem := make(chan struct{}, 10) // Limit concurrent NVD lookups if many results

	for i := range results { // Iterate by index to modify the slice elements directly
		// Skip if vulnerabilities already populated (e.g., from Nmap parse with vuln mapping)
		// This check might be too simple if "No known vulnerabilities" is a valid populated state we want to re-check.
		// For now, if it has more than one entry, or the single entry isn't a placeholder, assume mapped.
		if len(results[i].Vulnerabilities) > 0 && !(len(results[i].Vulnerabilities) == 1 && (results[i].Vulnerabilities[0] == "Version detection failed - manual verification needed" || results[i].Vulnerabilities[0] == "Service not in vulnerability database")) {
			// fmt.Printf("\r🔍 Skipping already mapped: %s:%d", results[i].Host, results[i].Port)
			// continue
		}

		wgVuln.Add(1)
		go func(idx int) {
			defer wgVuln.Done()
			vulnSem <- struct{}{}
			defer func() { <-vulnSem }()

			// Make a copy to avoid race conditions if other parts of the app read `results[idx]` concurrently
			// However, mapVulnerabilities is designed to modify the passed-in pointer.
			// The loop `for i := range results` gives us `results[i]` which is a copy if `results` contains structs,
			// but we are passing a pointer `&results[i]`.
			// Since `runUltraFastScan` finishes before this, direct modification should be fine.
			mapVulnerabilities(&results[idx])
			atomic.AddInt32(&mappedCount, 1)
			fmt.Printf("\r🔍 Processed vulnerability mapping for %d/%d results...", atomic.LoadInt32(&mappedCount), len(results))
		}(i)
	}
	wgVuln.Wait()
	fmt.Printf("\n✅ Vulnerability mapping completed for %d results.\n", mappedCount)
	displayResults() // Show updated results
}


func generateTopologyMap() {
	if len(results) == 0 {
		fmt.Println("❌ No scan results available. Run a scan first.")
		return
	}
	fmt.Println("🌐 Generating network topology map...")
	var dotGraph strings.Builder
	dotGraph.WriteString("digraph NetworkTopology {\n") // Changed to digraph for better layout control typically
	dotGraph.WriteString("  rankdir=LR;\n")
	dotGraph.WriteString("  node [shape=record, style=\"rounded,filled\", fillcolor=lightblue];\n")
	dotGraph.WriteString("  edge [style=dashed, color=gray];\n") // Default edge style

	// Group ports by host
	hostServices := make(map[string]map[string][]string) // host -> {service -> [port/proto, port/proto]}

	for _, result := range results {
		if strings.ToLower(result.State) == "open" || strings.Contains(strings.ToLower(result.State), "open") { // Consider open or open|filtered
			if _, ok := hostServices[result.Host]; !ok {
				hostServices[result.Host] = make(map[string][]string)
			}
			serviceKey := result.Service
			if serviceKey == "" || serviceKey == "unknown" {
				serviceKey = fmt.Sprintf("port_%d", result.Port)
			}
			portProto := fmt.Sprintf("%d/%s", result.Port, result.Protocol)
			hostServices[result.Host][serviceKey] = append(hostServices[result.Host][serviceKey], portProto)
		}
	}
	
	// Define nodes (hosts) with services listed
	for host, servicesMap := range hostServices {
		var serviceDetails []string
		for service, portsProtos := range servicesMap {
			serviceDetails = append(serviceDetails, fmt.Sprintf("%s: %s", service, strings.Join(portsProtos, ", ")))
		}
		label := fmt.Sprintf("{%s|%s}", host, strings.Join(serviceDetails, "\\n"))
		dotGraph.WriteString(fmt.Sprintf("  \"%s\" [label=\"%s\"];\n", host, label))
	}

	// Could add edges based on some logic, e.g., if a service on one host typically connects to another.
	// For a simple port scan, direct connections aren't discovered, so we just list hosts.
	// Example: if we knew hostA:webserver talks to hostB:database
	// dotGraph.WriteString(fmt.Sprintf("  \"%s\" -> \"%s\" [label=\"db connect\"];\n", "hostA_fqdn", "hostB_fqdn"));
    // // To make this practical, the scan would need to discover relationships,
    // // or this information would come from another source (e.g., netflow data, application config).
    // // For instance, if service detection on one host identified it as a client connecting 
    // // to a specific remote IP/service that was also in the scan results:
    // for _, result := range results {
    //     if result.Host == "client.example.com" && result.Service == "myapp_client" && strings.Contains(result.Version, "connects_to_db.example.com") {
    //         // Check if "db.example.com" is a known host in hostServices
    //         if _, ok := hostServices["db.example.com"]; ok {
    //             dotGraph.WriteString(fmt.Sprintf("  \"%s\" -> \"%s\" [label=\"identified db connection\"];\n", "client.example.com", "db.example.com"))
    //         }
    //     }
    // }


	dotGraph.WriteString("}\n")
	filename := fmt.Sprintf("%s_topology.dot", strings.ReplaceAll(config.OutputFile, ".", "_"))
	if err := os.WriteFile(filename, []byte(dotGraph.String()), 0644); err != nil {
		fmt.Printf("❌ Failed to write topology file: %v\n", err)
		return
	}
	fmt.Printf("✅ Network topology map (DOT format) saved to %s\n", filename)
	fmt.Println("💡 Use Graphviz to visualize: dot -Tpng ",filename," -o ", strings.ReplaceAll(filename, ".dot", ".png"))
}


func displayResults() {
	if len(results) == 0 {
		fmt.Println("❌ No results to display. Run a scan or parse Nmap results first.")
		return
	}

	// Create a filtered list if OnlyOpenPorts is true
	displayData := results
	if config.OnlyOpenPorts {
		filteredResults := []EnhancedScanResult{}
		for _, result := range results {
			if strings.ToLower(result.State) == "open" || strings.Contains(strings.ToLower(result.State), "open|filtered") {
				filteredResults = append(filteredResults, result)
			}
		}
		displayData = filteredResults
	}

	if len(displayData) == 0 {
		if config.OnlyOpenPorts {
			fmt.Println("ℹ️  No open (or open|filtered) ports to display based on current filter.")
		} else {
			fmt.Println("ℹ️  No results to display.")
		}
		return
	}


	fmt.Printf("\n📊 Scan Results (%d ports matching filter):\n", len(displayData))
	// Dynamic column widths could be calculated, but for now, use fixed reasonable ones.
	// Host (18) | Port (5) | Proto (8) | State (12) | Service (18) | Version (25) | Vulns (15) | OS (15)
	fmt.Println("┌────────────────────┬───────┬──────────┬──────────────┬────────────────────┬───────────────────────────┬─────────────────┬─────────────────┐")
	fmt.Println("│ Host               │ Port  │ Protocol │ State        │ Service            │ Version                   │ Vulnerabilities │ OS Guess        │")
	fmt.Println("├────────────────────┼───────┼──────────┼──────────────┼────────────────────┼───────────────────────────┼─────────────────┼─────────────────┤")

	for _, result := range displayData {
		vulnStr := "N/A" // Default if no vulns or not checked
		if config.VulnMapping {
			if len(result.Vulnerabilities) == 0 {
				vulnStr = "None found"
			} else if len(result.Vulnerabilities) == 1 && (result.Vulnerabilities[0] == "No known vulnerabilities found" || strings.HasPrefix(result.Vulnerabilities[0], "Version detection failed") || strings.HasPrefix(result.Vulnerabilities[0], "Service not in") || strings.HasPrefix(result.Vulnerabilities[0], "Vulnerability lookup error")) {
				vulnStr = result.Vulnerabilities[0] // Show specific message
			} else if len(result.Vulnerabilities) > 0 {
				// Show count or first few. For table, count is better.
				vulnStr = fmt.Sprintf("%d CVEs", len(result.Vulnerabilities))
				if strings.Contains(result.Vulnerabilities[0], "fuzzy match") {
					vulnStr += " (local)"
				}
			}
		}


		// Truncate long strings to fit columns
		hostStr := truncateString(result.Host, 18)
		serviceStr := truncateString(result.Service, 18)
		versionStr := truncateString(result.Version, 25)
		vulnDisplayStr := truncateString(vulnStr, 15)
		osGuessStr := truncateString(result.OSGuess, 15)
		stateStr := truncateString(result.State, 12)


		fmt.Printf("│ %-18s │ %-5d │ %-8s │ %-12s │ %-18s │ %-25s │ %-15s │ %-15s │\n",
			hostStr, result.Port, result.Protocol,
			stateStr, serviceStr, versionStr, vulnDisplayStr, osGuessStr)
	}
	fmt.Println("└────────────────────┴───────┴──────────┴──────────────┴────────────────────┴───────────────────────────┴─────────────────┴─────────────────┘")
}

func truncateString(s string, maxLen int) string {
	if len(s) > maxLen {
		if maxLen > 3 {
			return s[:maxLen-3] + "..."
		}
		return s[:maxLen]
	}
	return s
}


func saveResults() {
	if len(results) == 0 {
		fmt.Println("❌ No results to save. Run a scan first.")
		return
	}
	filename := fmt.Sprintf("%s.json", config.OutputFile)
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("❌ Error marshaling results to JSON: %v\n", err)
		return
	}
	if err := os.WriteFile(filename, data, 0644); err != nil {
		fmt.Printf("❌ Error writing JSON file: %v\n", err)
		return
	}
	fmt.Printf("✅ JSON results saved to %s\n", filename)
}

func exportResults() {
	if len(results) == 0 {
		fmt.Println("❌ No results to export. Run a scan first.")
		return
	}
	fmt.Println("📤 Choose export format:")
	fmt.Println("1. JSON (Default save format)")
	fmt.Println("2. CSV")
	fmt.Println("3. XML")
	fmt.Println("4. HTML Report")
	fmt.Print("Choose format: ")
	choice := getUserChoice()
	switch choice {
	case 1:
		exportJSON()
	case 2:
		exportCSV()
	case 3:
		exportXML()
	case 4:
		exportHTML()
	default:
		fmt.Println("❌ Invalid choice.")
	}
}

func exportJSON() {
	saveResults() // Leverages the existing JSON save function
}

func exportCSV() {
	if len(results) == 0 { // Redundant check, but good practice
		fmt.Println("❌ No results to export for CSV.")
		return
	}
	filename := fmt.Sprintf("%s.csv", config.OutputFile)
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("❌ Error creating CSV file: %v\n", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file) // Use bufio.Writer for better performance

	// Write CSV Header
	header := []string{"Host", "Port", "Protocol", "State", "Service", "Version", "ResponseTime(ms)", "Timestamp", "Vulnerabilities", "OSGuess"}
	writer.WriteString(strings.Join(header, ",") + "\n")

	for _, result := range results {
		// Prepare vulnerability string: join with semicolon, escape commas if any CVE ID contains them (unlikely but possible)
		vulnStr := strings.ReplaceAll(strings.Join(result.Vulnerabilities, "; "), "\"", "\"\"")

		// Prepare other fields, ensure commas within fields are handled (e.g., by quoting)
		// For simplicity, we'll just ensure strings are clean. Proper CSV libraries handle this better.
		record := []string{
			result.Host,
			strconv.Itoa(result.Port),
			result.Protocol,
			result.State,
			strings.ReplaceAll(result.Service, ",", " "), // Basic comma sanitization
			strings.ReplaceAll(result.Version, ",", " "), // Basic comma sanitization
			strconv.FormatInt(result.ResponseTime.Milliseconds(), 10),
			result.Timestamp.Format(time.RFC3339),
			vulnStr, // Already processed
			strings.ReplaceAll(result.OSGuess, ",", " "), // Basic comma sanitization
		}
		writer.WriteString(strings.Join(record, ",") + "\n")
	}
	writer.Flush() // Ensure all buffered data is written to the file
	fmt.Printf("✅ CSV results exported to %s\n", filename)
}

func exportXML() {
	if len(results) == 0 {
		fmt.Println("❌ No results to export for XML.")
		return
	}
	filename := fmt.Sprintf("%s.xml", config.OutputFile)
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("❌ Error creating XML file: %v\n", err)
		return
	}
	defer file.Close()

	// Define a structure suitable for XML marshalling, if EnhancedScanResult needs adjustment
	type XMLScanResult struct {
		EnhancedScanResult
		ResponseTimeMs int64    `xml:"responseTimeMs,omitempty"` // XML likes specific types
		Vulnerability  []string `xml:"vulnerability,omitempty"`  // More standard XML naming
	}
	
	type XMLRoot struct {
		XMLName xml.Name          `xml:"ReconRaptorScanResults"`
		Info    struct {
			Version   string `xml:"toolVersion"`
			Timestamp string `xml:"exportTimestamp"`
			Target    string `xml:"target,omitempty"`
		} `xml:"scanInfo"`
		Results []XMLScanResult `xml:"scanResult"`
	}


	xmlData := XMLRoot{}
	xmlData.Info.Version = VERSION
	xmlData.Info.Timestamp = time.Now().Format(time.RFC3339)
	if config.TargetHost != "" {
		xmlData.Info.Target = config.TargetHost
	} else if config.TargetFile != "" {
		xmlData.Info.Target = "File: " + config.TargetFile
	}


	for _, res := range results {
		xmlRes := XMLScanResult{EnhancedScanResult: res}
		xmlRes.ResponseTimeMs = res.ResponseTime.Milliseconds()
		// If Vulnerabilities field in EnhancedScanResult is already []string, this direct assignment is fine.
		// If it was, for example, a more complex type, it would need transformation.
		xmlRes.Vulnerability = res.Vulnerabilities // Ensure this is just a list of strings
		xmlData.Results = append(xmlData.Results, xmlRes)
	}


	encoder := xml.NewEncoder(file)
	encoder.Indent("", "  ") // For pretty printing

	file.WriteString(xml.Header) // Standard XML header
	if err := encoder.Encode(xmlData); err != nil {
		fmt.Printf("❌ Error marshaling results to XML: %v\n", err)
		return
	}

	fmt.Printf("✅ XML results exported to %s\n", filename)
}


func exportHTML() {
    if len(results) == 0 {
        fmt.Println("❌ No results to export for HTML.")
        return
    }
    filename := fmt.Sprintf("%s.html", config.OutputFile)
    file, err := os.Create(filename)
    if err != nil {
        fmt.Printf("❌ Error creating HTML file: %v\n", err)
        return
    }
    defer file.Close()

    // Prepare data for the template
    type HTMLReportData struct {
        ToolVersion     string
        ExportTimestamp string
        TargetInfo      string
        Results         []EnhancedScanResult
		OnlyOpen        bool
    }

    reportData := HTMLReportData{
        ToolVersion:     VERSION,
        ExportTimestamp: time.Now().Format("2006-01-02 15:04:05 MST"),
        Results:         results,
		OnlyOpen:        config.OnlyOpenPorts,
    }
	if config.TargetHost != "" {
		reportData.TargetInfo = config.TargetHost
	} else if config.TargetFile != "" {
		reportData.TargetInfo = "File: " + config.TargetFile
	}


    // HTML template with improved styling and structure
    htmlTemplate := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>r3cond0g Scan Report - {{.TargetInfo}}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f4; color: #333; }
        h1, h2 { color: #333; border-bottom: 2px solid #ddd; padding-bottom: 10px; }
		.header { background-color: #3498db; color: white; padding: 15px; text-align: center; margin-bottom: 20px; border-radius: 5px;}
		.header h1 { color: white; border-bottom: none;}
        table { border-collapse: collapse; width: 100%; margin-top: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #3498db; color: white; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f1f1f1; }
        .footer { text-align: center; margin-top: 30px; font-size: 0.9em; color: #777; }
        .summary { background-color: #eaf5ff; padding: 15px; border-left: 5px solid #3498db; margin-bottom:20px; border-radius: 5px;}
		.no-results { padding: 15px; background-color: #ffecec; border: 1px solid #f5c6cb; color: #721c24; border-radius: 5px; text-align: center;}
		.vuln-list { list-style-type: none; padding-left: 0;}
		.vuln-list li { padding: 2px 0;}
    </style>
</head>
<body>
	<div class="header">
    	<h1>ReconRaptor (r3cond0g) Scan Report</h1>
	</div>

    <div class="summary">
        <h2>Scan Summary</h2>
        <p><strong>Target:</strong> {{.TargetInfo}}</p>
        <p><strong>Tool Version:</strong> {{.ToolVersion}}</p>
        <p><strong>Export Timestamp:</strong> {{.ExportTimestamp}}</p>
        <p><strong>Total Results Found:</strong> {{len .Results}}</p>
		{{if .OnlyOpen}} <p><strong>Filter:</strong> Showing only open / open|filtered ports.</p> {{end}}
    </div>

    <h2>Scan Results</h2>
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
                <th>Timestamp</th>
            </tr>
        </thead>
        <tbody>
            {{range .Results}}
			{{if or (not $.OnlyOpen) (eq .State "open") (eq .State "open|filtered")}}
            <tr>
                <td>{{.Host}}</td>
                <td>{{.Port}}</td>
                <td>{{.Protocol}}</td>
                <td>{{.State}}</td>
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
            {{end}}
        </tbody>
    </table>
    {{else}}
    <p class="no-results">No results to display.</p>
    {{end}}

    <div class="footer">
        Report generated by ReconRaptor (r3cond0g)
    </div>
</body>
</html>
`
    tmpl, err := template.New("report").Parse(htmlTemplate)
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
	// Example for other configs:
	// if val := os.Getenv("RECONRAPTOR_TARGET_HOST"); val != "" && config.TargetHost == "" { config.TargetHost = val }
}

func parseCommandLineFlags() {
	// Provide default values from the config struct, which might have been set by env vars
	flag.StringVar(&config.TargetHost, "target", config.TargetHost, "Target host(s) (comma-separated or CIDR). Env: RECONRAPTOR_TARGET_HOST")
	flag.StringVar(&config.TargetFile, "target-file", config.TargetFile, "File containing list of targets. Env: RECONRAPTOR_TARGET_FILE")
	flag.StringVar(&config.PortRange, "ports", config.PortRange, "Port range (e.g., 1-1000, 80, 443). Env: RECONRAPTOR_PORTS")
	flag.IntVar(&config.ScanTimeout, "timeout", config.ScanTimeout, "Scan timeout in milliseconds per port. Env: RECONRAPTOR_TIMEOUT")
	flag.IntVar(&config.MaxConcurrency, "concurrency", config.MaxConcurrency, "Maximum concurrent scans. Env: RECONRAPTOR_CONCURRENCY")
	flag.StringVar(&config.OutputFile, "output", config.OutputFile, "Base name for output files (e.g., scan_results -> scan_results.json). Env: RECONRAPTOR_OUTPUT")
	flag.BoolVar(&config.UDPScan, "udp", config.UDPScan, "Enable UDP scanning (slower, less reliable). Env: RECONRAPTOR_UDP_SCAN")
	flag.BoolVar(&config.VulnMapping, "vuln", config.VulnMapping, "Enable vulnerability mapping using NVD. Env: RECONRAPTOR_VULN_MAPPING")
	flag.BoolVar(&config.TopologyMapping, "topology", config.TopologyMapping, "Enable network topology map generation (basic). Env: RECONRAPTOR_TOPOLOGY")
	flag.StringVar(&config.NVDAPIKey, "nvd-key", config.NVDAPIKey, "NVD API key (override env var). Env: NVD_API_KEY")
	flag.StringVar(&config.NmapResultsFile, "nmap-file", config.NmapResultsFile, "Import Nmap XML results file. Env: RECONRAPTOR_NMAP_FILE")
	flag.BoolVar(&config.OnlyOpenPorts, "open-only", config.OnlyOpenPorts, "Display and process only open (or open|filtered) ports. Env: RECONRAPTOR_OPEN_ONLY")
	flag.StringVar(&config.CVEPluginFile, "cve-plugin", config.CVEPluginFile, "Path to a custom CVE JSON file. Env: RECONRAPTOR_CVE_PLUGIN")
	
	// Custom usage message
    flag.Usage = func() {
        fmt.Fprintf(os.Stderr, "ReconRaptor (r3cond0g) - Advanced RedTeaming Network Recon Tool v%s\nUsage: %s [options]\n\nOptions:\n", VERSION, os.Args[0])
        flag.PrintDefaults()
        fmt.Fprintf(os.Stderr, "\nExample (direct scan): %s -target 192.168.1.0/24 -ports 1-1024 -vuln -nvd-key YOUR_API_KEY\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example (Nmap parse): %s -nmap-file results.xml -vuln\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example (interactive): %s\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "More info & docs: https://github.com/0xb0rn3/ReconRaptor\n") // Replace with actual repo URL
    }

	flag.Parse()

	// The informational message about Nmap file previously here has been removed
	// as the main() function now handles direct execution logic more comprehensively.
}
