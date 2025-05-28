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

// NVDResponse defines the structure of the NVD API JSON response
type NVDResponse struct {
	Result struct {
		CVEItems []struct {
			CVE struct {
				CVEDataMeta struct {
					ID string `json:"ID"`
				} `json:"CVE_data_meta"`
			} `json:"cve"`
		} `json:"CVE_Items"`
	} `json:"result"`
}

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
	parseCommandLineFlags()
	loadCustomCVEs()
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
			return []string{target}
		}
		var ips []string
		networkIP := ipnet.IP.Mask(ipnet.Mask)
		ones, bits := ipnet.Mask.Size()
		hostBits := bits - ones
		start := 0
		end := (1 << hostBits)
		if hostBits > 1 {
			start = 1
			end = end - 1
		}
		for i := start; i < end; i++ {
			ip := make(net.IP, len(networkIP))
			copy(ip, networkIP)
			for j := len(ip) - 1; j >= 0 && i > 0; j-- {
				ip[j] += byte(i & 0xff)
				i >>= 8
			}
			ips = append(ips, ip.String())
			if len(ips) >= 1000 {
				fmt.Printf("⚠️  Warning: CIDR range too large, limiting to first 1000 IPs\n")
				break
			}
		}
		return ips
	}
	return []string{target}
}

func scanTCPPort(host string, port int) *EnhancedScanResult {
	timeout := time.Duration(config.ScanTimeout) * time.Millisecond
	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil
		}
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
	result.Service, result.Version = detectServiceWithTimeout(conn, port, "tcp", timeout)
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
	conn.SetReadDeadline(time.Now().Add(timeout / 2))
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
				result.Service, result.Version = detectServiceWithTimeout(conn, port, "udp", timeout)
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
		result.Service, result.Version = detectServiceWithTimeout(conn, port, "udp", timeout)
		result.OSGuess = guessOS(result)
		return result
	}
	return nil
}

func detectServiceWithTimeout(conn net.Conn, port int, protocol string, timeout time.Duration) (string, string) {
	services := map[int]string{
		21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
		53: "dns", 80: "http", 110: "pop3", 143: "imap",
		443: "https", 993: "imaps", 995: "pop3s",
		3306: "mysql", 5432: "postgresql", 6379: "redis",
		27017: "mongodb", 3389: "rdp", 5985: "winrm",
		161: "snmp", 123: "ntp", 67: "dhcp", 68: "dhcp",
	}
	service, exists := services[port]
	if !exists {
		service = "unknown"
	}
	if protocol == "tcp" {
		if probe, ok := portProbes[port]; ok {
			conn.SetDeadline(time.Now().Add(timeout / 4))
			s, v := probe.Detect(conn)
			conn.SetDeadline(time.Time{})
			if s != "unknown" {
				return s, v
			}
		}
	}
	return service, "unknown"
}

func getUDPProbe(port int) []byte {
	switch port {
	case 53:
		return []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01}
	case 161:
		return []byte{0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00}
	case 123:
		return []byte{0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	default:
		return []byte("probe")
	}
}

func isCommonUDPPort(port int) bool {
	commonUDPPorts := []int{53, 67, 68, 69, 123, 161, 162, 514, 1812, 1813}
	for _, p := range commonUDPPorts {
		if port == p {
			return true
		}
	}
	return false
}

func guessOS(result *EnhancedScanResult) string {
	switch result.Service {
	case "http":
		if strings.Contains(result.Version, "IIS") {
			return "Windows"
		} else if strings.Contains(result.Version, "Apache") {
			return "Linux/Unix"
		}
	case "ssh":
		if strings.Contains(result.Version, "OpenSSH") {
			return "Linux/Unix"
		}
	}
	return "Unknown"
}

type Probe interface {
	Detect(conn net.Conn) (service string, version string)
}

type HTTPProbe struct{}

func (p *HTTPProbe) Detect(conn net.Conn) (string, string) {
	conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buffer)
	if err != nil {
		return "http", "unknown"
	}
	response := string(buffer[:n])
	if strings.HasPrefix(response, "HTTP/") {
		lines := strings.Split(response, "\r\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Server:") {
				server := strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
				return "http", server
			}
		}
		return "http", "unknown"
	}
	return "unknown", "unknown"
}

var portProbes = map[int]Probe{
	80:  &HTTPProbe{},
	443: &HTTPProbe{},
}

func mapVulnerabilities(result *EnhancedScanResult) {
	if !config.VulnMapping {
		return
	}
	key := fmt.Sprintf("%s %s", result.Service, result.Version)
	if vulns, ok := customCVEs[key]; ok {
		result.Vulnerabilities = vulns
		return
	}
	if cached, found := nvdCache.Load(key); found {
		result.Vulnerabilities = cached.([]string)
		return
	}
	if result.Version == "" {
		result.Vulnerabilities = []string{"Version unknown"}
		return
	}
	vp, ok := serviceToCPE[result.Service]
	if !ok {
		result.Vulnerabilities = []string{"Unknown service"}
		return
	}
	cpe := fmt.Sprintf("cpe:2.3:a:%s:%s:%s", vp.Vendor, vp.Product, result.Version)
	vulns, err := queryNVD(cpe)
	if err != nil {
		fmt.Printf("❌ Error querying NVD for CPE %s: %v\n", cpe, err)
		result.Vulnerabilities = []string{"Error querying vulnerabilities"}
		return
	}
	nvdCache.Store(key, vulns)
	result.Vulnerabilities = vulns
	if len(vulns) == 0 {
		similarKey := findSimilarKey(key)
		if similarKey != "" {
			if vulns, ok := vulnDB[similarKey]; ok {
				result.Vulnerabilities = vulns
			}
		}
	}
}

func queryNVD(cpe string) ([]string, error) {
	if err := limiter.Wait(context.Background()); err != nil {
		return nil, err
	}
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString=%s", cpe)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if config.NVDAPIKey != "" {
		req.Header.Set("apiKey", config.NVDAPIKey)
		limiter = rate.NewLimiter(rate.Every(30*time.Second/50), 1)
	}
	for attempts := 0; attempts < 3; attempts++ {
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode == 429 {
			time.Sleep(time.Duration(attempts+1) * time.Second)
			continue
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("NVD API returned status %d", resp.StatusCode)
		}
		var nvdResp NVDResponse
		if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
			return nil, err
		}
		var cves []string
		for _, item := range nvdResp.Result.CVEItems {
			cves = append(cves, item.CVE.CVEDataMeta.ID)
		}
		return cves, nil
	}
	return nil, fmt.Errorf("rate limit exceeded after retries")
}

func findSimilarKey(key string) string {
	parts := strings.Split(key, " ")
	if len(parts) < 2 {
		return ""
	}
	service := parts[0]
	for k := range vulnDB {
		if strings.HasPrefix(k, service) {
			return k
		}
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
		fmt.Printf("❌ Error parsing CVE plugin file: %v\n", err)
		return
	}
	fmt.Println("✅ Loaded custom CVE mappings")
}

func runUltraFastScan() []EnhancedScanResult {
	fmt.Println("🚀 Starting ultra-fast scan...")
	hosts := parseTargets(config.TargetHost, config.TargetFile)
	if len(hosts) == 0 {
		fmt.Println("❌ No valid targets found. Please check your target configuration.")
		return nil
	}
	ports := parsePortRange(config.PortRange)
	if len(ports) == 0 {
		fmt.Println("❌ No valid ports found. Please check your port range configuration.")
		return nil
	}
	totalScans := int64(len(hosts) * len(ports))
	if config.UDPScan {
		totalScans *= 2
	}
	fmt.Printf("📊 Scanning %d hosts across %d ports (%d total scans)\n", len(hosts), len(ports), totalScans)
	if totalScans > 100000 {
		fmt.Printf("⚠️  Warning: Large scan detected (%d operations). This may take significant time.\n", totalScans)
		fmt.Print("Continue? (y/N): ")
		var response string
		fmt.Scanln(&response)
		if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
			fmt.Println("❌ Scan cancelled by user.")
			return nil
		}
	}
	sem = make(chan struct{}, config.MaxConcurrency)
	results = nil
	scannedPorts = 0
	start := time.Now()
	progressTicker := time.NewTicker(2 * time.Second)
	defer progressTicker.Stop()
	go func() {
		for range progressTicker.C {
			current := atomic.LoadInt64(&scannedPorts)
			if current > 0 {
				percentage := float64(current) / float64(totalScans) * 100
				fmt.Printf("\r🔍 Progress: %d/%d (%.1f%%) - Found: %d open ports", current, totalScans, percentage, len(results))
			}
		}
	}()
	for _, host := range hosts {
		for _, port := range ports {
			wg.Add(1)
			go func(h string, p int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				if result := scanTCPPort(h, p); result != nil {
					if config.VulnMapping {
						mapVulnerabilities(result)
					}
					mutex.Lock()
					results = append(results, *result)
					mutex.Unlock()
					fmt.Printf("\r✅ Found open port: %s:%d (%s)", h, p, result.Service)
				}
				if config.UDPScan {
					if result := scanUDPPort(h, p); result != nil {
						if config.VulnMapping {
							mapVulnerabilities(result)
						}
						mutex.Lock()
						results = append(results, *result)
						mutex.Unlock()
						fmt.Printf("\r✅ Found open UDP port: %s:%d (%s)", h, p, result.Service)
					}
				}
				atomic.AddInt64(&scannedPorts, 1)
			}(host, port)
		}
	}
	wg.Wait()
	progressTicker.Stop()
	elapsed := time.Since(start)
	fmt.Printf("\n✅ Scan completed in %v\n", elapsed)
	fmt.Printf("📊 Found %d open ports across %d hosts\n", len(results), len(hosts))
	if len(results) > 0 {
		fmt.Printf("⚡ Average scan rate: %.0f ports/second\n", float64(totalScans)/elapsed.Seconds())
	}
	return results
}

func validateConfig() bool {
	fmt.Println("🔧 Validating configuration...")
	if config.TargetHost == "" && config.TargetFile == "" {
		fmt.Println("❌ No target specified. Please set either target host or target file.")
		return false
	}
	ports := parsePortRange(config.PortRange)
	if len(ports) == 0 {
		fmt.Println("❌ Invalid port range specified.")
		return false
	}
	if config.TargetFile != "" {
		if _, err := os.Stat(config.TargetFile); os.IsNotExist(err) {
			fmt.Printf("❌ Target file does not exist: %s\n", config.TargetFile)
			return false
		}
	}
	if config.ScanTimeout < 100 || config.ScanTimeout > 30000 {
		fmt.Println("⚠️  Warning: Scan timeout should be between 100ms and 30000ms for optimal results.")
	}
	if config.MaxConcurrency < 1 || config.MaxConcurrency > 1000 {
		fmt.Println("⚠️  Warning: Max concurrency should be between 1 and 1000 for optimal performance.")
	}
	fmt.Println("✅ Configuration validation complete.")
	return true
}

func debugCIDRParsing(cidr string) {
	fmt.Printf("🔍 Debug: Parsing CIDR %s\n", cidr)
	ips := parseSingleTarget(cidr)
	fmt.Printf("📊 Generated %d IP addresses:\n", len(ips))
	displayCount := len(ips)
	if displayCount > 10 {
		displayCount = 10
	}
	for i := 0; i < displayCount; i++ {
		fmt.Printf("  %d: %s\n", i+1, ips[i])
	}
	if len(ips) > 10 {
		fmt.Printf("  ... and %d more\n", len(ips)-10)
	}
}

func parseNmapResults() {
	if config.NmapResultsFile == "" {
		config.NmapResultsFile = askForString("📁 Enter Nmap XML results file path: ")
	}
	file, err := os.Open(config.NmapResultsFile)
	if err != nil {
		fmt.Printf("❌ Error opening file: %v\n", err)
		return
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		fmt.Printf("❌ Error reading file: %v\n", err)
		return
	}
	var nmapRun NmapRun
	if err := xml.Unmarshal(data, &nmapRun); err != nil {
		fmt.Printf("❌ Error parsing XML: %v\n", err)
		return
	}
	results = nil
	for _, host := range nmapRun.Hosts {
		for _, port := range host.Ports.Ports {
			if !config.OnlyOpenPorts || port.State.State == "open" {
				result := EnhancedScanResult{
					Host:      host.Address.Addr,
					Port:      port.PortID,
					Protocol:  port.Protocol,
					State:     port.State.State,
					Service:   port.Service.Name,
					Version:   port.Service.Version,
					Timestamp: time.Now(),
				}
				if config.VulnMapping {
					mapVulnerabilities(&result)
				}
				results = append(results, result)
			}
		}
	}
	fmt.Printf("✅ Parsed %d ports from Nmap results\n", len(results))
}

func performVulnerabilityMapping() {
	if len(results) == 0 {
		fmt.Println("❌ No scan results available. Run a scan first.")
		return
	}
	if config.NVDAPIKey == "" {
		config.NVDAPIKey = askForString("🔑 Enter NVD API Key: ")
	}
	fmt.Println("🔍 Mapping vulnerabilities...")
	for i := range results {
		mapVulnerabilities(&results[i])
		fmt.Printf("\r🔍 Processed %d/%d hosts", i+1, len(results))
	}
	fmt.Println("\n✅ Vulnerability mapping completed")
}

func generateTopologyMap() {
	if len(results) == 0 {
		fmt.Println("❌ No scan results available. Run a scan first.")
		return
	}
	fmt.Println("🌐 Generating network topology map...")
	var dotGraph strings.Builder
	dotGraph.WriteString("graph NetworkTopology {\n")
	dotGraph.WriteString("  rankdir=LR;\n")
	dotGraph.WriteString("  node [shape=box, style=rounded];\n")
	hostPorts := make(map[string][]int)
	for _, result := range results {
		if result.State == "open" {
			hostPorts[result.Host] = append(hostPorts[result.Host], result.Port)
		}
	}
	for host, ports := range hostPorts {
		label := fmt.Sprintf("%s\\n(%d open ports)", host, len(ports))
		dotGraph.WriteString(fmt.Sprintf("  \"%s\" [label=\"%s\"];\n", host, label))
	}
	dotGraph.WriteString("}\n")
	filename := fmt.Sprintf("%s-topology.dot", config.OutputFile)
	if err := os.WriteFile(filename, []byte(dotGraph.String()), 0644); err != nil {
		fmt.Printf("❌ Failed to write topology file: %v\n", err)
		return
	}
	fmt.Printf("✅ Network topology saved to %s\n", filename)
	fmt.Println("💡 Use Graphviz to visualize: dot -Tpng topology.dot -o topology.png")
}

func displayResults() {
	if len(results) == 0 {
		fmt.Println("❌ No results to display. Run a scan first.")
		return
	}
	fmt.Printf("\n📊 Scan Results (%d ports found):\n", len(results))
	fmt.Println("┌─────────────────┬──────┬──────────┬─────────┬─────────────┬──────────────────┬────────────┐")
	fmt.Println("│      Host       │ Port │ Protocol │  State  │   Service   │   Vulnerabilities │    OS      │")
	fmt.Println("├─────────────────┼──────┼──────────┼─────────┼─────────────┼──────────────────┼────────────┤")
	for _, result := range results {
		if config.OnlyOpenPorts && result.State != "open" {
			continue
		}
		vulnCount := len(result.Vulnerabilities)
		vulnStr := "None"
		if vulnCount > 0 {
			vulnStr = fmt.Sprintf("%d CVEs", vulnCount)
		}
		fmt.Printf("│ %-15s │ %4d │ %-8s │ %-7s │ %-11s │ %-16s │ %-10s │\n",
			result.Host, result.Port, result.Protocol,
			result.State, result.Service, vulnStr, result.OSGuess)
	}
	fmt.Println("└─────────────────┴──────┴──────────┴─────────┴─────────────┴──────────────────┴────────────┘")
}

func saveResults() {
	if len(results) == 0 {
		fmt.Println("❌ No results to save. Run a scan first.")
		return
	}
	filename := fmt.Sprintf("%s.json", config.OutputFile)
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("❌ Error marshaling results: %v\n", err)
		return
	}
	if err := os.WriteFile(filename, data, 0644); err != nil {
		fmt.Printf("❌ Error writing file: %v\n", err)
		return
	}
	fmt.Printf("✅ Results saved to %s\n", filename)
}

func exportResults() {
	if len(results) == 0 {
		fmt.Println("❌ No results to export. Run a scan first.")
		return
	}
	fmt.Println("📤 Choose export format:")
	fmt.Println("1. JSON")
	fmt.Println("2. CSV")
	fmt.Println("3. XML")
	fmt.Println("4. HTML")
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
	saveResults()
}

func exportCSV() {
	filename := fmt.Sprintf("%s.csv", config.OutputFile)
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("❌ Error creating CSV file: %v\n", err)
		return
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	defer writer.Flush()
	writer.WriteString("Host,Port,Protocol,State,Service,Version,ResponseTime,Vulnerabilities,OSGuess\n")
	for _, result := range results {
		vulns := strings.Join(result.Vulnerabilities, ";")
		line := fmt.Sprintf("%s,%d,%s,%s,%s,%s,%s,%s,%s\n",
			result.Host, result.Port, result.Protocol, result.State,
			result.Service, result.Version, result.ResponseTime.String(), vulns, result.OSGuess)
		writer.WriteString(line)
	}
	fmt.Printf("✅ CSV results exported to %s\n", filename)
}

func exportXML() {
	filename := fmt.Sprintf("%s.xml", config.OutputFile)
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("❌ Error creating XML file: %v\n", err)
		return
	}
	defer file.Close()
	type XMLResults struct {
		XMLName xml.Name             `xml:"scan_results"`
		Results []EnhancedScanResult `xml:"result"`
	}
	xmlResults := XMLResults{Results: results}
	data, err := xml.MarshalIndent(xmlResults, "", "  ")
	if err != nil {
		fmt.Printf("❌ Error marshaling XML: %v\n", err)
		return
	}
	file.WriteString(xml.Header)
	file.Write(data)
	fmt.Printf("✅ XML results exported to %s\n", filename)
}

func exportHTML() {
	filename := fmt.Sprintf("%s.html", config.OutputFile)
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("❌ Error creating HTML file: %v\n", err)
		return
	}
	defer file.Close()
	tmpl := template.Must(template.New("report").Parse(`
<!DOCTYPE html>
<html>
<head>
    <title>r3cond0g Scan Report</title>
    <style>
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid black; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Scan Results</h1>
    <table>
        <tr>
            <th>Host</th>
            <th>Port</th>
            <th>Protocol</th>
            <th>State</th>
            <th>Service</th>
            <th>Version</th>
            <th>Vulnerabilities</th>
            <th>OS Guess</th>
        </tr>
        {{range .Results}}
        <tr>
            <td>{{.Host}}</td>
            <td>{{.Port}}</td>
            <td>{{.Protocol}}</td>
            <td>{{.State}}</td>
            <td>{{.Service}}</td>
            <td>{{.Version}}</td>
            <td>{{range .Vulnerabilities}}{{.}}, {{end}}</td>
            <td>{{.OSGuess}}</td>
        </tr>
        {{end}}
    </table>
</body>
</html>
`))
	if err := tmpl.Execute(file, struct{ Results []EnhancedScanResult }{results}); err != nil {
		fmt.Printf("❌ Error generating HTML: %v\n", err)
		return
	}
	fmt.Printf("✅ HTML report exported to %s\n", filename)
}

func loadConfigFromEnv() {
	if config.NVDAPIKey == "" {
		config.NVDAPIKey = os.Getenv("NVD_API_KEY")
	}
}

func parseCommandLineFlags() {
	flag.StringVar(&config.TargetHost, "target", config.TargetHost, "Target host(s) (comma-separated or CIDR)")
	flag.StringVar(&config.TargetFile, "target-file", config.TargetFile, "File containing list of targets")
	flag.StringVar(&config.PortRange, "ports", config.PortRange, "Port range (e.g., 1-1000)")
	flag.IntVar(&config.ScanTimeout, "timeout", config.ScanTimeout, "Scan timeout in milliseconds")
	flag.IntVar(&config.MaxConcurrency, "concurrency", config.MaxConcurrency, "Maximum concurrent scans")
	flag.StringVar(&config.OutputFile, "output", config.OutputFile, "Output file name")
	flag.BoolVar(&config.UDPScan, "udp", config.UDPScan, "Enable UDP scanning")
	flag.BoolVar(&config.VulnMapping, "vuln", config.VulnMapping, "Enable vulnerability mapping")
	flag.BoolVar(&config.TopologyMapping, "topology", config.TopologyMapping, "Enable network topology mapping")
	flag.StringVar(&config.NVDAPIKey, "nvd-key", config.NVDAPIKey, "NVD API key")
	flag.StringVar(&config.NmapResultsFile, "nmap-file", config.NmapResultsFile, "Nmap results XML file")
	flag.BoolVar(&config.OnlyOpenPorts, "open-only", config.OnlyOpenPorts, "Show only open ports")
	flag.StringVar(&config.CVEPluginFile, "cve-plugin", config.CVEPluginFile, "CVE plugin file path")
	flag.Parse()
}
