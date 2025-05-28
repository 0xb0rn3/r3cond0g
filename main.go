package main

import (
	"bufio"
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
	nvdCache     = make(map[string][]string)
	customCVEs   = make(map[string][]string)
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
			results = runUltraFastScan()
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
		file, err := os.Open(targetFile)
		if err != nil {
			fmt.Printf("❌ Error opening target file: %v\n", err)
			return ips
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				ips = append(ips, parseSingleTarget(line)...)
			}
		}
	} else {
		parts := strings.Split(targets, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			ips = append(ips, parseSingleTarget(part)...)
		}
	}
	return ips
}

func parseSingleTarget(target string) []string {
    if strings.Contains(target, "/") {
        ip, ipnet, err := net.ParseCIDR(target)
        if err != nil {
            return []string{target}
        }
        var ips []string
        for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {  
            ips = append(ips, ip.String())
        }
        return ips
    }
    return []string{target}
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func scanTCPPort(host string, port int) *EnhancedScanResult {
	timeout := time.Duration(config.ScanTimeout) * time.Millisecond
	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
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
		Timestamp:    time.Now(),
	}

	// Enhanced service detection
	result.Service, result.Version = detectService(conn, port, "tcp")
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

	// Send probe packet
	_, err = conn.Write([]byte("probe"))
	if err != nil {
		return nil
	}

	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(timeout))
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return nil
	}

	result := &EnhancedScanResult{
		Host:         host,
		Port:         port,
		Protocol:     "udp",
		State:        "open",
		ResponseTime: time.Since(start),
		Timestamp:    time.Now(),
	}

	result.Service, result.Version = detectService(conn, port, "udp")
	result.OSGuess = guessOS(result)
	return result
}

func detectService(conn net.Conn, port int, protocol string) (string, string) {
	// Common service mappings as fallback
	services := map[int]string{
		21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
		53: "dns", 80: "http", 110: "pop3", 143: "imap",
		443: "https", 993: "imaps", 995: "pop3s",
		3306: "mysql", 5432: "postgresql", 6379: "redis",
		27017: "mongodb", 3389: "rdp", 5985: "winrm",
	}

	service, exists := services[port]
	if !exists {
		service = "unknown"
	}

	// Probe for specific services
	if protocol == "tcp" {
		if probe, ok := portProbes[port]; ok {
			s, v := probe.Detect(conn)
			if s != "unknown" {
				return s, v
			}
		}
	}

	return service, "unknown"
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
	443: &HTTPProbe{}, // Assuming HTTPS uses the same probe for simplicity
}

func mapVulnerabilities(result *EnhancedScanResult) {
	// Check custom CVEs first
	key := fmt.Sprintf("%s %s", result.Service, result.Version)
	if vulns, ok := customCVEs[key]; ok {
		result.Vulnerabilities = vulns
		return
	}

	// Check cache
	if cached, ok := nvdCache[key]; ok {
		result.Vulnerabilities = cached
		return
	}

	if config.NVDAPIKey == "" {
		return
	}

	// Enhanced query
	query := fmt.Sprintf("%s %s %s %d %s", result.Service, result.Version, result.Host, result.Port, result.OSGuess)
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s", query)

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}

	req.Header.Set("apiKey", config.NVDAPIKey)

	// Retry logic
	for attempt := 0; attempt < 3; attempt++ {
		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(time.Duration(math.Pow(2, float64(attempt))) * time.Second)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			retryAfter := resp.Header.Get("Retry-After")
			if retryAfter != "" {
				waitTime, _ := strconv.Atoi(retryAfter)
				time.Sleep(time.Duration(waitTime) * time.Second)
			} else {
				time.Sleep(time.Duration(math.Pow(2, float64(attempt))) * time.Second)
			}
			continue
		}

		var nvdResponse struct {
			Vulnerabilities []struct {
				CVE struct {
					ID string `json:"id"`
				} `json:"cve"`
			} `json:"vulnerabilities"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&nvdResponse); err != nil {
			return
		}

		for _, vuln := range nvdResponse.Vulnerabilities {
			result.Vulnerabilities = append(result.Vulnerabilities, vuln.CVE.ID)
		}

		// Cache the result
		nvdCache[key] = result.Vulnerabilities
		return
	}

	// If no exact match, try heuristic matching
	similarKey := findSimilarKey(key)
	if similarKey != "" {
		if vulns, ok := vulnDB[similarKey]; ok {
			result.Vulnerabilities = vulns
		}
	}
}

func findSimilarKey(key string) string {
    parts := strings.Split(key, " ")
    if len(parts) < 2 {
        return ""
    }
    service := parts[0]

    // Simple heuristic: find a key with the same service
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
	ports := parsePortRange(config.PortRange)
	sem = make(chan struct{}, config.MaxConcurrency)
	results = nil
	scannedPorts = 0

	start := time.Now()
	for _, host := range hosts {
		for _, port := range ports {
			wg.Add(1)
			go func(h string, p int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				// TCP scan
				if result := scanTCPPort(h, p); result != nil {
					if config.VulnMapping {
						mapVulnerabilities(result)
					}
					mutex.Lock()
					results = append(results, *result)
					mutex.Unlock()
				}

				// UDP scan if enabled
				if config.UDPScan {
					if result := scanUDPPort(h, p); result != nil {
						if config.VulnMapping {
							mapVulnerabilities(result)
						}
						mutex.Lock()
						results = append(results, *result)
						mutex.Unlock()
					}
				}

				atomic.AddInt64(&scannedPorts, 1)
				if scannedPorts%100 == 0 {
					fmt.Printf("\r🔍 Scanned %d ports...", scannedPorts)
				}
			}(host, port)
		}
	}

	wg.Wait()
	fmt.Printf("\n✅ Scan completed in %v\n", time.Since(start))
	fmt.Printf("📊 Found %d open ports\n", len(results))
	return results
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
