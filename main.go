// r3cond0g: Advanced Network Reconnaissance Tool
// A powerful network scanning tool for security professionals
// For educational use in controlled environments only

package main

import (
	"bufio"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Constants for the application
const (
	AppName    = "r3cond0g"
	AppVersion = "0.2.0" // Incrementing version for menu-driven interface
	AppBanner  = `
  _____ _____                              _   ___
 |  __ \___ /                             | | / _ \
 | |__) | |_ \ ___ ___  __ _ _ __ ___  __| | | | | | __ _
 |  _  /|___) / __/ _ \/ _' | '_ ' _ \/ _' | | | |/ _' |
 | | \ \____/ | (_| (_) | (_| | | | | | | (_| | | |_| | (_| |
 |_|  \_\_____|\___\___/\__,_|_| |_| |_|\__,_| \___/ \__, |
                                                        __/ |
                                                       |___/
 Advanced Network Reconnaissance Tool v0.2.0
`
)

// ScanResult represents the result of a scan
type ScanResult struct {
	IP       string
	Hostname string
	Ports    []PortInfo
	OS       string
	Banners  map[int]string // Added for banner grabbing
}

// PortInfo represents information about a port
type PortInfo struct {
	Port     int
	Protocol string
	Service  string
	State    string
}

// NmapRun represents the root element of Nmap XML output
type NmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []Host   `xml:"host"`
}

// Host represents a host element in Nmap XML output
type Host struct {
	XMLName xml.Name `xml:"host"`
	Address Address  `xml:"address"`
	Ports   Ports    `xml:"ports"`
	OS      OS       `xml:"os"`
}

// Address represents an address element in Nmap XML output
type Address struct {
	XMLName  xml.Name `xml:"address"`
	Addr     string   `xml:"addr,attr"`
	AddrType string   `xml:"addrtype,attr"`
}

// Ports represents a ports element in Nmap XML output
type Ports struct {
	XMLName xml.Name `xml:"ports"`
	Ports   []Port   `xml:"port"`
}

// Port represents a port element in Nmap XML output
type Port struct {
	XMLName  xml.Name `xml:"port"`
	Protocol string   `xml:"protocol,attr"`
	PortID   string   `xml:"portid,attr"`
	State    State    `xml:"state"`
	Service  Service  `xml:"service"`
}

// State represents a state element in Nmap XML output
type State struct {
	XMLName xml.Name `xml:"state"`
	State   string   `xml:"state,attr"`
}

// Service represents a service element in Nmap XML output
type Service struct {
	XMLName xml.Name `xml:"service"`
	Name    string   `xml:"name,attr"`
	Product string   `xml:"product,attr"`
	Version string   `xml:"version,attr"`
}

// OS represents an os element in Nmap XML output
type OS struct {
	XMLName     xml.Name    `xml:"os"`
	OsMatches   []OsMatch   `xml:"osmatch"`
	OsFingerprint OsFingerprint `xml:"osfingerprint"`
}

// OsMatch represents an osmatch element in Nmap XML output
type OsMatch struct {
	XMLName  xml.Name `xml:"osmatch"`
	Name     string   `xml:"name,attr"`
	Accuracy string   `xml:"accuracy,attr"`
}

// OsFingerprint represents an osfingerprint element in Nmap XML output
type OsFingerprint struct {
	XMLName xml.Name `xml:"osfingerprint"`
	Fingerprint string `xml:"fingerprint,attr"`
}

// Config represents the configuration for the scanner
type Config struct {
	Targets     string
	Ports       string
	ScanType    string
	Threads     int
	Timeout     int
	OutputFile  string
	Verbose     bool
	FastMode    bool
	ServiceScan bool
	OsScan      bool
	ScriptScan  bool
	CustomNmap  string
	UseRustScan bool
	TargetFile  string      // Added for targets from file
	CommonPorts bool        // Added option to scan common ports
	AllPorts    bool        // Added option to scan all ports
	BannerGrab  bool        // Added option for banner grabbing
}

// globalConfig holds the configuration for the scanner
var globalConfig Config

// commonPortsList is a predefined list of common ports
var commonPortsList = "21,22,23,25,53,80,110,111,135,139,143,443,445,1024-1029,1433,1521,3306,3389,5900,8000,8080"

// allPortsRange represents the full port range
var allPortsRange = "1-65535"

// main is the entry point for the application
func main() {
	// Parse command line flags (these will be largely ignored in menu mode but can still be parsed)
	flag.StringVar(&globalConfig.Targets, "targets", "", "Target specification (CIDR, IP range, or comma-separated IPs)")
	flag.StringVar(&globalConfig.TargetFile, "file", "", "Path to a file containing a list of targets (one per line)")
	flag.StringVar(&globalConfig.Ports, "ports", "", "Port specification (e.g., 80,443,8080 or 1-1000). Use --common-ports or --all-ports for predefined lists.")
	flag.BoolVar(&globalConfig.CommonPorts, "common-ports", false, "Scan common ports")
	flag.BoolVar(&globalConfig.AllPorts, "all-ports", false, "Scan all 65535 ports")
	flag.StringVar(&globalConfig.ScanType, "scan", "SYN", "Scan type (SYN, CONNECT, UDP, NULL, FIN, XMAS, COMPREHENSIVE)")
	flag.IntVar(&globalConfig.Threads, "threads", 100, "Number of concurrent threads")
	flag.IntVar(&globalConfig.Timeout, "timeout", 2000, "Timeout in milliseconds")
	flag.StringVar(&globalConfig.OutputFile, "output", "", "Output file name")
	flag.BoolVar(&globalConfig.Verbose, "verbose", false, "Enable verbose output")
	flag.BoolVar(&globalConfig.FastMode, "fast", false, "Enable fast mode (uses rustscan if available)")
	flag.BoolVar(&globalConfig.ServiceScan, "service", false, "Enable service detection")
	flag.BoolVar(&globalConfig.OsScan, "os", false, "Enable OS detection")
	flag.BoolVar(&globalConfig.ScriptScan, "script", false, "Enable script scanning")
	flag.StringVar(&globalConfig.CustomNmap, "custom", "", "Custom nmap arguments")
	flag.BoolVar(&globalConfig.UseRustScan, "rustscan", false, "Use rustscan for port discovery")
	flag.BoolVar(&globalConfig.BannerGrab, "banners", false, "Attempt to grab banners from open TCP ports")

	flag.Parse()

	// Display banner
	fmt.Println(AppBanner)

	runMenu()
}

func runMenu() {
	reader := bufio.NewReader(os.Stdin)
	var input string // Declare input variable outside the loop

	for {
		fmt.Println("\n=== r3cond0g Menu ===")
		fmt.Println("1. Set Target(s) (Current: " + getCurrentSetting(globalConfig.Targets, "Not Set") + ")")
		fmt.Println("2. Set Target File (Current: " + getCurrentSetting(globalConfig.TargetFile, "Not Set") + ")")
		fmt.Println("3. Set Ports (Current: " + getCurrentPortSetting() + ")")
		fmt.Println("4. Set Scan Type (Current: " + globalConfig.ScanType + ")")
		fmt.Println("5. Toggle Service Detection (Current: " + boolToString(globalConfig.ServiceScan) + ")")
		fmt.Println("6. Toggle OS Detection (Current: " + boolToString(globalConfig.OsScan) + ")")
		fmt.Println("7. Toggle Script Scanning (Current: " + boolToString(globalConfig.ScriptScan) + ")")
		fmt.Println("8. Toggle Banner Grabbing (Current: " + boolToString(globalConfig.BannerGrab) + ")")
		fmt.Println("9. Toggle Use Rustscan (Current: " + boolToString(globalConfig.UseRustScan) + ")")
		fmtPrintln("10. Set Output File (Current: " + getCurrentSetting(globalConfig.OutputFile, "Not Set") + ")")
		fmt.Println("11. Toggle Verbose Output (Current: " + boolToString(globalConfig.Verbose) + ")")
		fmt.Println("12. Set Number of Threads (Current: " + strconv.Itoa(globalConfig.Threads) + ")")
		fmt.Println("13. Set Timeout (ms) (Current: " + strconv.Itoa(globalConfig.Timeout) + ")")
		fmt.Println("14. Set Custom Nmap Arguments (Current: " + getCurrentSetting(globalConfig.CustomNmap, "Not Set") + ")")
		fmt.Println("15. Start Scan")
		fmt.Println("16. Exit")
		fmt.Print("Enter your choice: ")

		input, _ = reader.ReadString('\n') // Use assignment `=` here
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			fmt.Print("Enter target specification (CIDR, IP range, or comma-separated IPs): ")
			globalConfig.Targets, _ = reader.ReadString('\n')
			globalConfig.Targets = strings.TrimSpace(globalConfig.Targets)
			globalConfig.TargetFile = "" // Clear target file if direct targets are set
		case "2":
			fmt.Print("Enter path to target file: ")
			globalConfig.TargetFile, _ = reader.ReadString('\n')
			globalConfig.TargetFile = strings.TrimSpace(globalConfig.TargetFile)
			globalConfig.Targets = "" // Clear direct targets if target file is set
		case "3":
			fmt.Println("Select port option:")
			fmt.Println("   a. Specify ports (e.g., 80,443,1-100)")
			fmt.Println("   b. Scan common ports")
			fmt.Println("   c. Scan all ports")
			fmt.Println("   d. Default ports (1-1000)")
			fmt.Print("Enter your choice: ")
			portChoice, _ := reader.ReadString('\n')
			portChoice = strings.TrimSpace(strings.ToLower(portChoice))
			switch portChoice {
			case "a":
				fmt.Print("Enter port specification: ")
				globalConfig.Ports, _ = reader.ReadString('\n')
				globalConfig.Ports = strings.TrimSpace(globalConfig.Ports)
				globalConfig.CommonPorts = false
				globalConfig.AllPorts = false
			case "b":
				globalConfig.Ports = commonPortsList
				globalConfig.CommonPorts = true
				globalConfig.AllPorts = false
			case "c":
				globalConfig.Ports = allPortsRange
				globalConfig.CommonPorts = false
				globalConfig.AllPorts = true
			case "d", "":
				globalConfig.Ports = "1-1000"
				globalConfig.CommonPorts = false
				globalConfig.AllPorts = false
			default:
				fmt.Println("Invalid choice.")
			}
		case "4":
			fmt.Println("Select scan type:")
			fmt.Println("   1. SYN")
			fmt.Println("   2. CONNECT")
			fmt.Println("   3. UDP")
			fmt.Println("   4. NULL")
			fmt.Println("   5. FIN")
			fmt.Println("   6. XMAS")
			fmtPrintln("   7. COMPREHENSIVE")
			fmt.Print("Enter your choice: ")
			scanChoice, _ := reader.ReadString('\n')
			scanChoice = strings.TrimSpace(scanChoice)
			switch scanChoice {
			case "1":
				globalConfig.ScanType = "SYN"
			case "2":
				globalConfig.ScanType = "CONNECT"
			case "3":
				globalConfig.ScanType = "UDP"
			case "4":
				globalConfig.ScanType = "NULL"
			case "5":
				globalConfig.ScanType = "FIN"
			case "6":
				globalConfig.ScanType = "XMAS"
			case "7":
				globalConfig.ScanType = "COMPREHENSIVE"
			default:
				fmt.Println("Invalid choice, defaulting to SYN.")
				globalConfig.ScanType = "SYN"
			}
		case "5":
			globalConfig.ServiceScan = !globalConfig.ServiceScan
		case "6":
			globalConfig.OsScan = !globalConfig.OsScan
		case "7":
			globalConfig.ScriptScan = !globalConfig.ScriptScan
		case "8":
			globalConfig.BannerGrab = !globalConfig.BannerGrab
		case "9":
			globalConfig.UseRustScan = !globalConfig.UseRustScan
		case "10":
			fmt.Print("Enter output file name: ")
			globalConfig.OutputFile, _ = reader.ReadString('\n')
			globalConfig.OutputFile = strings.TrimSpace(globalConfig.OutputFile)
		case "11":
			globalConfig.Verbose = !globalConfig.Verbose
		case "12":
			fmt.Print("Enter number of threads: ")
			threadsStr, _ := reader.ReadString('\n')
			threadsStr = strings.TrimSpace(threadsStr)
			threads, err := strconv.Atoi(threadsStr)
			if err == nil && threads > 0 {
				globalConfig.Threads = threads
			} else {
				fmt.Println("Invalid thread count.")
			}
		case "13":
			fmt.Print("Enter timeout in milliseconds: ")
			timeoutStr, _ = reader.ReadString('\n')
			timeoutStr = strings.TrimSpace(timeoutStr)
			timeout, err := strconv.Atoi(timeoutStr)
			if err == nil && timeout > 0 {
				globalConfig.Timeout = timeout
			} else {
				fmt.Println("Invalid timeout.")
			}
		case "14":
			fmt.Print("Enter custom nmap arguments: ")
			globalConfig.CustomNmap, _ = reader.ReadString('\n')
			globalConfig.CustomNmap = strings.TrimSpace(globalConfig.CustomNmap)
		case "15":
			var targets []string
			if globalConfig.TargetFile != "" {
				fileTargets, err := loadTargetsFromFile(globalConfig.TargetFile)
				if err != nil {
					fmt.Printf("Error loading targets from file: %s\n", err)
					continue
				}
				targets = append(targets, fileTargets...)
			} else if globalConfig.Targets != "" {
				targets = strings.Split(globalConfig.Targets, ",")
				for i := range targets {
					targets[i] = strings.TrimSpace(targets[i])
				}
			}

			if len(targets) > 0 {
				results := runScan(globalConfig, targets)
				displayResults(results)
				if globalConfig.OutputFile != "" {
					saveResults(results, globalConfig.OutputFile)
				}
			} else {
				fmt.Println("No targets specified. Please set targets or a target file.")
			}
		case "16":
			fmt.Println("Exiting r3cond0g.")
			return
		default:
			fmt.Println("Invalid choice. Please enter a number between 1 and 16.")
		}
	}
}

func getCurrentSetting(setting string, defaultVal string) string {
	if setting == "" {
		return defaultVal
	}
	return setting
}

func getCurrentPortSetting() string {
	if globalConfig.CommonPorts {
		return "Common Ports (" + globalConfig.Ports + ")"
	}
	if globalConfig.AllPorts {
		return "All Ports (" + globalConfig.Ports + ")"
	}
	if globalConfig.Ports != "" {
		return globalConfig.Ports
	}
	return "Default (1-1000)"
}

func boolToString(b bool) string {
	if b {
		return "Enabled"
	}
	return "Disabled"
}

// loadTargetsFromFile reads targets from a file
func loadTargetsFromFile(filename string) ([]string, error) {
	var targets []string
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		target := strings.TrimSpace(scanner.Text())
		if target != "" {
			targets = append(targets, target)
		}
	}
	return targets, scanner.Err()
}

// isCommandAvailable checks if a command is available
func isCommandAvailable(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// runRustScan runs a rustscan scan for a specific target
func runRustScan(config Config, target string) []string {
	if config.Verbose {
		fmt.Printf("Starting rustscan on %s...\n", target)
	}

	// Build rustscan command
	args := []string{
		"-a", target,
		"--ulimit", "5000",
		"-t", strconv.Itoa(config.Timeout),
		"--scan-order", "serial",
	}

	if config.Ports != "" && !config.AllPorts && !config.CommonPorts {
		args = append(args, "-p", config.Ports)
	} else if config.AllPorts {
		args = append(args, "-p", allPortsRange)
	} else if config.CommonPorts {
		args = append(args, "-p", commonPortsList)
	}

	if config.Verbose {
		fmt.Printf("Running command: rustscan %s\n", strings.Join(args, " "))
	}

	// Run rustscan
	cmd := exec.Command("rustscan", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if !strings.Contains(err.Error(), "exit status 1") { // Ignore "no open ports" error as an error
			fmt.Printf("Error running rustscan on %s: %s\n", target, err)
		}
		return []string{}
	}

	// Parse rustscan output to get open ports
	openPorts := parseRustScanOutput(string(output))

	if config.Verbose {
		fmt.Printf("Open ports found on %s: %s\n", target, strings.Join(openPorts, ", "))
	}

	return openPorts
}

// parseRustScanOutput parses the output of rustscan
func parseRustScanOutput(output string) []string {
	var openPorts []string

	// Split output by lines
	lines := strings.Split(output, "\n")

	// Look for lines containing port information
	for _, line := range lines {
		if strings.Contains(line, "Open") && strings.Contains(line, "tcp") {
			parts := strings.Fields(line)
			for _, part := range parts {
				// Check if part is a port number
				if port, err := strconv.Atoi(part); err == nil {
					openPorts = append(openPorts, strconv.Itoa(port))
				}
			}
		}
	}

	return uniqueStrings(openPorts)
}

// uniqueStrings removes duplicate strings from a slice
func uniqueStrings(input []string) []string {
	uniqueMap := make(map[string]bool)
	list := []string{}
	for _, entry := range input {
		if _, value := uniqueMap[entry]; !value {
			uniqueMap[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

// runScan performs the actual scanning
func runScan(config Config, targets []string) []ScanResult {
	fmt.Println("=== Starting Scan ===")
	fmt.Printf("Target(s): %s\n", strings.Join(targets, ", "))
	fmt.Printf("Ports: %s\n", config.Ports)
	fmt.Printf("Scan Type: %s\n", config.ScanType)

	var results []ScanResult

	// Check if nmap is available
	if !isCommandAvailable("nmap") {
		fmt.Println("Error: nmap is not installed or not in PATH")
		fmt.Println("Please install nmap and try again")
		return results
	}

	if config.FastMode && config.UseRustScan && isCommandAvailable("rustscan") {
		fmt.Println("Using rustscan for port discovery...")
		var allOpenPorts map[string][]string = make(map[string][]string)
		for _, target := range targets {
			openPorts := runRustScan(config, target)
			if len(openPorts) > 0 {
				allOpenPorts[target] = openPorts
			}
		}

		if len(allOpenPorts) > 0 {
			// Use nmap for service and OS detection on open ports found by rustscan
			fmt.Println("Running nmap on discovered open ports...")
			var wg sync.WaitGroup
			var mutex sync.Mutex
			for target, openPorts := range allOpenPorts {
				wg.Add(1)
				go func(target string, openPorts []string) {
					defer wg.Done()
					nmapConfig := config
					nmapConfig.Targets = target
					nmapConfig.Ports = strings.Join(openPorts, ",")
					nmapResults := runNmapScan(nmapConfig)
					mutex.Lock()
					results = append(results, nmapResults...)
					mutex.Unlock()
				}(target, openPorts)
			}
			wg.Wait()

			// Perform banner grabbing separately after the nmap scan for open TCP ports
			if config.BannerGrab {
				fmt.Println("Performing banner grabbing...")
				for i := range results {
					if len(results[i].Ports) > 0 {
						results[i].Banners = grabBanners(results[i].IP, results[i].Ports)
					}
				}
			}

		} else {
			fmt.Println("No open ports found by rustscan.")
		}
	} else {
		// Use nmap directly
		if config.UseRustScan && !isCommandAvailable("rustscan") {
			fmt.Println("Warning: rustscan not found, falling back to nmap")
		}
		var wg sync.WaitGroup
		var mutex sync.Mutex
		for _, target := range targets {
			wg.Add(1)
			go func(target string) {
				defer wg.Done()
				nmapConfig := config
				nmapConfig.Targets = target
				nmapResults := runNmapScan(nmapConfig)
				mutex.Lock()
				results = append(results, nmapResults...)
				mutex.Unlock()
			}(target)
		}
		wg.Wait()

		// Perform banner grabbing if requested
		if config.BannerGrab {
			fmt.Println("Performing banner grabbing...")
			for i := range results {
				if len(results[i].Ports) > 0 {
					results[i].Banners = grabBanners(results[i].IP, results[i].Ports)
				}
			}
		}
	}

	return results
}

// runNmapScan runs an nmap scan for a specific target (configuration already contains the target)
func runNmapScan(config Config) []ScanResult {
	if config.Verbose {
		fmt.Printf("Starting nmap scan on %s...\n", config.Targets)
	}

	// Temporary file for XML output
	tmpFile, err := os.CreateTemp("", "r3cond0g_nmap_*.xml")
	if err != nil {
		fmt.Printf("Error creating temporary file: %s\n", err)
		return []ScanResult{}
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Build nmap command
	args := []string{
		"-oX", tmpFile.Name(), // XML output
	}

	// Add scan type
	switch config.ScanType {
	case "SYN":
		args = append(args, "-sS")
	case "CONNECT":
		args = append(args, "-sT")
	case "UDP":
		args = append(args, "-sU")
	case "NULL": // Added
		args = append(args, "-sN")
	case "FIN": // Added
		args = append(args, "-sF")
	case "XMAS": // Added
		args = append(args, "-sX")
	case "COMPREHENSIVE":
		args = append(args, "-sS", "-sV", "-O", "--script=default")
	default:
		args = append(args, "-sS") // Default to SYN
	}

	// Add ports
	if config.Ports != "" {
		args = append(args, "-p", config.Ports)
	}

	// Add service detection
	if config.ServiceScan {
		args = append(args, "-sV")
	}

	// Add OS detection
	if config.OsScan {
		args = append(args, "-O")
	}

	// Add script scanning
	if config.ScriptScan {
		args = append(args, "--script=default")
	}

	// Add custom arguments
	if config.CustomNmap != "" {
		customArgs := strings.Fields(config.CustomNmap)
		args = append(args, customArgs...)
	}

	// Add targets
	args = append(args, config.Targets)

	if config.Verbose {
		fmt.Printf("Running command: nmap %s\n", strings.Join(args, " "))
	}

	// Run nmap
	cmd := exec.Command("nmap", args...)
	var stdout, stderr strings.Builder
	cmd.Stdout = io.MultiWriter(os.Stdout, &stdout)
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderr)

	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error running nmap on %s: %s\n", config.Targets, err)
		return []ScanResult{}
	}

	// Parse nmap XML output
	results, err := parseNmapXML(tmpFile.Name())
	if err != nil {
		fmt.Printf("Error parsing nmap output on %s: %s\n", config.Targets, err)
		return []ScanResult{}
	}

	return results
}

// parseNmapXML parses the XML output from nmap
func parseNmapXML(xmlFile string) ([]ScanResult, error) {
	var results []ScanResult

	// Read XML file
	xmlData, err := os.ReadFile(xmlFile)
	if err != nil {
		return results, err
	}

	var nmapRun NmapRun
	err = xml.Unmarshal(xmlData, &nmapRun)
	if err != nil {
		return results, err
	}

	// Process each host
	for _, host := range nmapRun.Hosts {
		var result ScanResult
		result.IP = host.Address.Addr
		result.Banners = make(map[int]string) // Initialize banner map

		// Resolve hostname
		if addrs, err := net.LookupAddr(result.IP); err == nil && len(addrs) > 0 {
			result.Hostname = addrs[0]
		}

		// Get OS information
		if len(host.OS.OsMatches) > 0 {
			result.OS = host.OS.OsMatches[0].Name
		}

		// Get port information
		for _, port := range host.Ports.Ports {
			portNum, _ := strconv.Atoi(port.PortID)

			portInfo := PortInfo{
				Port:     portNum,
				Protocol: port.Protocol,
				Service:  port.Service.Name,
				State:    port.State.State,
			}

			result.Ports = append(result.Ports, portInfo)
		}

		results = append(results, result)
	}

	return results, nil
}

// grabBanners attempts to grab banners from open TCP ports
func grabBanners(ip string, ports []PortInfo) map[int]string {
	banners := make(map[int]string)
	var wg sync.WaitGroup
	var mutex sync.Mutex

	for _, portInfo := range ports {
		if portInfo.Protocol == "tcp" && portInfo.State == "open" {
			wg.Add(1)
			go func(ip string, port int) {
				defer wg.Done()
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), time.Duration(globalConfig.Timeout)*time.Millisecond)
				if err == nil {
					defer conn.Close()
					buffer := make([]byte, 1024)
					conn.SetReadDeadline(time.Now().Add(time.Duration(globalConfig.Timeout) * time.Millisecond))
					n, err := conn.Read(buffer)
					if err == nil || err == io.EOF {
						banner := string(buffer[:n])
						mutex.Lock()
						banners[port] = strings.TrimSpace(banner)
						mutex.Unlock()
					}
				}
			}(ip, portInfo.Port)
		}
	}
	wg.Wait()
	return banners
}

// displayResults displays the scan results
func displayResults(results []ScanResult) {
	if len(results) == 0 {
		fmt.Println("No results found.")
		return
	}

	fmt.Printf("\n=== Scan Results (%d hosts) ===\n", len(results))

	for _, result := range results {
		fmt.Println("\n------------------------------------")
		fmt.Printf("Host: %s", result.IP)
		if result.Hostname != "" {
			fmt.Printf(" (%s)", result.Hostname)
		}
		fmt.Println()

		if result.OS != "" {
			fmt.Printf("OS: %s\n", result.OS)
		}

		if len(result.Ports) > 0 {
			fmt.Printf("Open Ports: %d\n", len(result.Ports))
			fmt.Println("PORT\tSTATE\tSERVICE\tBANNER")

			for _, port := range result.Ports {
				if port.State == "open" {
					banner := ""
					if bannerText, ok := result.Banners[port.Port]; ok {
						banner = fmt.Sprintf("\t%s", strings.ReplaceAll(bannerText, "\n", " "))
					}
					fmt.Printf("%d/%s\t%s\t%s%s\n", port.Port, port.Protocol, port.State, port.Service, banner)
				}
			}
		} else {
			fmt.Println("No open ports found.")
		}
	}

	fmt.Println("\n=== End of Results ===")
}

// saveResults saves the scan results to a file
func saveResults(results []ScanResult, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Error creating output file: %s\n", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	// Write header
	writer.WriteString(fmt.Sprintf("r3cond0g Scan Results\n"))
	writer.WriteString(fmt.Sprintf("Date: %s\n", time.Now().Format(time.RFC1123)))
	writer.WriteString(fmt.Sprintf("Targets: %s\n", globalConfig.Targets))
	writer.WriteString(fmt.Sprintf("Ports: %s\n", globalConfig.Ports))
	writer.WriteString(fmt.Sprintf("Scan Type: %s\n\n", globalConfig.ScanType))

	// Write results
	for _, result := range results {
		writer.WriteString(fmt.Sprintf("Host: %s", result.IP))
		if result.Hostname != "" {
			writer.WriteString(fmt.Sprintf(" (%s)", result.Hostname))
		}
		writer.WriteString("\n")

		if result.OS != "" {
			writer.WriteString(fmt.Sprintf("OS: %s\n", result.OS))
		}

		if len(result.Ports) > 0 {
			writer.WriteString(fmt.Sprintf("Open Ports: %d\n", len(result.Ports)))
			writer.WriteString("PORT\tSTATE\tSERVICE\tBANNER\n")

			for _, port := range result.Ports {
				if port.State == "open" {
					banner := ""
					if bannerText, ok := result.Banners[port.Port]; ok {
						banner = strings.ReplaceAll(bannerText, "\n", " ")
					}
					writer.WriteString(fmt.Sprintf("%d/%s\t%s\t%s\t%s\n", port.Port, port.Protocol, port.State, port.Service, banner))
				}
			}
		} else {
			writer.WriteString("No open ports found.\n")
		}

		writer.WriteString("\n")
	}

	writer.Flush()
	fmt.Printf("Results saved to %s\n", filename)
}
