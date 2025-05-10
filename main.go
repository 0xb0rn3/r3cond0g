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
	AppVersion = "0.0.1"
	AppBanner  = `
 _____  _____               _  ___       
|  __ \|___ /              | |/ _ \      
| |__) | |_ \  ___ ___   __| | | | | __ _
|  _  /|___) |/ __/ _ \ / _' | | | |/ _' |
| | \ \____/ | (_| (_) | (_| | |_| | (_| |
|_|  \_\_____|\___\___/ \__,_|\___/ \__, |
                                     __/ |
                                    |___/ 
Advanced Network Reconnaissance Tool v0.0.1
`
)

// ScanResult represents the result of a scan
type ScanResult struct {
	IP       string
	Hostname string
	Ports    []PortInfo
	OS       string
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
	XMLName xml.Name `xml:"osmatch"`
	Name    string   `xml:"name,attr"`
	Accuracy string  `xml:"accuracy,attr"`
}

// OsFingerprint represents an osfingerprint element in Nmap XML output
type OsFingerprint struct {
	XMLName xml.Name `xml:"osfingerprint"`
	Fingerprint string `xml:"fingerprint,attr"`
}

// Config represents the configuration for the scanner
type Config struct {
	Targets      string
	Ports        string
	ScanType     string
	Threads      int
	Timeout      int
	OutputFile   string
	Verbose      bool
	FastMode     bool
	ServiceScan  bool
	OsScan       bool
	ScriptScan   bool
	CustomNmap   string
	UseRustScan  bool
}

// globalConfig holds the configuration for the scanner
var globalConfig Config

// main is the entry point for the application
func main() {
	// Parse command line flags
	flag.StringVar(&globalConfig.Targets, "targets", "", "Target specification (CIDR, IP range, or comma-separated IPs)")
	flag.StringVar(&globalConfig.Ports, "ports", "1-1000", "Port specification (e.g., 80,443,8080 or 1-1000)")
	flag.StringVar(&globalConfig.ScanType, "scan", "SYN", "Scan type (SYN, CONNECT, UDP, COMPREHENSIVE)")
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
	
	flag.Parse()

	// Display banner
	fmt.Println(AppBanner)
	
	// Interactive mode if no targets specified
	if globalConfig.Targets == "" {
		runInteractiveMode()
	} else {
		// Run the scan with the provided configuration
		results := runScan(globalConfig)
		
		// Display results
		displayResults(results)
		
		// Save results if output file is specified
		if globalConfig.OutputFile != "" {
			saveResults(results, globalConfig.OutputFile)
		}
	}
}

// runInteractiveMode provides an interactive interface for the user
func runInteractiveMode() {
	reader := bufio.NewReader(os.Stdin)
	
	fmt.Println("=== r3cond0g Interactive Mode ===")
	fmt.Println("Enter the target specification (CIDR, IP range, or comma-separated IPs):")
	globalConfig.Targets, _ = reader.ReadString('\n')
	globalConfig.Targets = strings.TrimSpace(globalConfig.Targets)
	
	fmt.Println("Enter port specification (default: 1-1000):")
	ports, _ := reader.ReadString('\n')
	ports = strings.TrimSpace(ports)
	if ports != "" {
		globalConfig.Ports = ports
	}
	
	fmt.Println("Select scan type:")
	fmt.Println("1. SYN scan (default)")
	fmt.Println("2. Connect scan")
	fmt.Println("3. UDP scan")
	fmt.Println("4. Comprehensive scan")
	scanType, _ := reader.ReadString('\n')
	scanType = strings.TrimSpace(scanType)
	switch scanType {
	case "2":
		globalConfig.ScanType = "CONNECT"
	case "3":
		globalConfig.ScanType = "UDP"
	case "4":
		globalConfig.ScanType = "COMPREHENSIVE"
	default:
		globalConfig.ScanType = "SYN"
	}
	
	fmt.Println("Enable service detection? (y/n, default: n):")
	service, _ := reader.ReadString('\n')
	service = strings.TrimSpace(strings.ToLower(service))
	globalConfig.ServiceScan = service == "y" || service == "yes"
	
	fmt.Println("Enable OS detection? (y/n, default: n):")
	os, _ := reader.ReadString('\n')
	os = strings.TrimSpace(strings.ToLower(os))
	globalConfig.OsScan = os == "y" || os == "yes"
	
	fmt.Println("Enable script scanning? (y/n, default: n):")
	script, _ := reader.ReadString('\n')
	script = strings.TrimSpace(strings.ToLower(script))
	globalConfig.ScriptScan = script == "y" || script == "yes"
	
	fmt.Println("Use rustscan for faster port discovery if available? (y/n, default: n):")
	fast, _ := reader.ReadString('\n')
	fast = strings.TrimSpace(strings.ToLower(fast))
	globalConfig.UseRustScan = fast == "y" || fast == "yes"
	
	fmt.Println("Enter output file name (leave empty to skip):")
	outputFile, _ := reader.ReadString('\n')
	globalConfig.OutputFile = strings.TrimSpace(outputFile)
	
	fmt.Println("Enable verbose output? (y/n, default: n):")
	verbose, _ := reader.ReadString('\n')
	verbose = strings.TrimSpace(strings.ToLower(verbose))
	globalConfig.Verbose = verbose == "y" || verbose == "yes"
	
	// Run the scan with the provided configuration
	results := runScan(globalConfig)
	
	// Display results
	displayResults(results)
	
	// Save results if output file is specified
	if globalConfig.OutputFile != "" {
		saveResults(results, globalConfig.OutputFile)
	}
}

// runScan performs the actual scanning
func runScan(config Config) []ScanResult {
	fmt.Println("=== Starting Scan ===")
	fmt.Printf("Target(s): %s\n", config.Targets)
	fmt.Printf("Ports: %s\n", config.Ports)
	fmt.Printf("Scan Type: %s\n", config.ScanType)
	
	var results []ScanResult
	
	// Check if nmap is available
	if !isCommandAvailable("nmap") {
		fmt.Println("Error: nmap is not installed or not in PATH")
		fmt.Println("Please install nmap and try again")
		return results
	}
	
	// Use rustscan if available and requested
	if config.UseRustScan && isCommandAvailable("rustscan") {
		fmt.Println("Using rustscan for port discovery...")
		openPorts := runRustScan(config)
		if len(openPorts) > 0 {
			// Use nmap for service detection on open ports found by rustscan
			config.Ports = strings.Join(openPorts, ",")
			results = runNmapScan(config)
		} else {
			fmt.Println("No open ports found by rustscan")
		}
	} else {
		// Use nmap directly
		if config.UseRustScan && !isCommandAvailable("rustscan") {
			fmt.Println("Warning: rustscan not found, falling back to nmap")
		}
		results = runNmapScan(config)
	}
	
	return results
}

// isCommandAvailable checks if a command is available
func isCommandAvailable(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// runRustScan runs a rustscan scan
func runRustScan(config Config) []string {
	fmt.Println("Starting rustscan...")
	
	// Build rustscan command
	args := []string{
		"-a", config.Targets,
		"--ulimit", "5000",
		"-t", strconv.Itoa(config.Timeout),
		"--scan-order", "serial",
	}
	
	if config.Ports != "" && config.Ports != "1-1000" {
		args = append(args, "-p", config.Ports)
	}
	
	if config.Verbose {
		fmt.Printf("Running command: rustscan %s\n", strings.Join(args, " "))
	}
	
	// Run rustscan
	cmd := exec.Command("rustscan", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running rustscan: %s\n", err)
		return []string{}
	}
	
	// Parse rustscan output to get open ports
	openPorts := parseRustScanOutput(string(output))
	
	if config.Verbose {
		fmt.Printf("Open ports found: %s\n", strings.Join(openPorts, ", "))
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
	
	return openPorts
}

// runNmapScan runs an nmap scan
func runNmapScan(config Config) []ScanResult {
	fmt.Println("Starting nmap scan...")
	
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
	case "COMPREHENSIVE":
		args = append(args, "-sS", "-sV", "-O", "--script=default")
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
	
	err = cmd.Run()
	if err != nil {
		fmt.Printf("Error running nmap: %s\n", err)
		return []ScanResult{}
	}
	
	// Parse nmap XML output
	results, err := parseNmapXML(tmpFile.Name())
	if err != nil {
		fmt.Printf("Error parsing nmap output: %s\n", err)
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
			fmt.Println("PORT\tSTATE\tSERVICE")
			
			for _, port := range result.Ports {
				if port.State == "open" {
					fmt.Printf("%d/%s\t%s\t%s\n", port.Port, port.Protocol, port.State, port.Service)
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
			writer.WriteString("PORT\tSTATE\tSERVICE\n")
			
			for _, port := range result.Ports {
				if port.State == "open" {
					writer.WriteString(fmt.Sprintf("%d/%s\t%s\t%s\n", port.Port, port.Protocol, port.State, port.Service))
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

// parallelScan performs scanning in parallel
func parallelScan(targets []string, config Config) []ScanResult {
	var results []ScanResult
	var mutex sync.Mutex
	var wg sync.WaitGroup
	
	// Create semaphore for concurrency control
	semaphore := make(chan struct{}, config.Threads)
	
	for _, target := range targets {
		wg.Add(1)
		semaphore <- struct{}{}
		
		go func(target string) {
			defer wg.Done()
			defer func() { <-semaphore }()
			
			// Copy configuration for this target
			targetConfig := config
			targetConfig.Targets = target
			
			// Run scan for this target
			targetResults := runNmapScan(targetConfig)
			
			// Add results to the global results
			mutex.Lock()
			results = append(results, targetResults...)
			mutex.Unlock()
		}(target)
	}
	
	wg.Wait()
	return results
}
