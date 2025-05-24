// r3cond0g: Advanced Network Reconnaissance & Sniffing Tool
// Version: 0.0.2 BETA
// Authors: 0xb0rn3 | 0xbv1
// For educational and ethical use in controlled environments only

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
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort" // Added for sorting displayTopNFlows
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo" // For writing PCAP files
)

// Constants
const (
	AppName        = "r3cond0g"
	AppVersion     = "0.0.2 BETA"
	AppAuthors     = "0xb0rn3 | 0xbv1"
	AppConfigDir   = ".r3cond0g"
	AppConfigFile  = "config.json"
	DefaultTimeout = 3000 // ms
	AppBanner      = `
  _____ _____                              _   ___   _ _   _____
 |  __ \___ /                             | | / _ \ | | | /  ___|
 | |__) | |_ \ ___ ___  __ _ _ __ ___  __| | | | | || | | \ '--.
 |  _  /|___) / __/ _ \/ _' | '_ ' _ \/ _' | | | | |/ _' |  '--. \
 | | \ \____/ | (_| (_) | (_| | | | | | | (_| | | |_| | (_| | /\__/ /
 |_|  \_\_____|\___\___/\__,_|_| |_| |_|\__,_| \___/ \__, | \____/  %s
                                                        __/ |
                                                       |___/
  Advanced Network Reconnaissance & Sniffing Tool
  Authors: %s
`
)

// --- Data Structures ---

type ScanResult struct {
	IP                   string
	Hostname             string
	Ports                []PortInfo
	OS                   string
	Banners              map[int]string
	PotentialVulns       []VulnerabilityInsight
	NmapScriptResults    string
	RustscanInitialPorts []string
	WebDiscoveryResults  []WebDiscoveryResult
}

type PortInfo struct {
	Port     int
	Protocol string
	Service  string
	Version  string
	State    string
}

type VulnerabilityInsight struct {
	Port        int
	ServiceName string
	Version     string
	Insight     string
	Severity    string
	Reference   string
	Source      string
}

type WebDiscoveryResult struct {
	URL        string
	StatusCode int
	Title      string
	Length     int64
	Found      bool
}

type SnifferRunSummary struct {
	Interface     string
	Filter        string
	PacketsSeen   int
	TCPSummary    map[string]int
	UDPSummary    map[string]int
	DNSSummary    []string
	HTTPSummary   []string
	FTPSummary    []string
	TelnetSummary []string
	PcapFile      string
	StartTime     time.Time
	EndTime       time.Time
	Errors        []string
}

type Config struct {
	Targets             string
	Ports               string
	ScanType            string
	Threads             int
	Timeout             int
	OutputFile          string
	OutputFormat        string
	Verbose             bool
	ServiceScan         bool
	OsScan              bool
	ScriptScan          bool
	CustomNmapArgs      string
	UseRustScan         bool
	TargetFile          string
	CommonPorts         bool
	AllPorts            bool
	BannerGrab          bool
	VulnInsightScan     bool
	CustomVulnDBFile    string
	WebDiscoveryEnabled bool
	WebWordlistFile     string
	SniffInterface      string
	SniffDuration       int
	SniffBPFFilter      string
	SniffPcapFile       string
	SaveConfigOnExit    bool
}

// Nmap XML parsing structures
type NmapRun struct { XMLName xml.Name `xml:"nmaprun"`; Hosts []Host `xml:"host"`; ScanInfo ScanInfo `xml:"scaninfo"`}
type ScanInfo struct { Type string `xml:"type,attr"`; Protocol string `xml:"protocol,attr"`; NumServices string `xml:"numservices,attr"`; Services    string `xml:"services,attr"`}
type Host struct { XMLName xml.Name `xml:"host"`; Status Status `xml:"status"`; Address Address  `xml:"address"`; Hostnames []Hostname `xml:"hostnames>hostname"`; Ports NmapPorts `xml:"ports"`; OS OS `xml:"os"`; Trace Trace `xml:"trace"`}
type Status struct { State string `xml:"state,attr"`; Reason string `xml:"reason,attr"`; ReasonTTL string `xml:"reason_ttl,attr"`}
type Address struct { XMLName xml.Name `xml:"address"`; Addr string `xml:"addr,attr"`; AddrType string `xml:"addrtype,attr"`; Vendor   string `xml:"vendor,attr"`}
type Hostname struct { Name string `xml:"name,attr"`; Type string `xml:"type,attr"`}
type NmapPorts struct { XMLName xml.Name `xml:"ports"`; Ports []NmapPort `xml:"port"`}
type NmapPort struct { XMLName xml.Name `xml:"port"`; Protocol string `xml:"protocol,attr"`; PortID string `xml:"portid,attr"`; State NmapState `xml:"state"`; Service NmapService `xml:"service"`; Scripts  []NmapScript `xml:"script"`}
type NmapState struct { XMLName xml.Name `xml:"state"`; State string `xml:"state,attr"`; Reason string `xml:"reason,attr"`; ReasonTTL string `xml:"reason_ttl,attr"`}
type NmapService struct { XMLName xml.Name `xml:"service"`; Name string `xml:"name,attr"`; Product string `xml:"product,attr"`; Version string `xml:"version,attr"`; ExtraInfo  string   `xml:"extrainfo,attr"`; Method string `xml:"method,attr"`; Conf string `xml:"conf,attr"`; CPEs []string `xml:"cpe"`; ServiceFP  string   `xml:"servicefp,attr"`; Tunnel string `xml:"tunnel,attr"`; Proto string `xml:"proto,attr"`; RPCType    string   `xml:"rpcnum,attr"`; Hostname   string   `xml:"hostname,attr"`; OSType     string   `xml:"ostype,attr"`; DeviceType string   `xml:"devicetype,attr"`}
type NmapScript struct { ID string `xml:"id,attr"`; Output string `xml:"output,attr"`}
type OS struct { XMLName xml.Name `xml:"os"`; OsMatches []OsMatch `xml:"osmatch"`; OsFingerprint OsFingerprint `xml:"osfingerprint"`; PortsUsed     []PortUsed    `xml:"portused"`}
type PortUsed struct { State string `xml:"state,attr"`; Proto string `xml:"proto,attr"`; PortID string `xml:"portid,attr"`}
type OsMatch struct { XMLName xml.Name `xml:"osmatch"`; Name string `xml:"name,attr"`; Accuracy string `xml:"accuracy,attr"`; Line string `xml:"line,attr"`; OSClasses []OSClass `xml:"osclass"`}
type OSClass struct { XMLName xml.Name `xml:"osclass"`; Type string `xml:"type,attr"`; Vendor string `xml:"vendor,attr"`; OSFamily string  `xml:"osfamily,attr"`; OSGen   string   `xml:"osgen,attr"`; Accuracy string  `xml:"accuracy,attr"`; CPEs    []string `xml:"cpe"`}
type OsFingerprint struct { XMLName xml.Name `xml:"osfingerprint"`; Fingerprint string `xml:"fingerprint,attr"`}
type Trace struct { XMLName xml.Name `xml:"trace"`; Proto string `xml:"proto,attr"`; Port string `xml:"port,attr"`; Hops []Hop `xml:"hop"`}
type Hop struct { TTL string `xml:"ttl,attr"`; RTT string `xml:"rtt,attr"`; IPAddr string `xml:"ipaddr,attr"`; Host string `xml:"host,attr"`}

// --- Global Variables ---
var globalConfig Config
var configFilePath string
var internalVulnDB = make(map[string]map[string]VulnerabilityInsight)
var customVulnDB = make(map[string]map[string]VulnerabilityInsight)
var defaultWebWordlist = []string{
	"/", "/index.html", "/index.php", "/index.jsp", "/robots.txt", "/sitemap.xml",
	"/.git/config", "/.git/HEAD", "/.svn/entries", "/.DS_Store",
	"/.env", "/env.txt", "/config.js", "/config.json", "/settings.py",
	"/admin", "/login", "/dashboard", "/backup", "/tmp", "/temp",
	"/uploads", "/static", "/assets", "/includes", "/cgi-bin/",
	"/phpmyadmin/", "/pma/", "/webdav/", "/conf/", "/config/",
	"/api/v1/users", "/api/v2/status", "/.well-known/security.txt",
	"/README", "/readme.md", "/INSTALL", "/LICENSE", "/CHANGELOG",
	"/flag.txt", "/flag", "/secret.txt", "/admin.php~", "/config.php.bak",
	"/cmd.php", "/shell.php", "/test.php", "/info.php",
}
var commonPortsList = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1024-1029,1433,1521,1723,3306,3389,5432,5800,5900,6379,8000,8009,8080,8443,9200,9300,27017,11211"
var allPortsRange = "1-65535"

// --- Initialization ---
func init() {
	internalVulnDB = map[string]map[string]VulnerabilityInsight{
		"ftp": {
			"vsftpd 2.3.4":    {Insight: "Known backdoor vulnerability.", Severity: "Critical", Reference: "CVE-2011-2523", Source: "internal"},
			"ProFTPD 1.3.5":   {Insight: "mod_copy Arbitrary File Copy.", Severity: "High", Reference: "CVE-2015-3306", Source: "internal"},
			"Pure-FTPd":       {Insight: "Check for specific version vulnerabilities.", Severity: "Medium", Reference: "Search CVEs", Source: "internal"},
			"*":               {Insight: "FTP transmits credentials in cleartext. Check for anonymous access (USER anonymous, PASS anonymous).", Severity: "Medium", Reference: "CWE-319", Source: "internal"},
		},
		"ssh": {
			"OpenSSH <7.7":   {Insight: "User enumeration via packet timing (CVE-2018-15473).", Severity: "Medium", Reference: "CVE-2018-15473", Source: "internal"},
			"OpenSSH <8.5":   {Insight: "Potential regex DoS in ssh-add (CVE-2021-28041), less impactful for server.", Severity: "Low", Reference: "CVE-2021-28041", Source: "internal"},
			"Dropbear sshd": {Insight: "Check specific version for vulns (e.g., <2020.79 scp overflow CVE-2020-14000).", Severity: "Medium", Reference: "Search Dropbear CVEs", Source: "internal"},
		},
		"telnet": {"*": {Insight: "Telnet is insecure (plaintext credentials). Avoid if possible. Capture traffic for creds.", Severity: "High", Reference: "CWE-319", Source: "internal"}},
		"smtp":   {"*": {Insight: "Check for open relay, EXPN/VRFY commands (user enumeration).", Severity: "Medium", Reference: "CWE-200", Source: "internal"}},
		"http": {
			"Apache httpd 2.4.49": {Insight: "Path Traversal & RCE (CVE-2021-41773, CVE-2021-42013).", Severity: "Critical", Reference: "CVE-2021-41773", Source: "internal"},
			"Apache httpd 2.4.50": {Insight: "Path Traversal (incomplete fix for CVE-2021-41773, leads to CVE-2021-42013).", Severity: "Critical", Reference: "CVE-2021-42013", Source: "internal"},
			"nginx <1.20.1":       {Insight: "Off-by-one in resolver (CVE-2021-23017) if using specific DNS setup.", Severity: "Medium", Reference: "CVE-2021-23017", Source: "internal"},
			"Microsoft IIS 7.5":  {Insight: "Old version, check patch level. Potential for various vulns like .NET Tilde enum.", Severity: "High", Reference: "Search IIS 7.5 CVEs", Source: "internal"},
			"Tomcat":             {Insight: "Check default credentials for manager console (e.g., tomcat/s3cret). Check for AJP Ghostcat (CVE-2020-1938).", Severity: "High", Reference: "CVE-2020-1938", Source: "internal"},
			"PHP":                {Insight: "If X-Powered-By: PHP/version is visible, check version for specific vulns. Check for common PHP vulns like RCE, LFI/RFI.", Severity: "High", Reference: "php.net/releases", Source: "internal"},
		},
		"https":        {"*": {Insight: "Check for SSL/TLS misconfigurations (weak ciphers, expired certs, Heartbleed if very old OpenSSL).", Severity: "Medium", Reference: "SSL Labs Test", Source: "internal"}},
		"smb":         {"*": {Insight: "Check anonymous access (smbclient -L //HOST -N), weak shares, MS17-010 (EternalBlue), SMBGhost (CVE-2020-0796).", Severity: "Critical", Reference: "MS17-010, CVE-2020-0796", Source: "internal"}},
		"mysql":       {"*": {Insight: "Default/weak credentials (root/root, root/toor, root/password). Try 'mysql -u root'. CVE-2012-2122 (auth bypass).", Severity: "High", Reference: "CVE-2012-2122", Source: "internal"}},
		"postgresql":  {"*": {Insight: "Default/weak credentials (postgres/postgres). CVE-2019-9193 (RCE via COPY TO/FROM PROGRAM).", Severity: "High", Reference: "CVE-2019-9193", Source: "internal"}},
		"rdp":         {"*": {Insight: "BlueKeep (CVE-2019-0708) for unpatched pre-Win8/Server2012. Brute-force weak creds. DejaBlue (CVE-2019-1181/1182).", Severity: "Critical", Reference: "CVE-2019-0708", Source: "internal"}},
		"vnc":         {"*": {Insight: "Check for no authentication or weak passwords (e.g., 'password', 'vnc').", Severity: "High", Reference: "CWE-287", Source: "internal"}},
		"mongodb":     {"*": {Insight: "Default config often allows unauthenticated access. Check with 'mongo host:port'.", Severity: "Critical", Reference: "CWE-284", Source: "internal"}},
		"redis":       {"*": {Insight: "Default config often allows unauthenticated access. Try 'redis-cli -h host -p port'. Can lead to RCE.", Severity: "Critical", Reference: "CWE-284", Source: "internal"}},
		"elasticsearch": {"*": {Insight: "Older versions (<1.2) had RCE (CVE-2014-3120). Unauth access to /_nodes or /_search can leak data.", Severity: "High", Reference: "CVE-2014-3120", Source: "internal"}},
		"jenkins":     {"*": {Insight: "Check for unauthenticated access to /script console (RCE). Default creds (admin/admin, admin/password).", Severity: "Critical", Reference: "CWE-284", Source: "internal"}},
		"docker":      {"*": {Insight: "Exposed Docker API (port 2375/2376) can lead to container/host compromise if unauthenticated.", Severity: "Critical", Reference: "CWE-284", Source: "internal"}},
	}
}

// --- Main Application Logic ---
func main() {
	homeDir, err := os.UserHomeDir()
	if err == nil { configFilePath = filepath.Join(homeDir, AppConfigDir, AppConfigFile) }
	if !loadConfiguration(&globalConfig, configFilePath) { setDefaultConfig(&globalConfig) }
	if globalConfig.CustomVulnDBFile != "" { loadCustomVulnerabilities(globalConfig.CustomVulnDBFile) }

	flag.StringVar(&globalConfig.Targets, "targets", globalConfig.Targets, "Target specification (CIDR, IP range, or comma-separated IPs)")
	flag.StringVar(&globalConfig.TargetFile, "file", globalConfig.TargetFile, "Path to a file containing a list of targets")
	flag.StringVar(&globalConfig.Ports, "ports", globalConfig.Ports, "Port specification (e.g., 80,443,8080 or 1-1000)")
	flag.BoolVar(&globalConfig.CommonPorts, "common-ports", globalConfig.CommonPorts, "Scan common ports")
	flag.BoolVar(&globalConfig.AllPorts, "all-ports", globalConfig.AllPorts, "Scan all 65535 ports")
	flag.StringVar(&globalConfig.ScanType, "scan", globalConfig.ScanType, "Nmap scan type (SYN, CONNECT, TCP, UDP, NULL, FIN, XMAS, AGGRESSIVE, COMPREHENSIVE)")
	flag.IntVar(&globalConfig.Threads, "threads", globalConfig.Threads, "Number of concurrent Nmap threads/operations")
	flag.IntVar(&globalConfig.Timeout, "timeout", globalConfig.Timeout, "Timeout in milliseconds for individual probes/operations")
	flag.StringVar(&globalConfig.OutputFile, "output", globalConfig.OutputFile, "Output file name (prefix, format will be appended)")
	flag.StringVar(&globalConfig.OutputFormat, "format", globalConfig.OutputFormat, "Output format (text, json, html)")
	flag.BoolVar(&globalConfig.Verbose, "verbose", globalConfig.Verbose, "Enable verbose output")
	flag.BoolVar(&globalConfig.ServiceScan, "service", globalConfig.ServiceScan, "Enable Nmap service detection (-sV)")
	flag.BoolVar(&globalConfig.OsScan, "os", globalConfig.OsScan, "Enable Nmap OS detection (-O)")
	flag.BoolVar(&globalConfig.ScriptScan, "script", globalConfig.ScriptScan, "Enable Nmap default script scanning (--script=default)")
	flag.StringVar(&globalConfig.CustomNmapArgs, "custom", globalConfig.CustomNmapArgs, "Custom nmap arguments")
	flag.BoolVar(&globalConfig.UseRustScan, "rustscan", globalConfig.UseRustScan, "Use rustscan for initial fast port discovery")
	flag.BoolVar(&globalConfig.BannerGrab, "banners", globalConfig.BannerGrab, "Attempt to grab banners from open TCP ports")
	flag.BoolVar(&globalConfig.VulnInsightScan, "vuln-insights", globalConfig.VulnInsightScan, "Enable basic vulnerability insights")
	flag.StringVar(&globalConfig.CustomVulnDBFile, "custom-vuln-db", globalConfig.CustomVulnDBFile, "Path to custom vulnerability DB JSON file")
	flag.BoolVar(&globalConfig.WebDiscoveryEnabled, "web-discover", globalConfig.WebDiscoveryEnabled, "Enable basic web directory/file discovery")
	flag.StringVar(&globalConfig.WebWordlistFile, "web-wordlist", globalConfig.WebWordlistFile, "Path to custom wordlist for web discovery")
	flag.StringVar(&globalConfig.SniffInterface, "sniff-iface", globalConfig.SniffInterface, "Network interface for sniffing")
	flag.IntVar(&globalConfig.SniffDuration, "sniff-duration", globalConfig.SniffDuration, "Duration for sniffing in seconds (0 for indefinite)")
	flag.StringVar(&globalConfig.SniffBPFFilter, "sniff-filter", globalConfig.SniffBPFFilter, "BPF filter for sniffing")
	flag.StringVar(&globalConfig.SniffPcapFile, "sniff-pcap", globalConfig.SniffPcapFile, "File to save sniffed packets (e.g., capture.pcap)")
	flag.BoolVar(&globalConfig.SaveConfigOnExit, "save-config", globalConfig.SaveConfigOnExit, "Save current settings to config file on exit from menu")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, AppBanner, AppVersion, AppAuthors)
		fmt.Fprintf(os.Stderr, "\nUsage: %s [options] or run without options for interactive menu\n\n", AppName)
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -targets 192.168.1.0/24 -common-ports -service -os -vuln-insights -output scan_results\n", AppName)
		fmt.Fprintf(os.Stderr, "  %s -file targets.txt -ports 80,443 -scan AGGRESSIVE -web-discover -format json\n", AppName)
		fmt.Fprintf(os.Stderr, "  %s -sniff-iface eth0 -sniff-duration 120 -sniff-filter \"tcp port 80\" -sniff-pcap traffic.pcap\n", AppName)
		fmt.Fprintf(os.Stderr, "  %s (interactive menu)\n", AppName)
	}
	flag.Parse()

	fmt.Printf(AppBanner+"\n", AppVersion, AppAuthors)

	if len(os.Args) == 1 {
		runMenu()
	} else {
		if globalConfig.Targets == "" && globalConfig.TargetFile == "" && globalConfig.SniffInterface == "" {
			fmt.Println("Error: No targets or sniffing interface specified via CLI.")
			flag.Usage(); os.Exit(1)
		}
		if globalConfig.SniffInterface != "" {
			runLiveSniffer(globalConfig.SniffInterface, globalConfig.SniffDuration, globalConfig.SniffBPFFilter, globalConfig.SniffPcapFile)
		} else {
			processScanRequest()
		}
	}
}

func setDefaultConfig(cfg *Config) {
	cfg.ScanType = "SYN"; cfg.Threads = 10; cfg.Timeout = DefaultTimeout; cfg.OutputFormat = "text"
	cfg.ServiceScan = true; cfg.OsScan = true; cfg.BannerGrab = true; cfg.UseRustScan = true
	cfg.Ports = ""; cfg.SaveConfigOnExit = true; cfg.SniffDuration = 60; cfg.VulnInsightScan = true
	cfg.WebDiscoveryEnabled = false
}

func runMenu() {
	reader := bufio.NewReader(os.Stdin)
	var input string
	for {
		fmt.Println("\n=== r3cond0g Menu v" + AppVersion + " ===")
		targetDisplay := "Not Set"; if globalConfig.TargetFile != "" { targetDisplay = fmt.Sprintf("File: %s", globalConfig.TargetFile) } else if globalConfig.Targets != "" { targetDisplay = globalConfig.Targets }
		fmt.Println("--- Scanning ---")
		fmt.Println("1. Set Target(s) (Current: " + targetDisplay + ")")
		fmt.Println("2. Set Ports (Current: " + getCurrentPortSetting() + ")")
		fmt.Println("3. Set Nmap Scan Type (Current: " + globalConfig.ScanType + ") (SYN, CONNECT, TCP, UDP, NULL, FIN, XMAS, AGGRESSIVE, COMPREHENSIVE)")
		fmt.Println("4. Toggle Service Detection (-sV) (Current: " + boolToString(globalConfig.ServiceScan) + ")")
		fmt.Println("5. Toggle OS Detection (-O) (Current: " + boolToString(globalConfig.OsScan) + ")")
		fmt.Println("6. Toggle Nmap Default Scripts (Current: " + boolToString(globalConfig.ScriptScan) + ")")
		fmt.Println("7. Toggle Banner Grabbing (Native) (Current: " + boolToString(globalConfig.BannerGrab) + ")")
		fmt.Println("8. Toggle Use Rustscan (Fast Scan) (Current: " + boolToString(globalConfig.UseRustScan) + ")")
		fmt.Println("9. Set Custom Nmap Arguments (Current: " + getCurrentSetting(globalConfig.CustomNmapArgs, "None") + ")")
		fmt.Println("\n--- Analysis & Discovery ---")
		fmt.Println("10. Toggle Vulnerability Insights (Current: " + boolToString(globalConfig.VulnInsightScan) + ")")
		fmt.Println("11. Set Custom Vulnerability DB (Current: " + getCurrentSetting(globalConfig.CustomVulnDBFile, "None") + ")")
		fmt.Println("12. Toggle Web Directory/File Discovery (Current: " + boolToString(globalConfig.WebDiscoveryEnabled) + ")")
		fmt.Println("13. Set Web Discovery Wordlist (Current: " + getCurrentSetting(globalConfig.WebWordlistFile, "Internal Default") + ")")
		fmt.Println("\n--- Sniffing ---")
		fmt.Println("14. Set Sniffing Interface (Current: " + getCurrentSetting(globalConfig.SniffInterface, "None") + ")")
		fmt.Println("15. Set Sniffing Duration (s, 0=inf) (Current: " + strconv.Itoa(globalConfig.SniffDuration) + ")")
		fmt.Println("16. Set Sniffing BPF Filter (Current: " + getCurrentSetting(globalConfig.SniffBPFFilter, "None") + ")")
		fmt.Println("17. Set Sniffing PCAP Output File (Current: " + getCurrentSetting(globalConfig.SniffPcapFile, "None") + ")")
		fmt.Println("18. List Network Interfaces")
		fmt.Println("P. Start Live Packet Sniffing")
		fmt.Println("\n--- Output & Settings ---")
		fmt.Println("19. Set Output File Prefix (Current: " + getCurrentSetting(globalConfig.OutputFile, "Not Set") + ")")
		fmt.Println("20. Set Output Format (Current: " + globalConfig.OutputFormat + ") (text, json, html)")
		fmt.Println("21. Set Nmap Threads (Current: " + strconv.Itoa(globalConfig.Threads) + ")")
		fmt.Println("22. Set Probe Timeout (ms) (Current: " + strconv.Itoa(globalConfig.Timeout) + ")")
		fmt.Println("23. Toggle Verbose Output (Current: " + boolToString(globalConfig.Verbose) + ")")
		fmt.Println("24. Save Current Configuration")
		fmt.Println("25. Load Configuration from File")
		fmt.Println("26. Toggle Save Config on Exit (Current: " + boolToString(globalConfig.SaveConfigOnExit) + ")")
		fmt.Println("\nS. Start Scan (using current target settings)")
		fmt.Println("Q. Quit")
		fmt.Print("Enter your choice: ")

		input, _ = reader.ReadString('\n'); input = strings.TrimSpace(strings.ToUpper(input))
		switch input {
		case "1": fmt.Println("Set Targets: (1) Direct Input, (2) From File"); fmt.Print("Choice: "); subInput, _ := reader.ReadString('\n'); subInput = strings.TrimSpace(subInput)
			if subInput == "1" { fmt.Print("Enter target(s): "); globalConfig.Targets, _ = reader.ReadString('\n'); globalConfig.Targets = strings.TrimSpace(globalConfig.Targets); globalConfig.TargetFile = ""
			} else if subInput == "2" { fmt.Print("Enter path to target file: "); globalConfig.TargetFile, _ = reader.ReadString('\n'); globalConfig.TargetFile = strings.TrimSpace(globalConfig.TargetFile); globalConfig.Targets = "" }
		case "2": configurePorts(reader)
		case "3": fmt.Print("Enter Nmap scan type: "); scanTypeInput, _ := reader.ReadString('\n'); globalConfig.ScanType = strings.TrimSpace(strings.ToUpper(scanTypeInput))
		case "4": globalConfig.ServiceScan = !globalConfig.ServiceScan
		case "5": globalConfig.OsScan = !globalConfig.OsScan
		case "6": globalConfig.ScriptScan = !globalConfig.ScriptScan
		case "7": globalConfig.BannerGrab = !globalConfig.BannerGrab
		case "8": globalConfig.UseRustScan = !globalConfig.UseRustScan
		case "9": fmt.Print("Enter custom Nmap arguments: "); globalConfig.CustomNmapArgs, _ = reader.ReadString('\n'); globalConfig.CustomNmapArgs = strings.TrimSpace(globalConfig.CustomNmapArgs)
		case "10": globalConfig.VulnInsightScan = !globalConfig.VulnInsightScan
		case "11": fmt.Print("Enter path to custom vuln DB JSON (blank to clear): "); fileInput, _ := reader.ReadString('\n'); globalConfig.CustomVulnDBFile = strings.TrimSpace(fileInput)
			if globalConfig.CustomVulnDBFile != "" { loadCustomVulnerabilities(globalConfig.CustomVulnDBFile) } else { customVulnDB = make(map[string]map[string]VulnerabilityInsight); fmt.Println("Custom vuln DB cleared.")}
		case "12": globalConfig.WebDiscoveryEnabled = !globalConfig.WebDiscoveryEnabled
		case "13": fmt.Print("Enter path to web wordlist (blank for default): "); fileInput, _ := reader.ReadString('\n'); globalConfig.WebWordlistFile = strings.TrimSpace(fileInput)
		case "14": fmt.Print("Enter sniff interface ('list' to see options): "); ifaceInput, _ := reader.ReadString('\n'); ifaceInput = strings.TrimSpace(ifaceInput)
			if strings.ToLower(ifaceInput) == "list" { listNetworkInterfaces(); fmt.Print("Enter interface name: "); ifaceInput2, _ := reader.ReadString('\n'); globalConfig.SniffInterface = strings.TrimSpace(ifaceInput2) } else { globalConfig.SniffInterface = ifaceInput }
		case "15": fmt.Print("Enter sniff duration (s, 0=inf): "); durStr, _ := reader.ReadString('\n'); dur, err := strconv.Atoi(strings.TrimSpace(durStr)); if err == nil && dur >= 0 { globalConfig.SniffDuration = dur } else { fmt.Println("Invalid duration.") }
		case "16": fmt.Print("Enter BPF filter (blank for none): "); globalConfig.SniffBPFFilter, _ = reader.ReadString('\n'); globalConfig.SniffBPFFilter = strings.TrimSpace(globalConfig.SniffBPFFilter)
		case "17": fmt.Print("Enter PCAP output file (blank for no save): "); globalConfig.SniffPcapFile, _ = reader.ReadString('\n'); globalConfig.SniffPcapFile = strings.TrimSpace(globalConfig.SniffPcapFile)
		case "18": listNetworkInterfaces()
		case "P": if globalConfig.SniffInterface == "" { fmt.Println("Sniffing interface not set."); continue }; runLiveSniffer(globalConfig.SniffInterface, globalConfig.SniffDuration, globalConfig.SniffBPFFilter, globalConfig.SniffPcapFile)
		case "19": fmt.Print("Enter output file prefix: "); globalConfig.OutputFile, _ = reader.ReadString('\n'); globalConfig.OutputFile = strings.TrimSpace(globalConfig.OutputFile)
		case "20": fmt.Print("Enter output format (text, json, html): "); formatInput, _ := reader.ReadString('\n'); formatInput = strings.TrimSpace(strings.ToLower(formatInput))
			if formatInput=="text"||formatInput=="json"||formatInput=="html" { globalConfig.OutputFormat = formatInput } else { fmt.Println("Invalid format."); globalConfig.OutputFormat = "text" }
		case "21": fmt.Print("Enter Nmap threads: "); threadsStr, _ := reader.ReadString('\n'); threads, err := strconv.Atoi(strings.TrimSpace(threadsStr)); if err == nil && threads > 0 { globalConfig.Threads = threads } else { fmt.Println("Invalid thread count.") }
		case "22": fmt.Print("Enter probe timeout (ms): "); timeoutStr, _ := reader.ReadString('\n'); timeout, err := strconv.Atoi(strings.TrimSpace(timeoutStr)); if err == nil && timeout > 0 { globalConfig.Timeout = timeout } else { fmt.Println("Invalid timeout.") }
		case "23": globalConfig.Verbose = !globalConfig.Verbose
		case "24": if saveConfiguration(globalConfig, configFilePath) { fmt.Println("Config saved.") }
		case "25": if loadConfiguration(&globalConfig, configFilePath) { fmt.Println("Config loaded.") }
		case "26": globalConfig.SaveConfigOnExit = !globalConfig.SaveConfigOnExit
		case "S": processScanRequest()
		case "Q": if globalConfig.SaveConfigOnExit { if saveConfiguration(globalConfig, configFilePath) { fmt.Println("Config saved.") } }; fmt.Println("Exiting r3cond0g."); return
		default: fmt.Println("Invalid choice.")
		}
	}
}

func configurePorts(reader *bufio.Reader) {
	fmt.Println("Select port option:")
	fmt.Println("   a. Specify ports (e.g., 80,443,1-100)")
	fmt.Println("   b. Scan common ports (uses internal list: " + commonPortsList + ")")
	fmt.Println("   c. Scan all ports (1-65535)")
	fmt.Println("   d. Nmap default (top 1000 ports - clear other settings)")
	fmt.Print("Enter your choice: ")
	portChoice, _ := reader.ReadString('\n')
	portChoice = strings.TrimSpace(strings.ToLower(portChoice))
	switch portChoice {
	case "a": fmt.Print("Enter port specification: "); globalConfig.Ports, _ = reader.ReadString('\n'); globalConfig.Ports = strings.TrimSpace(globalConfig.Ports); globalConfig.CommonPorts = false; globalConfig.AllPorts = false
	case "b": globalConfig.Ports = ""; globalConfig.CommonPorts = true; globalConfig.AllPorts = false; fmt.Println("Common ports selected.")
	case "c": globalConfig.Ports = ""; globalConfig.CommonPorts = false; globalConfig.AllPorts = true; fmt.Println("All ports selected.")
	case "d": globalConfig.Ports = ""; globalConfig.CommonPorts = false; globalConfig.AllPorts = false; fmt.Println("Nmap default ports selected.")
	default: fmt.Println("Invalid choice. Port settings unchanged.")
	}
}

func getCurrentSetting(setting string, defaultVal string) string { if setting == "" { return defaultVal }; return setting }
func getCurrentPortSetting() string {
	if globalConfig.AllPorts { return "All Ports (1-65535)" }
	if globalConfig.CommonPorts { return "Common Ports (Internal List)" }
	if globalConfig.Ports != "" { return globalConfig.Ports }
	return "Nmap Default (Top 1000)"
}
func boolToString(b bool) string { if b { return "Enabled" }; return "Disabled" }

func loadTargetsFromFile(filename string) ([]string, error) {
	var targets []string
	file, err := os.Open(filename)
	if err != nil { return nil, err }
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		target := strings.TrimSpace(scanner.Text())
		if target != "" && !strings.HasPrefix(target, "#") { targets = append(targets, target) }
	}
	return targets, scanner.Err()
}

func saveConfiguration(config Config, filePath string) bool {
	if filePath == "" { fmt.Println("Error: Config file path not set."); return false }
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil { fmt.Printf("Error marshalling config: %s\n", err); return false }
	dir := filepath.Dir(filePath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0750); err != nil { fmt.Printf("Error creating config dir %s: %s\n", dir, err); return false }
	}
	err = os.WriteFile(filePath, data, 0640)
	if err != nil { fmt.Printf("Error writing config to %s: %s\n", filePath, err); return false }
	return true
}

func loadConfiguration(config *Config, filePath string) bool {
	if filePath == "" { return false }
	if _, err := os.Stat(filePath); os.IsNotExist(err) { return false }
	data, err := os.ReadFile(filePath)
	if err != nil { fmt.Printf("Error reading config from %s: %s. Using defaults.\n", filePath, err); return false }
	err = json.Unmarshal(data, config)
	if err != nil { fmt.Printf("Error unmarshalling config from %s: %s. Using defaults.\n", filePath, err); return false }
	fmt.Println("Configuration loaded from", filePath)
	return true
}

func processScanRequest() {
	var targetsToScan []string
	if globalConfig.TargetFile != "" {
		fileTargets, err := loadTargetsFromFile(globalConfig.TargetFile)
		if err != nil { fmt.Printf("Error loading targets from file '%s': %s\n", globalConfig.TargetFile, err); return }
		targetsToScan = append(targetsToScan, fileTargets...)
	} else if globalConfig.Targets != "" {
		targetsToScan = strings.Split(globalConfig.Targets, ",")
		for i := range targetsToScan { targetsToScan[i] = strings.TrimSpace(targetsToScan[i]) }
	}
	if len(targetsToScan) == 0 { fmt.Println("No targets specified."); return }
	fmt.Printf("Targets to scan: %v\n", targetsToScan)
	results := runScansConcurrently(globalConfig, targetsToScan)
	displayScanResults(results)
	if globalConfig.OutputFile != "" { saveScanResults(results, globalConfig.OutputFile, globalConfig.OutputFormat) }
}

func runScansConcurrently(config Config, targets []string) []ScanResult {
	fmt.Println("\n=== Starting Scan ==="); var allResults []ScanResult; var wg sync.WaitGroup; var mutex sync.Mutex
	ctx, cancel := context.WithCancel(context.Background()); defer cancel()
	sem := make(chan struct{}, config.Threads)

	for _, target := range targets {
		if target == "" { continue }
		wg.Add(1); sem <- struct{}{}
		go func(currentTarget string, currentConfig Config, parentCtx context.Context) {
			defer wg.Done(); defer func() { <-sem }()
			opCtx, opCancel := context.WithTimeout(parentCtx, time.Duration(currentConfig.Timeout*20)*time.Millisecond)
			defer opCancel()

			var targetNmapResults []ScanResult; var rustscanPorts []string
			nmapAvailable := isCommandAvailable("nmap"); rustscanAvailable := isCommandAvailable("rustscan")
			if !nmapAvailable { fmt.Printf("Nmap not found for %s.\n", currentTarget); return }
			currentConfig.Targets = currentTarget

			if currentConfig.UseRustScan && rustscanAvailable {
				if currentConfig.Verbose { fmt.Printf("[%s] Rustscan phase...\n", currentTarget) }
				discoveredPorts := runRustScan(opCtx, currentConfig)
				if len(discoveredPorts) > 0 {
					rustscanPorts = discoveredPorts
					if currentConfig.Verbose { fmt.Printf("[%s] Rustscan found: %s. Nmap detail phase...\n", currentTarget, strings.Join(rustscanPorts, ",")) }
					nmapConfig := currentConfig; nmapConfig.Ports = strings.Join(rustscanPorts, ","); nmapConfig.CommonPorts=false; nmapConfig.AllPorts=false
					targetNmapResults = runNmapScan(opCtx, nmapConfig)
				} else if currentConfig.Verbose { fmt.Printf("[%s] Rustscan: no open ports found.\n", currentTarget) }
			} else {
				if currentConfig.UseRustScan && !rustscanAvailable { fmt.Printf("[%s] Warning: Rustscan selected but not found. Using Nmap for all phases.\n", currentTarget) }
				if currentConfig.Verbose { fmt.Printf("[%s] Nmap direct scan phase...\n", currentTarget) }
				targetNmapResults = runNmapScan(opCtx, currentConfig)
			}

			processedNmapResults := make([]ScanResult, len(targetNmapResults))
			for i, nmapResult := range targetNmapResults {
				processedResult := nmapResult
				processedResult.RustscanInitialPorts = rustscanPorts
				if currentConfig.BannerGrab && len(processedResult.Ports) > 0 {
					if currentConfig.Verbose { fmt.Printf("[%s] Banner grabbing phase...\n", processedResult.IP) }
					processedResult.Banners = grabBannersNative(processedResult.IP, processedResult.Ports, currentConfig.Timeout)
				}
				if currentConfig.VulnInsightScan && len(processedResult.Ports) > 0 {
					if currentConfig.Verbose { fmt.Printf("[%s] Vulnerability insights phase...\n", processedResult.IP) }
					processedResult.PotentialVulns = checkVulnerabilityInsights(processedResult.Ports)
				}
				if currentConfig.WebDiscoveryEnabled && len(processedResult.Ports) > 0 {
					if currentConfig.Verbose { fmt.Printf("[%s] Web discovery phase...\n", processedResult.IP) }
					processedResult.WebDiscoveryResults = runWebDiscoveryForHost(opCtx, processedResult, currentConfig)
				}
				processedNmapResults[i] = processedResult
			}
			mutex.Lock(); allResults = append(allResults, processedNmapResults...); mutex.Unlock()
		}(target, config, ctx)
	}
	wg.Wait(); close(sem)
	fmt.Println("\n=== All Scans Completed ===")
	return allResults
}

func isCommandAvailable(cmdName string) bool { return exec.Command("sh", "-c", "command -v "+cmdName).Run() == nil }

func runRustScan(ctx context.Context, config Config) []string {
	args := []string{"-a", config.Targets, "--ulimit", "5000", "--timeout", strconv.Itoa(config.Timeout), "--no-config", "--accessible"}
	if config.AllPorts { args = append(args, "-p", allPortsRange)
	} else if config.CommonPorts { args = append(args, "-p", commonPortsList)
	} else if config.Ports != "" { args = append(args, "-p", config.Ports)
	} else { args = append(args, "-p", "1-1000") }
	if config.Verbose { fmt.Printf("[%s] Rustscan command: rustscan %s\n", config.Targets, strings.Join(args, " ")) }

	cmd := exec.CommandContext(ctx, "rustscan", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil { fmt.Printf("[%s] Rustscan context error: %v\n", config.Targets, ctx.Err()); return []string{} }
		if exitErr, ok := err.(*exec.ExitError); ok && (exitErr.ExitCode() == 0 || exitErr.ExitCode() == 1) { /* Non-fatal */ } else {
			fmt.Printf("[%s] Error running Rustscan: %s\nOutput: %s\n", config.Targets, err, string(output)); return []string{}
		}
	}
	return parseRustScanOutputImproved(string(output), config.Verbose)
}

func parseRustScanOutputImproved(output string, verbose bool) []string {
    var openPorts []string; seenPorts := make(map[string]bool)
    re := regexp.MustCompile(`(?:Open\s+[\w.-]+:|\[✓\]\s*|Discovered\s+open\s+port\s+)(\d+)(?:/(?:tcp|udp))?`)
    lines := strings.Split(output, "\n");
    for _, line := range lines {
        matches := re.FindStringSubmatch(line)
        if len(matches) > 1 {
            portStr := matches[1]
            if _, err := strconv.Atoi(portStr); err == nil { if !seenPorts[portStr] { openPorts = append(openPorts, portStr); seenPorts[portStr] = true } }
        }
    }
    if verbose && len(openPorts) > 0 { fmt.Printf("Parsed Rustscan ports: %v\n", openPorts) }
    return openPorts
}

func runNmapScan(ctx context.Context, config Config) []ScanResult {
	tmpFile, err := os.CreateTemp("", AppName+"_nmap_*.xml"); if err != nil { fmt.Printf("[%s] Temp Nmap XML err: %s\n", config.Targets, err); return []ScanResult{} }
	defer os.Remove(tmpFile.Name()); tmpFile.Close()
	args := []string{"-oX", tmpFile.Name()}
	scanTypeArg := ""; switch strings.ToUpper(config.ScanType) {
	case "SYN": scanTypeArg = "-sS"; case "CONNECT": scanTypeArg = "-sT"; case "TCP": scanTypeArg = "-sT"; case "UDP": scanTypeArg = "-sU"; case "NULL": scanTypeArg = "-sN"; case "FIN": scanTypeArg = "-sF"; case "XMAS": scanTypeArg = "-sX"
	case "AGGRESSIVE": args = append(args, "-A"); config.ServiceScan,config.OsScan,config.ScriptScan = false,false,false
	case "COMPREHENSIVE": scanTypeArg = "-sS"; args = append(args, "-sV", "-O", "--script=default", "--version-intensity", "7"); config.ServiceScan,config.OsScan,config.ScriptScan = false,false,false
	default: scanTypeArg = "-sS"
	}
	if scanTypeArg != "" { args = append(args, scanTypeArg) }
	if config.AllPorts { args = append(args, "-p-")
	} else if config.CommonPorts { args = append(args, "-p", commonPortsList)
	} else if config.Ports != "" { args = append(args, "-p", config.Ports) }
	if config.ServiceScan { args = append(args, "-sV", "--version-intensity", "5") }
	if config.OsScan { args = append(args, "-O"); if strings.ToUpper(config.ScanType) == "UDP" { args = append(args, "--osscan-limit") } }
	if config.ScriptScan { args = append(args, "--script=default") }
	args = append(args, "-T"+strconv.Itoa(min(max(1, config.Threads/2), 5)))
	args = append(args, "--host-timeout", strconv.Itoa(config.Timeout*10)+"ms")
	if config.Verbose { args = append(args, "-v") }
	if config.CustomNmapArgs != "" { customArgs := strings.Fields(config.CustomNmapArgs); args = append(args, customArgs...) }
	args = append(args, config.Targets)

	if config.Verbose { fmt.Printf("[%s] Nmap command: nmap %s\n", config.Targets, strings.Join(args, " ")) }
	cmd := exec.CommandContext(ctx, "nmap", args...); var stdoutStderr strings.Builder; cmd.Stdout = &stdoutStderr; cmd.Stderr = &stdoutStderr
	err = cmd.Run()
	if err != nil {
		if ctx.Err() != nil { fmt.Printf("[%s] Nmap context error: %v\n", config.Targets, ctx.Err()); return []ScanResult{} }
		fmt.Printf("[%s] Nmap run err: %s\nNmap output:\n%s\n", config.Targets, err, stdoutStderr.String()); return []ScanResult{}
	}
	if config.Verbose { fmt.Printf("[%s] Nmap completed. Parsing XML output from %s\n", config.Targets, tmpFile.Name()) }
	parsedResults, parseErr := parseNmapXML(tmpFile.Name()); if parseErr != nil { fmt.Printf("[%s] Nmap XML parse err: %s\n", config.Targets, parseErr); return []ScanResult{} }
	return parsedResults
}

func parseNmapXML(xmlFilePath string) ([]ScanResult, error) {
	xmlFile, err := os.Open(xmlFilePath); if err != nil { return nil, fmt.Errorf("failed to open nmap xml output file '%s': %w", xmlFilePath, err) }
	defer xmlFile.Close()
	byteValue, _ := io.ReadAll(xmlFile); if len(byteValue) == 0 { return nil, fmt.Errorf("nmap xml output file '%s' is empty", xmlFilePath) }
	var nmapRun NmapRun; if err := xml.Unmarshal(byteValue, &nmapRun); err != nil { return nil, fmt.Errorf("failed to unmarshal nmap xml from '%s' (Nmap might have failed or produced invalid XML - first 200 bytes: %s): %w", xmlFilePath, string(byteValue[:min(200, len(byteValue))]), err) }
	var results []ScanResult
	for _, host := range nmapRun.Hosts {
		if host.Status.State != "up" { if globalConfig.Verbose {fmt.Printf("Skipping host %s, state: %s\n", host.Address.Addr, host.Status.State)}; continue }
		var sr ScanResult; sr.IP = host.Address.Addr
		if len(host.Hostnames) > 0 && host.Hostnames[0].Name != "" { sr.Hostname = host.Hostnames[0].Name } else { addrs, lookupErr := net.LookupAddr(sr.IP); if lookupErr == nil && len(addrs) > 0 { sr.Hostname = strings.TrimSuffix(addrs[0], ".") } }
		if len(host.OS.OsMatches) > 0 {
			bestOS := ""; highestAccuracy := -1
			for _, osMatch := range host.OS.OsMatches {
				acc, _ := strconv.Atoi(osMatch.Accuracy)
				if acc > highestAccuracy { highestAccuracy = acc; bestOS = osMatch.Name; if len(osMatch.OSClasses) > 0 && osMatch.OSClasses[0].OSFamily != "" { bestOS += fmt.Sprintf(" (Family: %s, Gen: %s)", osMatch.OSClasses[0].OSFamily, osMatch.OSClasses[0].OSGen)}}}
			sr.OS = bestOS
		}
		for _, port := range host.Ports.Ports {
			portID, _ := strconv.Atoi(port.PortID); pi := PortInfo{Port:portID, Protocol:port.Protocol, State:port.State.State, Service:port.Service.Name, Version:port.Service.Version}
			if port.Service.Product != "" {
				pi.Service = port.Service.Product
				if port.Service.Version != "" { pi.Version = port.Service.Version }
				if port.Service.Product != "" && port.Service.Version != "" { pi.Version = port.Service.Product + " " + port.Service.Version } else if port.Service.Product != "" { pi.Version = port.Service.Product } else {pi.Version = port.Service.Version}
			}
			if port.Service.ExtraInfo != "" { pi.Version += " (" + strings.TrimSpace(port.Service.ExtraInfo) + ")" }
			sr.Ports = append(sr.Ports, pi)
			for _, script := range port.Scripts { sr.NmapScriptResults += fmt.Sprintf("Port %d/%s - Script: %s:\n%s\n", portID, port.Protocol, script.ID, strings.TrimSpace(script.Output)) }
		}
		results = append(results, sr)
	}
	return results, nil
}

func grabBannersNative(ip string, ports []PortInfo, timeoutMs int) map[int]string {
	banners := make(map[int]string); var wg sync.WaitGroup; var mutex sync.Mutex; timeout := time.Duration(timeoutMs) * time.Millisecond; sem := make(chan struct{}, 10)
	for _, portInfo := range ports {
		if portInfo.Protocol == "tcp" && portInfo.State == "open" {
			wg.Add(1); sem <- struct{}{}
			go func(p PortInfo) {
				defer wg.Done(); defer func() { <-sem }()
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, p.Port), timeout)
				if err == nil {
					defer conn.Close()
					var probe []byte
					if p.Port == 80 || strings.Contains(strings.ToLower(p.Service), "http") { probe = []byte("HEAD / HTTP/1.1\r\nHost: " + ip + "\r\nUser-Agent: "+AppName+"/"+AppVersion+"\r\nConnection: close\r\n\r\n")
					} else if p.Port == 21 || strings.Contains(strings.ToLower(p.Service), "ftp") { /* Usually on connect */
					} else if p.Port == 22 || strings.Contains(strings.ToLower(p.Service), "ssh") { /* Usually on connect */
					} else { probe = []byte("\r\n\r\n") }
					if len(probe)>0 { _, _ = conn.Write(probe) }

					_ = conn.SetReadDeadline(time.Now().Add(timeout)); buffer := make([]byte, 2048);
					n, readErr := conn.Read(buffer)
					if (readErr == nil || readErr == io.EOF) && n > 0 {
						banner := strings.TrimSpace(string(buffer[:n])); banner = regexp.MustCompile(`[^\x20-\x7E\r\n\t]`).ReplaceAllString(banner, "")
						mutex.Lock(); banners[p.Port] = banner; mutex.Unlock()
					}
				}
			}(portInfo)
		}
	}
	wg.Wait(); close(sem); return banners
}

func loadCustomVulnerabilities(filePath string) {
	if filePath == "" { return }
	data, err := os.ReadFile(filePath)
	if err != nil { fmt.Printf("Warning: Could not read custom vuln DB '%s': %s\n", filePath, err); return }
	var loadedDB map[string]map[string]VulnerabilityInsight
	if err := json.Unmarshal(data, &loadedDB); err != nil { fmt.Printf("Warning: Could not parse custom vuln DB '%s': %s\n", filePath, err); return }
	customVulnDB = loadedDB
	fmt.Printf("Successfully loaded %d service entries from custom vulnerability DB: %s\n", len(customVulnDB), filePath)
}

func checkVulnerabilityInsights(ports []PortInfo) []VulnerabilityInsight {
	var insights []VulnerabilityInsight
	mergedDB := make(map[string]map[string]VulnerabilityInsight)
	for service, versions := range internalVulnDB {
		mergedDB[service] = make(map[string]VulnerabilityInsight)
		for ver, insight := range versions { mergedDB[service][ver] = insight }
	}
	for service, versions := range customVulnDB {
		if _, ok := mergedDB[service]; !ok { mergedDB[service] = make(map[string]VulnerabilityInsight) }
		for ver, insight := range versions { insight.Source="custom"; mergedDB[service][ver] = insight }
	}

	for _, p := range ports {
		if p.State != "open" { continue }
		serviceKey := strings.ToLower(p.Service)
		if serviceKey == "microsoft-ds" || serviceKey == "netbios-ssn" { serviceKey = "smb" }
		if strings.Contains(serviceKey, "www") || strings.Contains(serviceKey, "http-proxy") { serviceKey = "http" }

		versionKey := strings.TrimSpace(p.Version)
		plainServiceKey := strings.ToLower(p.Service) // For cases where product name is more specific than generic key

		// Check against mergedDB using potentially normalized serviceKey
		if serviceVulns, ok := mergedDB[serviceKey]; ok {
			foundMatch := false
			if insight, vok := serviceVulns[versionKey]; vok { // Exact version match
				iCopy := insight; iCopy.Port = p.Port; iCopy.ServiceName = p.Service; iCopy.Version = p.Version
				insights = append(insights, iCopy); foundMatch = true
			}
			if !foundMatch { // Wildcard for normalized service
				if insight, wildOk := serviceVulns["*"]; wildOk {
					iCopy := insight; iCopy.Port = p.Port; iCopy.ServiceName = p.Service; iCopy.Version = p.Version
					insights = append(insights, iCopy); foundMatch = true
				}
			}
		}
		// Also check against plain service name if different and not already matched
		if serviceKey != plainServiceKey {
			if serviceVulnsPlain, okPlain := mergedDB[plainServiceKey]; okPlain {
				foundMatchPlain := false
				if insight, vokPlain := serviceVulnsPlain[versionKey]; vokPlain { // Exact version match
					// Avoid duplicate if already added by normalized key (simple check by port and insight text)
					isDup := false; for _, ex := range insights { if ex.Port == p.Port && ex.Insight == insight.Insight {isDup=true; break}}
					if !isDup { iCopy := insight; iCopy.Port = p.Port; iCopy.ServiceName = p.Service; iCopy.Version = p.Version; insights = append(insights, iCopy); foundMatchPlain = true }
				}
				if !foundMatchPlain { // Wildcard for plain service
					if insight, wildOkPlain := serviceVulnsPlain["*"]; wildOkPlain {
						isDup := false; for _, ex := range insights { if ex.Port == p.Port && ex.Insight == insight.Insight {isDup=true; break}}
						if !isDup { iCopy := insight; iCopy.Port = p.Port; iCopy.ServiceName = p.Service; iCopy.Version = p.Version; insights = append(insights, iCopy)}
					}
				}
			}
		}
	}
	return insights
}

func runWebDiscoveryForHost(ctx context.Context, hostResult ScanResult, config Config) []WebDiscoveryResult {
	var discoveryResults []WebDiscoveryResult; var wordlist []string
	if config.WebWordlistFile != "" {
		fileData, err := os.ReadFile(config.WebWordlistFile)
		if err != nil { fmt.Printf("[%s] Warn: Web wordlist '%s' read error: %s. Using internal.\n", hostResult.IP, config.WebWordlistFile, err); wordlist = defaultWebWordlist
		} else { var cleanList []string; for _, item := range strings.Split(string(fileData), "\n") { item = strings.TrimSpace(item); if item != "" && !strings.HasPrefix(item, "#") { cleanList = append(cleanList, item) } }; wordlist = cleanList }
	} else { wordlist = defaultWebWordlist }
	if len(wordlist) == 0 { return discoveryResults }

	httpClient := &http.Client{ Timeout: time.Duration(config.Timeout) * time.Millisecond, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	var wg sync.WaitGroup; var mutex sync.Mutex; webSem := make(chan struct{}, min(config.Threads, 5))

	for _, portInfo := range hostResult.Ports {
		if portInfo.State == "open" && (strings.Contains(portInfo.Service, "http") || portInfo.Port == 80 || portInfo.Port == 443 || portInfo.Port == 8080 || portInfo.Port == 8443) {
			scheme := "http"; if strings.Contains(portInfo.Service, "https") || portInfo.Port == 443 || portInfo.Port == 8443 { scheme = "https" }
			baseURL := fmt.Sprintf("%s://%s:%d", scheme, hostResult.IP, portInfo.Port)
			if globalConfig.Verbose { fmt.Printf("[%s] Starting web discovery for base: %s\n", hostResult.IP, baseURL)}

			for _, path := range wordlist {
				select { case <-ctx.Done(): if config.Verbose { fmt.Printf("[%s] Web discovery ctx done for %s\n", hostResult.IP, baseURL+path)}; return discoveryResults; default: }
				wg.Add(1); webSem <- struct{}{}
				go func(targetPath string) {
					defer wg.Done(); defer func() { <-webSem }()
					var res WebDiscoveryResult; targetURL := baseURL + targetPath; res.URL = targetURL
					if config.Verbose { fmt.Printf("[%s] Web probing: %s\n", hostResult.IP, targetURL) }
					req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil); if err != nil { return }
					req.Header.Set("User-Agent", AppName+"/"+AppVersion)
					resp, err := httpClient.Do(req)
					if err != nil { if ctx.Err() != nil {} else if config.Verbose { fmt.Printf("[%s] Web req err %s: %v\n", hostResult.IP, targetURL, err)}; return }
					defer resp.Body.Close()
					res.StatusCode = resp.StatusCode; res.Length = resp.ContentLength
					if (res.StatusCode >= 200 && res.StatusCode < 300) {
						res.Found = true
						bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024)); titleRegex := regexp.MustCompile(`(?ims)<title[^>]*>(.*?)</title>`)
						matches := titleRegex.FindStringSubmatch(string(bodyBytes)); if len(matches) > 1 { res.Title = strings.TrimSpace(matches[1]) }
					} else if (res.StatusCode >= 300 && res.StatusCode < 400) { res.Found = true; res.Title = "Redirect: " + resp.Header.Get("Location")
					} else if res.StatusCode == 401 || res.StatusCode == 403 { res.Found = true; res.Title = http.StatusText(res.StatusCode) }
					if res.Found { mutex.Lock(); discoveryResults = append(discoveryResults, res); mutex.Unlock() }
				}(path)
			}
		}
	}
	wg.Wait(); close(webSem)
	return discoveryResults
}

func runLiveSniffer(ifaceName string, durationSec int, bpfFilter string, pcapFile string) {
	fmt.Printf("\n--- Starting Live Packet Sniffing on %s ---\n", ifaceName)
	if durationSec > 0 { fmt.Printf("Duration: %d seconds\n", durationSec) } else { fmt.Println("Duration: Indefinite (Ctrl+C to stop)") }
	if bpfFilter != "" { fmt.Printf("BPF Filter: %s\n", bpfFilter) } else { fmt.Println("BPF Filter: None") }
	if pcapFile != "" { fmt.Printf("Saving to PCAP: %s\n", pcapFile) } else { fmt.Println("Saving to PCAP: No")}

	summary := SnifferRunSummary{ Interface: ifaceName, Filter: bpfFilter, PcapFile: pcapFile, TCPSummary: make(map[string]int), UDPSummary: make(map[string]int), StartTime: time.Now()}
	handle, err := pcap.OpenLive(ifaceName, 1600, true, pcap.BlockForever); if err != nil { log.Printf("Error opening interface %s: %v. Try with sudo/admin.", ifaceName, err); summary.Errors = append(summary.Errors, err.Error()); displaySnifferSummary(summary); return }
	defer handle.Close()
	if bpfFilter != "" { if err := handle.SetBPFFilter(bpfFilter); err != nil { log.Printf("Error BPF filter '%s': %v", bpfFilter, err); summary.Errors = append(summary.Errors, "BPF Err: "+err.Error()) }}

	var pcapWriter *pcapgo.Writer; var outFile *os.File
	if pcapFile != "" {
		outFile, err = os.Create(pcapFile); if err != nil { log.Printf("Err PCAP create %s: %v", pcapFile, err); summary.Errors = append(summary.Errors, "PCAP Create Err: "+err.Error())
		} else { pcapWriter = pcapgo.NewWriter(outFile); if err := pcapWriter.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil { log.Printf("Err PCAP header %s: %v", pcapFile, err); summary.Errors = append(summary.Errors, "PCAP Header Err: "+err.Error()); outFile.Close(); pcapWriter = nil }}}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType()); packets := packetSource.Packets()
	sigChan := make(chan os.Signal, 1); signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	ctx, cancelSniffing := context.WithCancel(context.Background())
	if durationSec > 0 { ctx, _ = context.WithTimeout(ctx, time.Duration(durationSec)*time.Second) }
	defer cancelSniffing()
	fmt.Println("Listening for packets... (Press Ctrl+C to stop)");
	loop:
	for { select {
		case packet, ok := <-packets: if !ok || packet == nil { fmt.Println("Packet source closed."); break loop }; summary.PacketsSeen++
			if pcapWriter != nil { if err := pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil { summary.Errors = append(summary.Errors, "PCAP Write Err"); pcapWriter = nil; outFile.Close() }} // Stop trying on error
			processPacketForSummary(&summary, packet)
		case <-sigChan: fmt.Println("\nInterrupted. Stopping sniffer..."); break loop
		case <-ctx.Done(): if durationSec > 0 { fmt.Println("\nSniffing duration reached.") } else { fmt.Println("\nSniffing context done.") }; break loop
	}}
	summary.EndTime = time.Now(); if outFile != nil { outFile.Close() }; displaySnifferSummary(summary)
}

func processPacketForSummary(summary *SnifferRunSummary, packet gopacket.Packet) {
	if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ipv4 := ip4Layer.(*layers.IPv4)
		flowKeySrc := ipv4.SrcIP.String()
		flowKeyDst := ipv4.DstIP.String()

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			flowKey := fmt.Sprintf("%s:%s -> %s:%s", flowKeySrc, tcp.SrcPort, flowKeyDst, tcp.DstPort)
			summary.TCPSummary[flowKey]++
			payload := tcp.Payload
			if len(payload) > 0 {
				payloadStr := string(payload)
				if tcp.DstPort == 21 || tcp.SrcPort == 21 { if len(summary.FTPSummary) < 20 { summary.FTPSummary = append(summary.FTPSummary, strings.TrimSpace(payloadStr)) }}
				else if tcp.DstPort == 23 || tcp.SrcPort == 23 { if len(summary.TelnetSummary) < 10 { summary.TelnetSummary = append(summary.TelnetSummary, strings.TrimSpace(payloadStr)) }}
				else if tcp.DstPort == 80 || tcp.SrcPort == 80 { if (strings.HasPrefix(payloadStr, "GET ") || strings.HasPrefix(payloadStr, "POST ")) && len(summary.HTTPSummary) < 20 { lines := strings.Split(payloadStr, "\r\n"); if len(lines)>0 { summary.HTTPSummary = append(summary.HTTPSummary, lines[0]) }}}}
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			flowKey := fmt.Sprintf("%s:%s -> %s:%s", flowKeySrc, udp.SrcPort, flowKeyDst, udp.DstPort)
			summary.UDPSummary[flowKey]++
			if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
				dns, _ := dnsLayer.(*layers.DNS)
				if len(summary.DNSSummary) < 50 { for _, q := range dns.Questions { summary.DNSSummary = append(summary.DNSSummary, fmt.Sprintf("Q: %s %s", q.Name, q.Type)) }}}
		}
	}
}

func displaySnifferSummary(summary SnifferRunSummary) {
	fmt.Println("\n--- Sniffer Summary ---")
	fmt.Printf("Interface:     %s\n", summary.Interface); fmt.Printf("BPF Filter:    %s\n", getCurrentSetting(summary.Filter, "None"))
	fmt.Printf("Start Time:    %s\n", summary.StartTime.Format(time.RFC1123)); fmt.Printf("End Time:      %s\n", summary.EndTime.Format(time.RFC1123))
	fmt.Printf("Duration:      %s\n", summary.EndTime.Sub(summary.StartTime).Round(time.Second)); fmt.Printf("Packets Seen:  %d\n", summary.PacketsSeen)
	if summary.PcapFile != "" { if fi, err := os.Stat(summary.PcapFile); err == nil { fmt.Printf("PCAP Saved:    %s (Size: %.2f KB)\n", summary.PcapFile, float64(fi.Size())/1024) } else { fmt.Printf("PCAP File:     %s (Save Error/Not Found)\n", summary.PcapFile) }}

	displayTopNFlowsHelper := func(title string, flowMap map[string]int) {
		if len(flowMap) > 0 {
			fmt.Printf("\n%s (Top 5 by count):\n", title)
			type kv struct{ Key string; Value int }
			var ss []kv
			for k, v := range flowMap { ss = append(ss, kv{k, v}) }
			sort.Slice(ss, func(i, j int) bool { return ss[i].Value > ss[j].Value }) // Sort
			count := 0
			for _, sData := range ss {
				if count < 5 { fmt.Printf("  %s: %d packets\n", sData.Key, sData.Value); count++ } else { break }
			}
		}
	}
	displayTopNFlowsHelper("TCP Flows (SrcIP:SrcPort -> DstIP:DstPort)", summary.TCPSummary)
	displayTopNFlowsHelper("UDP Flows (SrcIP:SrcPort -> DstIP:DstPort)", summary.UDPSummary)

	if len(summary.HTTPSummary) > 0 { fmt.Println("\nHTTP Requests (Sample):"); for i,s := range summary.HTTPSummary { if i < 5 {fmt.Printf("  %s\n", s)}} }
	if len(summary.DNSSummary) > 0 { fmt.Println("\nDNS Queries (Sample):"); for i,s := range summary.DNSSummary { if i < 5 {fmt.Printf("  %s\n", s)}} }
	if len(summary.FTPSummary) > 0 { fmt.Println("\nFTP Payloads (Sample Snippets):"); for i,s := range summary.FTPSummary { if i < 3 {fmt.Printf("  %s\n", string([]byte(s)[:min(60, len(s))]))}} }
	if len(summary.TelnetSummary) > 0 { fmt.Println("\nTelnet Payloads (Sample Snippets):"); for i,s := range summary.TelnetSummary { if i < 3 {fmt.Printf("  %s\n", string([]byte(s)[:min(60, len(s))]))}} }
	if len(summary.Errors) > 0 { fmt.Println("\nSniffing Errors:"); for _, e := range summary.Errors { fmt.Printf("  - %s\n", e) } }
	fmt.Println("-----------------------")
}


func listNetworkInterfaces() {
	interfaces, err := net.Interfaces(); if err != nil { fmt.Printf("Error listing net interfaces: %s\n", err); return }
	fmt.Println("\n--- Available Network Interfaces ---")
	for _, iface := range interfaces {
		flags := iface.Flags.String(); if !strings.Contains(flags, "up") { flags += " (Interface Down)" }
		fmt.Printf("Name: %-15s HW Address: %-20s Flags: %s MTU: %d\n", iface.Name, iface.HardwareAddr, flags, iface.MTU)
		addrs, _ := iface.Addrs()
		for _, addr := range addrs { fmt.Printf("  L-- Address: %s\n", addr.String()) }
	}
	fmt.Println("----------------------------------")
}

func displayScanResults(results []ScanResult) {
	if len(results) == 0 { fmt.Println("No scan results to display (no hosts were up or matched criteria)."); return }
	fmt.Printf("\n=== Scan Results (%d hosts processed) ===\n", len(results))
	for _, result := range results {
		fmt.Println("\n===================================="); fmt.Printf("Host: %s", result.IP); if result.Hostname != "" { fmt.Printf(" (%s)", result.Hostname) }; fmt.Println()
		if result.OS != "" { fmt.Printf("OS Guess: %s\n", result.OS) }
		if len(result.RustscanInitialPorts) > 0 { fmt.Printf("Rustscan Initial Ports: %s\n", strings.Join(result.RustscanInitialPorts, ", ")) }
		if len(result.Ports) > 0 {
			fmt.Println("--- Open Ports & Services ---"); fmt.Println("PORT     STATE  SERVICE                  VERSION & BANNER"); fmt.Println("-------- ------ ------------------------ --------------------------------------------------")
			for _, port := range result.Ports {
				if port.State == "open" {
					serviceDisplay := port.Service; if len(serviceDisplay) > 22 { serviceDisplay = serviceDisplay[:22] + "..." }
					versionDisplay := port.Version
					if banner, ok := result.Banners[port.Port]; ok && banner != "" { bannerPreview := strings.ReplaceAll(strings.ReplaceAll(banner, "\n", " "), "\r", ""); if len(bannerPreview) > 40 { bannerPreview = bannerPreview[:37] + "..." }; versionDisplay += " | Banner: " + bannerPreview }
					if len(versionDisplay) > 48 { versionDisplay = versionDisplay[:45] + "..." }
					fmt.Printf("%-7d  %-5s  %-24s %s\n", port.Port, port.Protocol, serviceDisplay, versionDisplay)
				}
			}
		} else { fmt.Println("No open ports found on this host by Nmap scan phase.") }
		if len(result.WebDiscoveryResults) > 0 {
			fmt.Println("\n--- Web Discovery ---")
			for _, webRes := range result.WebDiscoveryResults { titlePreview := webRes.Title; if len(titlePreview) > 50 { titlePreview = titlePreview[:47]+"..."}; fmt.Printf("  [%d] %s (Title: %s, Length: %d)\n", webRes.StatusCode, webRes.URL, titlePreview, webRes.Length) }
		}
		if len(result.PotentialVulns) > 0 {
			fmt.Println("\n--- Potential Vulnerability Insights ---")
			for _, vuln := range result.PotentialVulns { fmt.Printf("  Port %d (%s %s): [%s] %s (Ref: %s) (Source: %s)\n", vuln.Port, vuln.ServiceName, vuln.Version, vuln.Severity, vuln.Insight, vuln.Reference, vuln.Source) }
		}
		if result.NmapScriptResults != "" { fmt.Println("\n--- Nmap Script Outputs ---"); fmt.Println(strings.TrimSpace(result.NmapScriptResults)) }
		fmt.Println("====================================")
	}
	fmt.Println("\n=== End of Scan Results ===")
}

func saveScanResults(results []ScanResult, filePrefix, format string) {
	if filePrefix == "" { fmt.Println("No output file prefix. Not saving."); return }
	fileName := fmt.Sprintf("%s_%s.%s", filePrefix, time.Now().Format("20060102_150405"), format)
	var dataToWrite []byte; var err error
	switch strings.ToLower(format) {
	case "json": dataToWrite, err = json.MarshalIndent(results, "", "  ")
	case "html":
		htmlTemplate := `<!DOCTYPE html><html><head><title>r3cond0g Scan Report - {{.Timestamp}}</title><style>body{font-family:monospace;margin:15px;background-color:#1a1a1a;color:#e0e0e0;} table{border-collapse:collapse;width:100%;margin-bottom:15px;} th,td{border:1px solid #444;padding:6px;text-align:left;} th{background-color:#333;} .host{background-color:#2a2a2a;padding:12px;margin-top:20px;border:1px solid #555;border-radius:5px;} h1,h2,h3,h4{color:#00c0ff;} a{color:#70d7ff;text-decoration:none;} a:hover{text-decoration:underline;} .vuln-Critical{color:#ff4d4d;font-weight:bold;} .vuln-High{color:#ff8c66;} .vuln-Medium{color:#ffd700;} .vuln-Low{color:#90ee90;} pre{background-color:#222;padding:8px;border-radius:4px;overflow-x:auto;white-space:pre-wrap;word-wrap:break-word;}</style></head><body><h1>r3cond0g Scan Report</h1><p>Generated: {{.Timestamp}} by {{.AppName}} {{.AppVersion}} (Authors: {{.AppAuthors}})</p><h2>Global Config Used:</h2><pre>{{printf "%+v" .Config}}</pre> {{range .Results}} <div class="host"><h3>Host: {{.IP}} {{if .Hostname}}({{.Hostname}}){{end}}</h3> {{if .OS}}<p><strong>OS:</strong> {{.OS}}</p>{{end}} {{if .RustscanInitialPorts}}<p><strong>Rustscan Ports:</strong> {{join .RustscanInitialPorts ", "}}</p>{{end}} {{if .Ports}}<h4>Open Ports & Services:</h4><table><tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Version</th><th>Banner</th></tr> {{range .Ports}}{{if eq .State "open"}}<tr><td>{{.Port}}</td><td>{{.Protocol}}</td><td>{{.State}}</td><td>{{.Service}}</td><td>{{.Version}}</td><td><pre>{{getBanner .Banners .Port}}</pre></td></tr>{{end}}{{end}} </table>{{else}}<p>No open ports found by Nmap.</p>{{end}} {{if .WebDiscoveryResults}}<h4>Web Discovery:</h4><ul> {{range .WebDiscoveryResults}}<li>[{{.StatusCode}}] <a href="{{.URL}}" target="_blank">{{.URL}}</a> (Title: {{.Title}}, Length: {{.Length}})</li>{{end}} </ul>{{end}} {{if .PotentialVulns}}<h4>Potential Vulnerabilities:</h4><ul> {{range .PotentialVulns}}<li>Port {{.Port}} ({{.ServiceName}} {{.Version}}): <strong class="vuln-{{.Severity}}">[{{.Severity}}]</strong> {{.Insight}} (Ref: {{.Reference}}) (Source: {{.Source}})</li>{{end}} </ul>{{end}} {{if .NmapScriptResults}}<h4>Nmap Script Output:</h4><pre>{{.NmapScriptResults}}</pre>{{end}} </div>{{end}}</body></html>`
		tmplFuncs := template.FuncMap{
			"join": strings.Join,
			"getBanner": func(banners map[int]string, port int) string { if banner, ok := banners[port]; ok { return banner }; return ""},
		}
		tmpl, tmplErr := template.New("report").Funcs(tmplFuncs).Parse(htmlTemplate)
		if tmplErr != nil { err = fmt.Errorf("HTML template parse error: %w", tmplErr); break }
		var reportData = struct { Timestamp, AppName, AppVersion, AppAuthors string; Config Config; Results []ScanResult }{
			Timestamp: time.Now().Format(time.RFC1123), AppName: AppName, AppVersion: AppVersion, AppAuthors: AppAuthors, Config: globalConfig, Results: results,
		}
		var buf strings.Builder; if tmplErr = tmpl.Execute(&buf, reportData); tmplErr != nil { err = fmt.Errorf("HTML template execute error: %w", tmplErr); break }
		dataToWrite = []byte(buf.String())
	case "text": fallthrough
	default:
		var sb strings.Builder; sb.WriteString(fmt.Sprintf("r3cond0g Scan Results - %s\nAuthors: %s\nVersion: %s\nGlobal Config Used: %+v\n\n", time.Now().Format(time.RFC1123), AppAuthors, AppVersion, globalConfig))
		for _, result := range results {
			sb.WriteString("====================================\n"); sb.WriteString(fmt.Sprintf("Host: %s", result.IP)); if result.Hostname != "" { sb.WriteString(fmt.Sprintf(" (%s)", result.Hostname)) }; sb.WriteString("\n")
			if result.OS != "" { sb.WriteString(fmt.Sprintf("OS: %s\n", result.OS)) }
			if len(result.RustscanInitialPorts) > 0 { sb.WriteString(fmt.Sprintf("Rustscan Ports: %s\n", strings.Join(result.RustscanInitialPorts, ", "))) }
			if len(result.Ports) > 0 {
				sb.WriteString("Open Ports:\n  PORT\tPROTO\tSTATE\tSERVICE\t\t\tVERSION & BANNER\n")
				for _, port := range result.Ports { if port.State == "open" { bannerTxt:=""; if b,ok := result.Banners[port.Port];ok{bannerTxt=strings.ReplaceAll(b,"\n","\\n")}; sb.WriteString(fmt.Sprintf("  %d\t%s\t%s\t%-20s\t%s\n", port.Port, port.Protocol, port.State, port.Service, port.Version + " | " + bannerTxt))}}
			} else { sb.WriteString("No Nmap open ports.\n") }
			if len(result.WebDiscoveryResults) > 0 { sb.WriteString("\nWeb Discovery:\n"); for _, webRes := range result.WebDiscoveryResults { sb.WriteString(fmt.Sprintf("  [%d] %s (Title: %s, Length: %d)\n", webRes.StatusCode, webRes.URL, webRes.Title, webRes.Length)) } }
			if len(result.PotentialVulns) > 0 { sb.WriteString("\nPotential Vulnerabilities:\n"); for _, vuln := range result.PotentialVulns { sb.WriteString(fmt.Sprintf("  Port %d (%s %s): [%s] %s (Ref: %s) (Source: %s)\n", vuln.Port, vuln.ServiceName, vuln.Version, vuln.Severity, vuln.Insight, vuln.Reference, vuln.Source)) } }
			if result.NmapScriptResults != "" { sb.WriteString("\nNmap Script Outputs:\n" + result.NmapScriptResults + "\n") }
			sb.WriteString("\n")
		}
		dataToWrite = []byte(sb.String())
	}
	if err != nil { fmt.Printf("Error preparing output data for %s: %s\n", fileName, err); return }
	err = os.WriteFile(fileName, dataToWrite, 0644)
	if err != nil { fmt.Printf("Error writing results to %s: %s\n", fileName, err); return }
	fmt.Printf("Results saved to %s\n", fileName)
}

func min(a, b int) int { if a < b { return a }; return b }
func max(a, b int) int { if a > b { return a }; return b }
