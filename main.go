package main

import (
	"bufio"
	"bytes" // For ARP command output
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
	"os/exec" // For ARP command
	"regexp"
	"runtime" // For OS-specific ARP command
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// VERSION is the current version of the tool
const VERSION = "0.2.3 ReconRaptor" // User requested version
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
	EnableMACLookup  bool   `json:"enable_mac_lookup"`
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
	MACAddress      string        `json:"mac_address,omitempty"`
	MACVendor       string        `json:"mac_vendor,omitempty"`
}

// NmapRun represents the root XML structure
type NmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []NmapHost `xml:"host"`
}

// NmapHost represents a host in nmap results
type NmapHost struct {
	Addresses []NmapAddress `xml:"address"`
	Ports     NmapPorts   `xml:"ports"`
	Status    NmapStatus  `xml:"status"`
}

// NmapAddress represents host address
type NmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr,omitempty"`
}

// NmapStatus for host liveness
type NmapStatus struct {
	State string `xml:"state,attr"`
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

var ouiData = map[string]string{
	// Cisco
	"00:00:0C": "Cisco Systems, Inc", "00:01:42": "Cisco Systems, Inc", "00:01:43": "Cisco Systems, Inc",
	"00:01:63": "Cisco Systems, Inc", "00:01:96": "Cisco Systems, Inc", "00:01:C7": "Cisco Systems, Inc",
	"00:02:16": "Cisco Systems, Inc", "00:02:4A": "Cisco Systems, Inc", "00:02:4B": "Cisco Systems, Inc",
	"00:02:7E": "Cisco Systems, Inc", "00:02:B9": "Cisco Systems, Inc", "00:02:BA": "Cisco Systems, Inc",
	// Juniper Networks
	"00:05:85": "Juniper Networks, Inc", "00:10:DB": "Juniper Networks, Inc", "00:14:F6": "Juniper Networks, Inc",
	"20:93:39": "Juniper Networks, Inc", "24:5D:92": "Juniper Networks, Inc", "40:36:B7": "Juniper Networks, Inc",
	"68:ED:57": "Juniper Networks, Inc", "74:29:72": "Juniper Networks, Inc", "84:52:34": "Juniper Networks, Inc",
	"BC:0F:FE": "Juniper Networks, Inc", "C0:DF:ED": "Juniper Networks, Inc", "D0:81:C5": "Juniper Networks, Inc",
	"E4:5E:CC": "Juniper Networks, Inc",
	// HP Enterprise / Aruba Networks
	"00:0B:86": "Hewlett Packard Enterprise", "00:14:38": "Hewlett Packard Enterprise", "00:1A:1E": "Hewlett Packard Enterprise",
	"00:24:D7": "Aruba Networks (HPE)", "10:E7:C6": "Hewlett Packard Enterprise", "80:CE:62": "Hewlett Packard Enterprise",
	"9C:7B:EF": "Hewlett Packard Enterprise", "B8:AF:67": "Hewlett Packard Enterprise",
	// Dell Networking / Dell Inc.
	"00:06:5B": "Dell Inc.", "00:0B:DB": "Dell Inc.", "00:16:F0": "Dell Inc.", "00:26:B9": "Dell Inc.",
	"64:B9:4E": "Dell Inc.", "A8:3C:A5": "Dell Inc.", "D0:46:0C": "Dell Inc.", "E8:CF:83": "Dell Inc.",
	"DC:A6:32": "Dell Inc.",
	// Broadcom
	"00:0A:F7": "Broadcom Corporation", "00:10:18": "Broadcom Corporation", "00:1B:E9": "Broadcom Corporation",
	"00:22:19": "Broadcom Corporation", "00:26:0B": "Broadcom Corporation", "00:62:0B": "Broadcom Limited",
	"14:23:F3": "Broadcom Limited", "BC:97:E1": "Broadcom Limited",
	// Arista Networks
	"00:1C:73": "Arista Networks, Inc", "18:9C:E1": "Arista Networks, Inc", "28:99:3A": "Arista Networks, Inc",
	"44:4C:A8": "Arista Networks", "74:1C:B3": "Arista Networks", "D4:63:C6": "Arista Networks",
	// Ubiquiti Networks
	"00:15:6D": "Ubiquiti Inc", "00:27:22": "Ubiquiti Inc", "04:18:D6": "Ubiquiti Networks Inc.",
	"18:66:DA": "Ubiquiti Networks Inc.", "24:A4:3C": "Ubiquiti Networks Inc.",
	// MikroTik (Routerboard/MikroTikls SIA)
	"00:0C:42": "Routerboard/MikroTikls SIA", "04:F4:1C": "Routerboard/MikroTikls SIA", "4C:5E:0C": "MikroTikls SIA",
	"64:D1:54": "MikroTikls SIA", "D4:CA:6D": "MikroTikls SIA", "E4:8D:8C": "MikroTikls SIA",
	// Fortinet
	"00:09:0F": "Fortinet Inc", "00:1A:A0": "Fortinet Inc.", "00:1E:C9": "Fortinet Inc.",
	"00:74:78": "Fortinet Inc", "08:5B:0E": "Fortinet Inc.",
	// Palo Alto Networks
	"00:1B:17": "Palo Alto Networks", "00:30:07": "Palo Alto Networks", "60:15:2B": "Palo Alto Networks",
	// Netgear
	"00:09:5B": "NETGEAR, Inc", "00:0F:B5": "NETGEAR, Inc", "00:14:6C": "NETGEAR", "00:18:4D": "NETGEAR",
	"00:1B:2F": "NETGEAR", "00:1F:33": "NETGEAR",
	// D-Link
	"00:05:5F": "D-Link Corporation", "00:0D:88": "D-Link Corporation", "00:13:46": "D-Link Corporation",
	"00:15:E9": "D-Link Corporation", "00:17:9A": "D-Link Corporation",
	// Linksys (Cisco-Linksys LLC / Belkin)
	"00:03:2F": "Linksys", "00:06:25": "Linksys", "00:0C:41": "Cisco-Linksys LLC",
	"00:0F:66": "Cisco-Linksys LLC", "00:12:17": "Linksys",
	// Intel Corporation
	"00:02:B3": "Intel Corporation", "00:03:47": "Intel Corporation", "00:04:23": "Intel Corporation",
	"00:07:E9": "Intel Corporation", "00:0D:60": "Intel Corporation", "00:AA:00": "Intel Corporation",
	// Realtek Semiconductor Corp.
	"00:E0:4C": "REALTEK SEMICONDUCTOR CORP.", "10:EC:81": "Realtek Semiconductor Corp.", "14:58:D0": "Realtek Semiconductor Corp.",
	"18:C0:4D": "Realtek Semiconductor Corp.", "1C:83:41": "Realtek Semiconductor Corp.",
	// Mellanox Technologies (NVIDIA)
	"00:02:C9": "Mellanox Technologies, Inc.", "00:25:8C": "Mellanox Technologies", "14:02:EC": "Mellanox Technologies",
	"20:4D:52": "Mellanox Technologies, Inc.", "24:B6:FD": "Mellanox Technologies", "3C:A8:2A": "Mellanox Technologies",
	// Marvell (QLogic Corp)
	"00:0E:1E": "QLogic Corp", "00:17:EA": "Marvell Semiconductor", "00:1B:32": "Marvell Semiconductor",
	// IBM Corporation
	"00:02:55": "IBM Corporation", "00:04:AC": "IBM Corporation", "00:09:6B": "IBM Corporation",
	"00:11:25": "IBM Corporation", "00:21:5E": "IBM Corporation",
	// Supermicro Computer, Inc.
	"00:25:90": "Super Micro Computer, Inc.", "0C:C4:7A": "Super Micro Computer, Inc.", "3C:52:82": "Supermicro Computer, Inc.",
	"74:27:EA": "Supermicro Computer, Inc.", "D0:50:99": "Supermicro Computer, Inc.",
	// VMware, Inc.
	"00:05:69": "VMware, Inc.", "00:0C:29": "VMware, Inc.", "00:50:56": "VMware, Inc.",
	// Microsoft Corporation (Hyper-V, Surface, Xbox)
	"00:03:FF": "Microsoft Corporation", "00:12:5A": "Microsoft Corporation", "00:15:5D": "Microsoft Corporation",
	"00:17:FA": "Microsoft Corporation", "00:1D:D8": "Microsoft Corporation",
	// XenSource, Inc. (Citrix XenServer)
	"00:16:3E": "XenSource, Inc.",
	// Apple, Inc.
	"00:03:93": "Apple, Inc.", "00:05:02": "Apple, Inc.", "00:0A:95": "Apple, Inc.", "00:0D:93": "Apple, Inc.",
	"00:11:24": "Apple, Inc.", "00:14:51": "Apple, Inc.", "F8:E4:3B": "Apple, Inc.",
	// Samsung Electronics Co., Ltd
	"00:07:AB": "Samsung Electronics Co.,Ltd", "00:12:FB": "Samsung Electronics Co.,Ltd", "00:16:32": "Samsung Electronics Co.,Ltd",
	"00:16:6B": "Samsung Electronics Co.,Ltd", "00:16:6C": "Samsung Electronics Co.,Ltd",
	// Lenovo
	"00:01:64": "Lenovo Mobile Communication Technology Ltd.", "00:0F:20": "Lenovo", "00:18:F3": "Lenovo",
	"00:21:5C": "Lenovo", "00:23:18": "Lenovo",
	// ASUSTek COMPUTER INC.
	"00:01:80": "ASUSTek COMPUTER INC.", "00:0C:6E": "ASUSTek COMPUTER INC.", "00:11:2F": "ASUSTek COMPUTER INC.",
	"00:13:D4": "ASUSTek COMPUTER INC.", "00:15:F2": "ASUSTek COMPUTER INC.", "00:1B:FC": "ASUSTek COMPUTER INC.",
	"BC:FC:E7": "ASUSTek COMPUTER INC.",
	// Acer Incorporated
	"00:01:24": "Acer Incorporated", "00:0A:5E": "Acer Incorporated", "00:11:5C": "Acer Incorporated",
	"00:12:A9": "Acer Incorporated", "00:13:74": "Acer Incorporated",
	// Google, Inc.
	"3C:5A:B4": "Google, Inc.", "94:EB:2C": "Google, Inc.", "A4:77:33": "Google, Inc.",
	"F4:F5:D8": "Google, Inc.", "F4:F5:E8": "Google, Inc.",
	// Raspberry Pi Foundation / Trading Ltd
	"B8:27:EB": "Raspberry Pi Foundation", "2C:54:91": "Raspberry Pi Foundation", "3A:35:41": "Raspberry Pi Trading Ltd",
	// Espressif Inc.
	"24:0A:C4": "Espressif Inc.", "24:B2:DE": "Espressif Inc.", "30:AE:A4": "Espressif Inc.",
	"54:5A:A6": "Espressif Inc.", "60:01:94": "Espressif Inc.", "DC:06:75": "Espressif Inc.",
	"DC:1E:D5": "Espressif Inc.",
	// Particle Industries, Inc.
	"6C:0B:84": "Particle Industries, Inc.",
	// Texas Instruments
	"00:12:4B": "Texas Instruments", "00:18:30": "Texas Instruments", "00:1A:B6": "Texas Instruments",
	"00:1D:E1": "Texas Instruments", "04:E3:1E": "Texas Instruments", "14:9C:EF": "Texas Instruments",
	// HP (Printers)
	"00:01:E6": "Hewlett-Packard", "00:0E:7F": "Hewlett-Packard", "00:11:0A": "Hewlett-Packard",
	"3C:D9:2B": "Hewlett Packard",
	// Brother Industries, Ltd.
	"00:1B:A9": "Brother Industries, Ltd.", "00:1E:A3": "Brother Industries, Ltd.", "00:26:0C": "Brother Industries, Ltd.",
	"00:80:77": "Brother Industries, Ltd.", "00:80:92": "Brother Industries, Ltd.", "30:05:5C": "Brother Industries, Ltd.",
	// Canon Inc.
	"00:00:85": "Canon Inc.", "00:1E:8F": "Canon Inc.", "00:27:0C": "Canon Inc.", "00:B0:C7": "Canon Inc.",
	"28:68:D0": "Canon Inc.", "40:F8:DF": "Canon Inc.",
	// Epson (Seiko Epson Corp.)
	"00:00:48": "Seiko Epson Corp.", "00:26:AB": "Seiko Epson Corp.", "08:00:46": "Seiko Epson Corp.",
	"40:26:19": "Seiko Epson Corp.", "50:57:9C": "Seiko Epson Corp.", "64:16:66": "Seiko Epson Corp.",
	// Xerox Corporation
	"00:00:01": "XEROX Corporation", "00:00:AA": "XEROX Corporation",
	"00:02:03": "XEROX Corporation", "00:04:05": "XEROX Corporation", "00:06:07": "XEROX Corporation",
	"9C:93:4E": "XEROX Corporation",
	// Ricoh Company, Ltd.
	"00:00:74": "Ricoh Company, Ltd.", "00:00:E2": "Ricoh Company, Ltd.", "00:09:2D": "Ricoh Company, Ltd.",
	"00:0D:72": "Ricoh Company, Ltd.", "00:1C:5A": "Ricoh Company, Ltd.", "00:26:5D": "Ricoh Company, Ltd.",
	"58:38:79": "Ricoh Company, Ltd.",
	// Polycom Inc. (HP)
	"00:04:F2": "Polycom, Inc.", "64:16:7F": "Polycom, Inc.",
	// Yealink Network Technology
	"00:15:65": "Xiamen Yealink Network Technology Co., Ltd.", "24:9A:D8": "Xiamen Yealink Network Technology Co., Ltd.",
	"80:5E:0C": "Xiamen Yealink Network Technology Co., Ltd.", "88:D7:F6": "Xiamen Yealink Network Technology Co., Ltd.",
	// Grandstream Networks, Inc.
	"00:0B:82": "Grandstream Networks, Inc.", "C0:74:AD": "Grandstream Networks, Inc.", "EC:74:D7": "Grandstream Networks, Inc.",
	// Avaya Inc.
	"00:04:0D": "Avaya Inc.", "00:09:6E": "Avaya Inc.", "00:1B:4F": "Avaya Inc.", "00:22:64": "Avaya Inc.",
	"00:25:64": "Avaya Inc.", "10:CD:AE": "Avaya Inc.",
	// Sony Interactive Entertainment Inc. (PlayStation)
	"00:01:4A": "Sony Interactive Entertainment Inc.", "00:04:1F": "Sony Interactive Entertainment Inc.", "00:0D:BD": "Sony Interactive Entertainment Inc.",
	"00:13:A9": "Sony Interactive Entertainment Inc.", "00:15:C1": "Sony Interactive Entertainment Inc.", "5C:96:66": "Sony Interactive Entertainment Inc.",
	// Nintendo Co., Ltd.
	"00:09:BF": "Nintendo Co., Ltd.", "00:16:56": "Nintendo Co., Ltd.", "00:17:AB": "Nintendo Co., Ltd.",
	"00:19:1D": "Nintendo Co., Ltd.", "00:1B:EA": "Nintendo Co., Ltd.", "00:1F:32": "Nintendo Co., Ltd.",
	// Additional common ones
	"00:1A:11": "ASRock Incorporation", "BC:5F:F4": "ASRock Incorporation",
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
		EnableMACLookup:  false,
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
		"http":          {"apache", "httpd"}, "https": {"apache", "httpd"}, "ssh": {"openssh", "openssh"},
		"ftp":           {"proftpd", "proftpd"}, "mysql": {"oracle", "mysql"}, "dns": {"isc", "bind"},
		"smtp":          {"postfix", "postfix"}, "redis": {"redis", "redis"}, "rdp": {"microsoft", "remote_desktop_services"},
		"ms-wbt-server": {"microsoft", "remote_desktop_services"}, "microsoft-ds": {"microsoft", "windows"},
		"netbios-ssn":   {"microsoft", "windows"}, "winrm": {"microsoft", "windows_remote_management"},
		"snmp":          {"net-snmp", "net-snmp"},
	}
)

func main() {
	printBanner()
	loadConfigFromEnv()
	parseCommandLineFlags()
	loadCustomCVEs()

	// Direct Action Logic
	runDirectly := false
	if (config.TargetHost != "" || config.TargetFile != "") && config.PortRange != "" {
		if config.NmapResultsFile == "" || (config.NmapResultsFile != "" && (config.TargetHost != "" || config.TargetFile != "")) {
			runDirectly = true // Scan action
		}
	} else if config.NmapResultsFile != "" && !(config.TargetHost != "" || config.TargetFile != "") {
		runDirectly = true // Nmap parse action
	}

	if runDirectly || isAnyFlagSetBesidesHelp() { // If specific action flags are set
		if (config.TargetHost != "" || config.TargetFile != "") && config.PortRange != "" {
			// Scan action
			fmt.Println("ℹ️  Target and ports provided, attempting direct scan...")
			if validateConfig() {
				results = runUltraFastScan()
				if config.VulnMapping && len(results) > 0 { performVulnerabilityMapping() }
				if config.TopologyMapping && len(results) > 0 { generateTopologyMap() }
				if len(results) > 0 { displayResults(); saveResults()
				} else { fmt.Println("ℹ️  Direct scan completed. No open ports matching criteria found on live hosts.") }
			} else { fmt.Println("❌ Direct scan aborted due to invalid configuration.") }
		} else if config.NmapResultsFile != "" {
			// Nmap parse action
			fmt.Printf("ℹ️  Nmap results file '%s' provided, attempting direct parse...\n", config.NmapResultsFile)
			parseNmapResults()
			if len(results) > 0 {
				saveResults()
				if config.VulnMapping { // Automatically try vuln mapping if enabled
					fmt.Println("ℹ️  Attempting vulnerability mapping on parsed Nmap results...")
					performVulnerabilityMapping()
				}
			}
		}
		fmt.Println("👋 Exiting ReconRaptor v" + VERSION)
		return
	}

	// Interactive Menu Loop
	for {
		showMenu()
		choice := getUserChoice()
		switch choice {
		case 1: if validateConfig() { results = runUltraFastScan() } else { fmt.Println("❌ Scan aborted.") }
		case 2: configureSettings()
		case 3: displayResults()
		case 4: saveResults()
		case 5: parseNmapResults()
		case 6: performVulnerabilityMapping()
		case 7: generateTopologyMap()
		case 8: exportResults()
		case 9: performIPSweepAndSave()
		case 10: fmt.Println("👋 Exiting ReconRaptor v" + VERSION); return
		case 11: cidr := askForString("🔍 Enter CIDR/Target to debug parsing: "); debugCIDRParsing(cidr)
		default: fmt.Println("❌ Invalid option.")
		}
	}
}

func isAnyFlagSetBesidesHelp() bool {
    anySet := false
    flag.Visit(func(f *flag.Flag) {
		// This logic is a bit tricky because some flags might have default values that match "set"
		// A more robust way is to see if os.Args contains flags beyond the program name.
		// For now, a simple check if any known action-driving flag was explicitly set.
		// This is a simplified check. `flag.NFlag()` could also be used after `flag.Parse()`.
    })
	// A simpler check: if number of actual arguments passed to flag.Parse() is > 0
	if flag.NFlag() > 0 {
		return true
	}
    return anySet
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
	fmt.Println("1. 🚀 Run Ultra-Fast Scan (Ports)")
	fmt.Println("2. 🛠️  Configure Settings")
	fmt.Println("3. 📋 Display Scan Results")
	fmt.Println("4. 💾 Save Scan Results")
	fmt.Println("5. 📄 Parse Nmap XML Results")
	fmt.Println("6. 🔍 Perform Vulnerability Mapping")
	fmt.Println("7. 🌐 Generate Network Topology")
	fmt.Println("8. 📤 Export Scan Results")
	fmt.Println("9. 📡 IP Sweep Only & Save Live Hosts")
	fmt.Println("10. ❌ Exit")
	fmt.Print("Choose an option: ")
}

func getUserChoice() int {
	var choiceStr string; fmt.Scanln(&choiceStr)
	choice, err := strconv.Atoi(choiceStr); if err != nil { return -1 }
	return choice
}

func askForBool(prompt string) bool {
	fmt.Print(prompt); var input string; fmt.Scanln(&input)
	return strings.ToLower(input) == "true" || strings.ToLower(input) == "y"
}

func askForString(prompt string) string {
	fmt.Print(prompt); reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n'); return strings.TrimSpace(input)
}

func configureSettings() {
	for {
		fmt.Println("\n=== ⚙️ Enhanced Settings ===")
		fmt.Printf(" 1. Target Host: %s\n", config.TargetHost)
		fmt.Printf(" 2. Target File: %s\n", config.TargetFile)
		fmt.Printf(" 3. Port Range: %s\n", config.PortRange)
		fmt.Printf(" 4. Scan Timeout (ms): %d\n", config.ScanTimeout)
		fmt.Printf(" 5. Max Concurrency: %d\n", config.MaxConcurrency)
		fmt.Printf(" 6. Output File: %s\n", config.OutputFile)
		fmt.Printf(" 7. UDP Scan: %t\n", config.UDPScan)
		fmt.Printf(" 8. Vulnerability Mapping: %t\n", config.VulnMapping)
		fmt.Printf(" 9. Topology Mapping: %t\n", config.TopologyMapping)
		fmt.Printf("10. NVD API Key: %s\n", maskAPIKey(config.NVDAPIKey))
		fmt.Printf("11. Nmap Results File: %s\n", config.NmapResultsFile)
		fmt.Printf("12. Only Open Ports (Display/Nmap): %t\n", config.OnlyOpenPorts)
		fmt.Printf("13. CVE Plugin File: %s\n", config.CVEPluginFile)
		fmt.Printf("14. Ping Sweep Enabled: %t\n", config.PingSweep)
		fmt.Printf("15. Ping Sweep Ports: %s\n", config.PingSweepPorts)
		fmt.Printf("16. Ping Sweep Timeout (ms): %d\n", config.PingSweepTimeout)
		fmt.Printf("17. MAC Address Lookup (Experimental): %t\n", config.EnableMACLookup)
		fmt.Println(" 0. Back to main menu")
		fmt.Print("⚙️ Choose a setting to edit: ")

		choice := getUserChoice()
		switch choice {
		case 1: config.TargetHost = askForString("🎯 Target Host(s): ")
		case 2: config.TargetFile = askForString("📁 Target File Path: ")
		case 3: config.PortRange = askForString("🔢 Port Range (e.g., 1-1000): ")
		case 4: fmt.Print("⏱️ Scan Timeout (ms): "); fmt.Scanln(&config.ScanTimeout)
		case 5: fmt.Print("🔄 Max Concurrency: "); fmt.Scanln(&config.MaxConcurrency)
		case 6: config.OutputFile = askForString("📄 Output File Name: ")
		case 7: config.UDPScan = askForBool("🛡️ Enable UDP Scan? (true/false): ")
		case 8: config.VulnMapping = askForBool("🔍 Enable Vuln Mapping? (true/false): ")
		case 9: config.TopologyMapping = askForBool("🌐 Enable Topology Mapping? (true/false): ")
		case 10: config.NVDAPIKey = askForString("🔑 NVD API Key: ")
		case 11: config.NmapResultsFile = askForString("📁 Nmap Results File Path: ")
		case 12: config.OnlyOpenPorts = askForBool("🎯 Show Only Open Ports? (true/false): ")
		case 13: config.CVEPluginFile = askForString("📄 CVE Plugin File Path: ")
		case 14: config.PingSweep = askForBool(fmt.Sprintf("📡 Enable TCP Ping Sweep (current: %t)? (true/false): ", config.PingSweep))
		case 15: config.PingSweepPorts = askForString(fmt.Sprintf("🎯 Ping Sweep Ports (current: %s): ", config.PingSweepPorts))
		case 16: fmt.Printf("⏱️ Ping Sweep Timeout (ms) (current: %d): ", config.PingSweepTimeout); fmt.Scanln(&config.PingSweepTimeout)
		case 17: config.EnableMACLookup = askForBool(fmt.Sprintf("🏷️ Enable MAC Lookup (current: %t)? (true/false): ", config.EnableMACLookup))
		case 0: return
		default: fmt.Println("❌ Invalid choice.")
		}
	}
}

func maskAPIKey(key string) string {
	if len(key) == 0 { return "Not set" }
	if len(key) <= 8 { return strings.Repeat("*", len(key)) }
	return key[:4] + strings.Repeat("*", len(key)-8) + key[len(key)-4:]
}

func LookupMACVendor(macAddr string) string {
	if macAddr == "" { return "" }
	mac, err := net.ParseMAC(macAddr)
	if err != nil { return "" }
	ouiPrefix := fmt.Sprintf("%02X:%02X:%02X", mac[0], mac[1], mac[2])
	vendor, found := ouiData[strings.ToUpper(ouiPrefix)]
	if found { return vendor }
	return "Unknown Vendor"
}

func AttemptToGetMACAddress(ipAddr string, timeout time.Duration) string {
	var cmd *exec.Cmd
	var arpOutput []byte
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Try to "ping" or connect to the host to populate ARP cache if necessary.
	// This is a heuristic. A proper ARP implementation sends ARP requests.
	// For this shell-out version, we rely on the OS's ARP cache or `arp` command behavior.
	// A very quick TCP dial attempt might help populate it on some OSes if not already there.
	quickDialTimeout := 50 * time.Millisecond
	if timeout < quickDialTimeout { quickDialTimeout = timeout / 2}
	conn, dialErr := net.DialTimeout("tcp", net.JoinHostPort(ipAddr, "80"), quickDialTimeout) // Check a common port
	if dialErr == nil {
		conn.Close()
	} // We don't care about the error here, just an attempt to interact.

	switch runtime.GOOS {
	case "linux", "darwin":
		cmd = exec.CommandContext(ctx, "arp", "-n", ipAddr)
	case "windows":
		cmd = exec.CommandContext(ctx, "arp", "-a", ipAddr)
	default:
		return "" // Unsupported OS for this method
	}

	arpOutput, err = cmd.Output()
	if err != nil {
		// fmt.Printf("Debug: ARP command for %s failed: %v\n", ipAddr, err)
		return ""
	}

	outputStr := string(arpOutput)
	lines := strings.Split(outputStr, "\n")
	macRegex := regexp.MustCompile(`([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Ensure the line pertains to the IP address we're looking for
		// This check might need to be more robust depending on `arp` output variations
		if strings.Contains(line, ipAddr) || (runtime.GOOS == "linux" && strings.Contains(line, fmt.Sprintf("(%s)", ipAddr))) {
			match := macRegex.FindString(line)
			if match != "" {
				normalizedMac := strings.ReplaceAll(match, "-", ":")
				return strings.ToUpper(normalizedMac)
			}
		}
	}
	return ""
}


func parsePortRange(portRangeStr string) []int {
	var ports []int; seen := make(map[int]bool)
	ranges := strings.Split(portRangeStr, ","); for _, r := range ranges {
		r = strings.TrimSpace(r)
		if strings.Contains(r, "-") {
			parts := strings.SplitN(r, "-", 2)
			if len(parts) == 2 {
				start, err1 := strconv.Atoi(strings.TrimSpace(parts[0])); end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
				if err1 == nil && err2 == nil && start > 0 && end > 0 && start <= 65535 && end <= 65535 && start <= end {
					for i := start; i <= end; i++ { if !seen[i] { ports = append(ports, i); seen[i] = true } }
				} else { fmt.Printf("⚠️  Warning: Invalid port range values in '%s'.\n", r) }
			} else { fmt.Printf("⚠️  Warning: Invalid port range format '%s'.\n", r) }
		} else {
			port, err := strconv.Atoi(r)
			if err == nil && port > 0 && port <= 65535 { if !seen[port] { ports = append(ports, port); seen[port] = true }
			} else { fmt.Printf("⚠️  Warning: Invalid port number '%s'.\n", r) }
		}
	}
	return ports
}

func parseTargets(targets string, targetFile string) []string {
	var parsedTargets []string; tempTargets := []string{}
	if targetFile != "" {
		fmt.Printf("📁 Reading targets from file: %s\n", targetFile)
		file, err := os.Open(targetFile)
		if err != nil { fmt.Printf("❌ Error opening target file: %v\n", err)
		} else { defer file.Close(); scanner := bufio.NewScanner(file)
			for scanner.Scan() { line := strings.TrimSpace(scanner.Text()); if line != "" && !strings.HasPrefix(line, "#") { tempTargets = append(tempTargets, line) } }
			if err := scanner.Err(); err != nil { fmt.Printf("❌ Error reading target file: %v\n", err) }
		}
	}
	if targets != "" { parts := strings.Split(targets, ","); for _, part := range parts { trimmedPart := strings.TrimSpace(part); if trimmedPart != "" { tempTargets = append(tempTargets, trimmedPart) } } }
	seen := make(map[string]bool)
	for _, targetEntry := range tempTargets { expanded := parseSingleTarget(targetEntry); for _, t := range expanded { if !seen[t] { parsedTargets = append(parsedTargets, t); seen[t] = true } } }
	if len(parsedTargets) > 0 { fmt.Printf("📊 Total unique targets to process: %d\n", len(parsedTargets)) }
	return parsedTargets
}

func parseSingleTarget(target string) []string {
	target = strings.TrimSpace(target)
	if strings.Contains(target, "/") {
		ip, ipnet, err := net.ParseCIDR(target)
		if err != nil { if parsedIP := net.ParseIP(target); parsedIP != nil { return []string{parsedIP.String()} }; return []string{target} }
		var ips []string
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) { ips = append(ips, ip.String()); if len(ips) >= 131072 { fmt.Printf("⚠️  CIDR %s too large, limiting to %d IPs.\n", target, len(ips)); break } }
		ones, bits := ipnet.Mask.Size()
		// Remove network and broadcast for common IPv4 subnets (not /31 or /32)
		if bits == 32 && ones > 0 && ones < 31 && len(ips) >= 2 { // Check len(ips) >=2 to ensure there's something to remove
			// Check if the first IP is the network address
			if ips[0] == ipnet.IP.Mask(ipnet.Mask).String() {
				ips = ips[1:]
			}
			// Check if the last IP (if list is still not empty) is the broadcast address
			if len(ips) > 0 {
				broadcastIP := make(net.IP, len(ipnet.IP))
				for i := range ipnet.IP { broadcastIP[i] = ipnet.IP[i] | ^ipnet.Mask[i] }
				if ips[len(ips)-1] == broadcastIP.String() {
					ips = ips[:len(ips)-1]
				}
			}
		}
		return ips
	}
	if parsedIP := net.ParseIP(target); parsedIP != nil { return []string{parsedIP.String()} }
	return []string{target}
}

func incIP(ip net.IP) { for j := len(ip) - 1; j >= 0; j-- { ip[j]++; if ip[j] > 0 { break } } }

func isHostAliveTCP(host string, ports []int, timeout time.Duration) bool {
	if len(ports) == 0 { return true } // If no ping ports, assume alive for scan
	var wgHostPing sync.WaitGroup
	aliveChan := make(chan bool, 1) // Buffered channel to signal first success

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Cancel all ongoing dials if one succeeds or all fail

	for _, port := range ports {
		wgHostPing.Add(1)
		go func(p int) {
			defer wgHostPing.Done()
			dialCtx, dialCancel := context.WithTimeout(ctx, timeout) // Use overall context + per-dial timeout
			defer dialCancel()
			
			dialer := net.Dialer{}
			conn, err := dialer.DialContext(dialCtx, "tcp", fmt.Sprintf("%s:%d", host, p))
			if err == nil {
				conn.Close()
				select {
				case aliveChan <- true: // Signal success
				default: // Already signaled
				}
				cancel() // Cancel other pending dials for this host
			}
		}(port)
	}

	// Wait for either a success signal or all goroutines to finish
	go func() {
		wgHostPing.Wait()
		select {
		case aliveChan <- false: // All finished without success
		default: // Success already signaled
		}
	}()
	
	return <-aliveChan
}

func scanTCPPort(host string, port int) *EnhancedScanResult {
	timeout := time.Duration(config.ScanTimeout) * time.Millisecond; start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeout); defer cancel()
	dialer := net.Dialer{}; conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil { return nil }; defer conn.Close()
	result := &EnhancedScanResult{ Host: host, Port: port, Protocol: "tcp", State: "open", ResponseTime: time.Since(start), Timestamp: time.Now().UTC() }
	serviceDetectionTimeout := timeout / 2; if serviceDetectionTimeout < 100*time.Millisecond { serviceDetectionTimeout = 100 * time.Millisecond }
	result.Service, result.Version = detectServiceWithTimeout(conn, port, "tcp", serviceDetectionTimeout)
	result.OSGuess = guessOS(result)
	return result
}

func scanUDPPort(host string, port int) *EnhancedScanResult {
	timeout := time.Duration(config.ScanTimeout) * time.Millisecond; start := time.Now()
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", host, port), timeout); if err != nil { return nil }; defer conn.Close()
	probe := getUDPProbe(port); conn.SetWriteDeadline(time.Now().Add(timeout / 3)); _, err = conn.Write(probe); if err != nil { return nil }
	buffer := make([]byte, 2048); readDeadlineTimeout := timeout / 2; if readDeadlineTimeout < 100*time.Millisecond { readDeadlineTimeout = 100 * time.Millisecond }
	conn.SetReadDeadline(time.Now().Add(readDeadlineTimeout))
	n, err := conn.Read(buffer)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			if isCommonUDPPort(port) {
				result := &EnhancedScanResult{ Host: host, Port: port, Protocol: "udp", State: "open|filtered", ResponseTime: time.Since(start), Timestamp: time.Now().UTC() }
				serviceDetectionTimeout := readDeadlineTimeout / 2; if serviceDetectionTimeout < 50*time.Millisecond { serviceDetectionTimeout = 50 * time.Millisecond }
				result.Service, result.Version = detectServiceWithTimeout(nil, port, "udp", serviceDetectionTimeout)
				result.OSGuess = guessOS(result); return result
			}
		}
		return nil
	}
	if n > 0 {
		result := &EnhancedScanResult{ Host: host, Port: port, Protocol: "udp", State: "open", ResponseTime: time.Since(start), Timestamp: time.Now().UTC() }
		serviceDetectionTimeout := readDeadlineTimeout / 2; if serviceDetectionTimeout < 50*time.Millisecond { serviceDetectionTimeout = 50 * time.Millisecond }
		if port == 161 { 
			result.Service = "snmp"; 
            snmpPayload := string(buffer[:n])
            re := regexp.MustCompile(`(?i)(Linux|Windows|Cisco|Juniper|JUNOS|IOS|FortiOS|PAN-OS)[\s\/\-\_A-Za-z0-9\.\(\)]*`)
            matches := re.FindAllString(snmpPayload, -1)
            if len(matches) > 0 { bestMatch := ""; for _, m := range matches { if len(m) > len(bestMatch) { bestMatch = m } }; result.Version = truncateString(strings.TrimSpace(bestMatch), 100)
            } else { rePrintable := regexp.MustCompile(`[[:print:]]{10,}`); printableMatches := rePrintable.FindAllString(snmpPayload, -1); if len(printableMatches) > 0 { result.Version = truncateString(strings.TrimSpace(printableMatches[0]), 100) } }
		} else if port == 53 && n >= 12 {
			isResponse := (buffer[2]&0x80) != 0; opCode := (buffer[2]>>3)&0x0F; responseCode := buffer[3]&0x0F
			if isResponse && opCode == 0 { result.Service = "dns"; if responseCode == 0 { result.Version = "response NOERROR" } else { result.Version = fmt.Sprintf("response RCODE %d", responseCode) } }
		}
		if result.Service == "" || result.Service == "unknown" { result.Service, result.Version = detectServiceWithTimeout(nil, port, "udp", serviceDetectionTimeout) }
		result.OSGuess = guessOS(result); return result
	}
	return nil
}

type ServiceProbe struct { Name string; Probe []byte; Matcher func([]byte) (string, string) }
var enhancedProbes = map[int]ServiceProbe{
	22: { Name: "SSH", Probe: []byte("SSH-2.0-ReconRaptor\r\n"), Matcher: func(r []byte) (string, string) { rs := string(r); if strings.HasPrefix(rs, "SSH-") { l := strings.SplitN(rs, "\r\n", 2); return "ssh", strings.TrimSpace(l[0]) }; return "ssh", "unknown" } },
	25: { Name: "SMTP", Probe: []byte("EHLO reconraptor.local\r\n"), Matcher: func(r []byte) (string, string) { rs := string(r); if strings.Contains(rs, "220 ") { l := strings.Split(rs, "\r\n"); for _, line := range l { if strings.HasPrefix(line, "220 ") { return "smtp", strings.TrimSpace(strings.TrimPrefix(line, "220 ")) } }; return "smtp", "220 greeting" }; return "smtp", "unknown" } },
}

func extractServerHeader(response string) string { lines := strings.Split(response, "\r\n"); for _, line := range lines { if strings.HasPrefix(strings.ToLower(line), "server:") { return strings.TrimSpace(line[len("Server:"):]) } }; return "" }
type HTTPProbe struct{}
func (p *HTTPProbe) Detect(conn net.Conn) (string, string) {
	conn.SetWriteDeadline(time.Now().Add(1*time.Second)); _, err := conn.Write([]byte("HEAD / HTTP/1.1\r\nHost: reconraptor\r\nUser-Agent: ReconRaptor-Scanner\r\nConnection: close\r\n\r\n")); if err != nil { return "http", "unknown (write_fail)" }
	buffer := make([]byte, 2048); conn.SetReadDeadline(time.Now().Add(2*time.Second)); n, err := conn.Read(buffer)
	if err != nil { if netErr, ok := err.(net.Error); ok && netErr.Timeout() { return "http", "timeout" }; if err == io.EOF && n > 0 { response := string(buffer[:n]); if strings.HasPrefix(response, "HTTP/") { server := extractServerHeader(response); if server != "" { return "http", server }; return "http", "generic HTTP" } }; return "http", "unknown (read_fail)" }
	response := string(buffer[:n]); if strings.HasPrefix(response, "HTTP/") { server := extractServerHeader(response); if server != "" { return "http", server }; return "http", "generic HTTP" }; return "unknown", "non-HTTP on HTTP port"
}

func detectServiceWithTimeout(conn net.Conn, port int, protocol string, timeout time.Duration) (string, string) {
	defaultServices := map[int]string{ 21:"ftp", 22:"ssh", 23:"telnet", 25:"smtp", 53:"dns", 80:"http", 110:"pop3", 139:"netbios-ssn", 143:"imap", 161:"snmp", 389:"ldap", 443:"https", 445:"microsoft-ds", 3306:"mysql", 3389:"ms-wbt-server", 5432:"postgresql", 5900:"vnc", 8080:"http-proxy" }
	detectedService, defaultExists := defaultServices[port]; if !defaultExists { detectedService = "unknown" }; detectedVersion := "unknown"
	if protocol == "tcp" && conn != nil {
		conn.SetDeadline(time.Now().Add(timeout)); defer conn.SetDeadline(time.Time{})
		if probe, exists := enhancedProbes[port]; exists { conn.SetWriteDeadline(time.Now().Add(timeout/2)); if _, err := conn.Write(probe.Probe); err == nil { buffer := make([]byte, 4096); conn.SetReadDeadline(time.Now().Add(timeout/2)); if n, errRead := conn.Read(buffer); errRead == nil && n > 0 { return probe.Matcher(buffer[:n]) } } }
		isHTTPPort := (port==80 || port==8080 || port==8000); isHTTPSPort := (port==443 || port==8443)
		if isHTTPPort { return (&HTTPProbe{}).Detect(conn) }; if isHTTPSPort && detectedService == "https" { return "https", "requires TLS" }
	} else if protocol == "udp" { return detectedService, "unknown (UDP)" }
	return detectedService, detectedVersion
}

func getUDPProbe(port int) []byte {
	switch port {
	case 53: return []byte{ 0xAA,0xBB,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x07,0x65,0x78,0x61,0x6d,0x70,0x6c,0x65,0x03,0x63,0x6f,0x6d,0x00,0x00,0x01,0x00,0x01 }
	case 123: return []byte{0x1B,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
	case 161: return []byte{ 0x30,0x26,0x02,0x01,0x00,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,0x63,0xA0,0x19,0x02,0x04,0x01,0x02,0x03,0x04,0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x0B,0x30,0x09,0x06,0x08,0x2B,0x06,0x01,0x02,0x01,0x01,0x01,0x00,0x05,0x00 } // sysDescr.0
	default: return []byte("ReconRaptorUDP")
	}
}
func isCommonUDPPort(port int) bool { common := []int{53,67,68,69,123,137,138,161,162,500,514,1900,4500,5353}; for _,p:=range common {if p==port{return true}}; return false }

func guessOS(result *EnhancedScanResult) string {
	serviceLower := strings.ToLower(result.Service); versionLower := strings.ToLower(result.Version)
	macVendorLower := strings.ToLower(result.MACVendor)

	// MAC Vendor based hints (often very strong)
	if macVendorLower != "" && macVendorLower != "unknown vendor" {
		if strings.Contains(macVendorLower, "vmware") { return "Virtual Machine (VMware)" }
		if strings.Contains(macVendorLower, "oracle") && (strings.Contains(macVendorLower, "virtualbox") || result.Service == "virtualbox") { return "Virtual Machine (VirtualBox)"}
		if strings.Contains(macVendorLower, "microsoft") && (result.OSGuess == "" || result.OSGuess == "Unknown" || result.OSGuess == "Windows (Port Hint)") { /* Strengthens Windows guess but don't override specific windows version if known */ }
		if strings.Contains(macVendorLower, "apple") { return "Apple Device (macOS/iOS)" }
		if strings.Contains(macVendorLower, "raspberry pi") { return "Linux (Raspberry Pi)" }
		if strings.Contains(macVendorLower, "cisco") { return "Network Device (Cisco)" }
		if strings.Contains(macVendorLower, "juniper") { return "Network Device (Juniper)" }
		if strings.Contains(macVendorLower, "arista") { return "Network Device (Arista)" }
		if strings.Contains(macVendorLower, "dell") && (result.OSGuess == "" || result.OSGuess == "Unknown" || result.OSGuess == "Windows (Port Hint)") { /* Dell Hardware */ }
		if strings.Contains(macVendorLower, "hewlett packard") || strings.Contains(macVendorLower, "hp enterprise") { /* HP Hardware */ }
		// If a strong MAC Vendor hint is found, we can often return it, or use it to refine service-based guesses.
	}
	
	if serviceLower == "snmp" && versionLower != "unknown" && versionLower != "" {
		vl := strings.ToLower(versionLower)
		if strings.Contains(vl, "windows") || strings.Contains(vl, "microsoft") { return "Windows (SNMP)"}
		if strings.Contains(vl, "linux") { return "Linux (SNMP)" }
		if strings.Contains(vl, "cisco ios") || strings.Contains(vl, "cisco adaptive security appliance") || strings.Contains(vl, "cisco nx-os") { return "Cisco IOS/ASA/NX-OS (SNMP)" }
		if strings.Contains(vl, "junos") || strings.Contains(vl, "juniper") { return "Juniper JUNOS (SNMP)" }
		if strings.Contains(vl, "fortios") || strings.Contains(vl, "fortigate") { return "Fortinet FortiOS (SNMP)"}
		if strings.Contains(vl, "pan-os") { return "Palo Alto PAN-OS (SNMP)"}
		if strings.Contains(vl, "routeros") || strings.Contains(vl, "mikrotik") { return "MikroTik RouterOS (SNMP)"}
		if strings.Contains(vl, "esxi") || strings.Contains(vl, "vmware") {return "VMware ESXi (SNMP)"}
		// If SNMP info is descriptive but not caught by specific rules, it could still be better than "Unknown"
		if len(vl) > 5 && (result.OSGuess == "" || result.OSGuess == "Unknown" || result.OSGuess == "Windows (Port Hint)") { return "Device (SNMP: " + truncateString(result.Version, 20) + ")" }
	}
	if strings.Contains(serviceLower, "http") {
		if strings.Contains(versionLower, "iis") || strings.Contains(versionLower, "microsoft-httpapi") { return "Windows" }
		if strings.Contains(versionLower, "apache") { if strings.Contains(versionLower, "win32")||strings.Contains(versionLower,"win64"){return "Windows"}; return "Linux/Unix (Apache)" }
		if strings.Contains(versionLower, "nginx") { return "Linux/Unix (Nginx)" }
	}
	if strings.Contains(serviceLower, "ssh") {
		if strings.Contains(versionLower, "openssh") {
			if strings.Contains(versionLower, "windows") { return "Windows (OpenSSH)"}
			return "Linux/Unix (OpenSSH)"
		}
		if strings.Contains(versionLower, "dropbear") { return "Linux/Embedded (Dropbear)" }
	}
	if serviceLower == "ms-wbt-server" || serviceLower == "rdp" { return "Windows" }
	if serviceLower == "microsoft-ds" || serviceLower == "netbios-ssn" { return "Windows" }
	if serviceLower == "winrm" || strings.Contains(serviceLower, "ws-management") { return "Windows" }
	switch result.Port { case 135,139,445,3389,5985,5986: if result.OSGuess==""||result.OSGuess=="Unknown"{return "Windows (Port Hint)"} }
	
	// Fallback if OSGuess is still empty but MAC vendor gave a clue
	if result.OSGuess == "" || result.OSGuess == "Unknown" {
		if macVendorLower != "" && macVendorLower != "unknown vendor" {
			return "Device (" + result.MACVendor + ")"
		}
	}
	if result.OSGuess != "" && result.OSGuess != "Unknown" { return result.OSGuess } // Keep prior more specific guess if any
	return "Unknown"
}

func queryNVD(cpe string) ([]string, error) {
	if err := limiter.Wait(context.Background()); err != nil { return nil, fmt.Errorf("rate limiter error: %w", err) }
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=%s&resultsPerPage=100", cpe)
	req, err := http.NewRequest("GET", url, nil); if err != nil { return nil, fmt.Errorf("create NVD request: %w", err) }
	req.Header.Set("User-Agent", "ReconRaptor/"+VERSION)
	currentRateLimit := limiter.Limit()
	if config.NVDAPIKey != "" {
		req.Header.Set("apiKey", config.NVDAPIKey)
		if currentRateLimit < 1 { limiter.SetLimit(rate.Every(30*time.Second/50)); limiter.SetBurst(50) }
	} else {
		if currentRateLimit > (rate.Every(30*time.Second/5)+0.01) { limiter.SetLimit(rate.Every(30*time.Second/5)); limiter.SetBurst(5) }
		// fmt.Println("⚠️  No NVD API key. Rate limited.") // Reduce noise, user is warned once.
	}
	var cves []string; maxRetries := 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		resp, err := httpClient.Do(req)
		if err != nil { if attempt == maxRetries-1 { return nil, fmt.Errorf("NVD req failed: %w", err) }; time.Sleep(time.Duration(math.Pow(2,float64(attempt)))*time.Second); continue }
		body, readErr := io.ReadAll(resp.Body); resp.Body.Close(); if readErr != nil { return nil, fmt.Errorf("read NVD body: %w", readErr) }
		if resp.StatusCode == http.StatusOK {
			var nvdResp struct{Vulnerabilities []struct{CVE struct{ID string `json:"id"`} `json:"cve"`} `json:"vulnerabilities"`}
			if err := json.Unmarshal(body, &nvdResp); err != nil { return nil, fmt.Errorf("parse NVD JSON: %w. Body: %s", err, string(body)) }
			for _, vuln := range nvdResp.Vulnerabilities { cves = append(cves, vuln.CVE.ID) }; return cves, nil
		} else if resp.StatusCode == http.StatusNotFound { return []string{}, nil
		} else if resp.StatusCode == http.StatusForbidden { errorMsg:="NVD API forbidden (403)"; if config.NVDAPIKey==""{errorMsg+=" - API key needed."}else{errorMsg+=" - check key/quota."}; return nil, fmt.Errorf("%s Resp: %s", errorMsg, string(body))
		} else if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == 429 {
			retryAfterStr := resp.Header.Get("Retry-After"); waitTime := time.Duration(math.Pow(2,float64(attempt+1)))*time.Second
			if retryAfterSec, errConv := strconv.Atoi(retryAfterStr); errConv == nil { waitTime = time.Duration(retryAfterSec)*time.Second }
			if waitTime > 60*time.Second { waitTime = 60*time.Second }
			fmt.Printf("⏳ NVD API rate limit (%d). Wait %v, retry %d/%d for %s\n", resp.StatusCode, waitTime, attempt+1, maxRetries, cpe)
			time.Sleep(waitTime); if attempt == maxRetries-1 { return nil, fmt.Errorf("NVD rate limit exceeded for %s. Body: %s", cpe, string(body)) }; continue
		} else { if attempt == maxRetries-1 { return nil, fmt.Errorf("NVD API error %d for %s. Body: %s", resp.StatusCode, cpe, string(body)) }; time.Sleep(time.Duration(math.Pow(2,float64(attempt)))*time.Second) }
	}
	return nil, fmt.Errorf("NVD query failed max retries for %s", cpe)
}
func findSimilarKey(key string) string { parts := strings.Fields(strings.ToLower(key)); if len(parts)<1{return ""}; serviceName:=parts[0]; var bestMatch string; highestSimilarity:=-1; for dbKey:=range vulnDB{dbKeyLower:=strings.ToLower(dbKey); dbParts:=strings.Fields(dbKeyLower); if len(dbParts)<1{continue}; dbServiceName:=dbParts[0]; currentSimilarity:=0; if serviceName==dbServiceName{currentSimilarity+=10}; if currentSimilarity>highestSimilarity{highestSimilarity=currentSimilarity; bestMatch=dbKey}}; if highestSimilarity>=10{return bestMatch}; return "" }
func loadCustomCVEs() { if config.CVEPluginFile==""{return}; file,err:=os.Open(config.CVEPluginFile); if err!=nil{fmt.Printf("❌ Error CVE plugin file '%s': %v\n",config.CVEPluginFile,err);return}; defer file.Close(); data,err:=io.ReadAll(file); if err!=nil{fmt.Printf("❌ Error reading CVE plugin '%s': %v\n",config.CVEPluginFile,err);return}; if err:=json.Unmarshal(data,&customCVEs);err!=nil{fmt.Printf("❌ Error parsing CVE plugin JSON '%s': %v\n",config.CVEPluginFile,err);return}; fmt.Printf("✅ Loaded %d custom CVE maps from %s\n",len(customCVEs),config.CVEPluginFile) }

func runUltraFastScan() []EnhancedScanResult {
	fmt.Println("🚀 Starting Network Scan...")
	results = nil; atomic.StoreInt64(&scannedPorts, 0)
	initialHosts := parseTargets(config.TargetHost, config.TargetFile)
	if len(initialHosts) == 0 { fmt.Println("❌ No valid targets."); return nil }
	var liveHosts []string
	if config.PingSweep {
		fmt.Println("🔎 Performing TCP Ping Sweep..."); pingPortsToTry := parsePortRange(config.PingSweepPorts)
		if len(pingPortsToTry) == 0 { fmt.Println("⚠️ No valid ping ports, defaulting."); pingPortsToTry = []int{80,443,22,3389} }
		tcpPingTimeout := time.Duration(config.PingSweepTimeout)*time.Millisecond; if tcpPingTimeout <= 0 { tcpPingTimeout = 300*time.Millisecond }
		var pingWg sync.WaitGroup; var liveHostsMutex sync.Mutex
		pingSemMax := config.MaxConcurrency; if pingSemMax > 200 {pingSemMax=200}; if pingSemMax <= 0 {pingSemMax=50}
		pingSem := make(chan struct{}, pingSemMax)
		fmt.Printf("📡 Pinging %d hosts (ports: %v, timeout: %v, concurrency: %d)...\n", len(initialHosts), pingPortsToTry, tcpPingTimeout, pingSemMax)
		var pingedCountAtomic int64; totalToPing := len(initialHosts)
		pingProgressTicker := time.NewTicker(1*time.Second); var displayMutexPing sync.Mutex; doneSignal := make(chan bool)
		go func(){for{select{case <-pingProgressTicker.C: current:=atomic.LoadInt64(&pingedCountAtomic); if totalToPing==0{continue}; percentage:=float64(current)/float64(totalToPing)*100; liveHostsMutex.Lock();foundLive:=len(liveHosts);liveHostsMutex.Unlock(); displayMutexPing.Lock();fmt.Printf("\r\033[K📡 Ping Sweep: %d/%d (%.1f%%) | Live: %d",current,totalToPing,percentage,foundLive);displayMutexPing.Unlock()
		case <-doneSignal: return}}}()
		for _,host := range initialHosts { pingWg.Add(1); go func(h string){defer pingWg.Done();pingSem<-struct{}{};defer func(){<-pingSem}(); if isHostAliveTCP(h,pingPortsToTry,tcpPingTimeout){liveHostsMutex.Lock();liveHosts=append(liveHosts,h);liveHostsMutex.Unlock()}; atomic.AddInt64(&pingedCountAtomic,1)}(host)}
		pingWg.Wait(); doneSignal<-true; pingProgressTicker.Stop(); time.Sleep(150*time.Millisecond)
		finalLiveCount := len(liveHosts)
		displayMutexPing.Lock(); fmt.Printf("\r\033[K📡 Ping Sweep Complete. Found %d live hosts from %d.\n",finalLiveCount,totalToPing); displayMutexPing.Unlock()
		if finalLiveCount == 0 { fmt.Println("❌ No live hosts from ping sweep. Aborting port scan."); return nil }
	} else { liveHosts = initialHosts }

	hostsToScan := liveHosts; portsToScan := parsePortRange(config.PortRange)
	if len(portsToScan)==0{fmt.Println("❌ No valid ports."); return nil}; if len(hostsToScan)==0{fmt.Println("❌ No hosts."); return nil}
	totalScansPerProtocol := int64(len(hostsToScan)*len(portsToScan)); totalOperations := totalScansPerProtocol; if config.UDPScan{totalOperations*=2}
	fmt.Printf("📊 Port Scanning %d live hosts on %d ports. Total operations: %d\n", len(hostsToScan), len(portsToScan), totalOperations)
	if totalOperations == 0 {fmt.Println("ℹ️ No scan operations."); return nil}
	if totalOperations > 50000 && len(hostsToScan)>10 {fmt.Printf("⚠️ Large scan (%d ops).\n",totalOperations); if !askForBool("Continue? (y/N): "){fmt.Println("❌ Scan cancelled.");return nil}}
	sem = make(chan struct{}, config.MaxConcurrency); startScanTime := time.Now()
	scanProgressTicker := time.NewTicker(1*time.Second); var displayMutexScan sync.Mutex; scanDoneSignal := make(chan bool)
	go func(){for{select{case <-scanProgressTicker.C: current:=atomic.LoadInt64(&scannedPorts); if totalOperations==0{continue}; if current > 0 { percentage:=float64(current)/float64(totalOperations)*100; elapsed:=time.Since(startScanTime);rate:=0.0;if elapsed.Seconds()>0{rate=float64(current)/elapsed.Seconds()}; var eta time.Duration; if rate>0&&current<totalOperations{eta=time.Duration(float64(totalOperations-current)/rate)*time.Second}; mutex.Lock();foundOpenCount:=len(results);mutex.Unlock(); displayMutexScan.Lock();fmt.Printf("\r\033[K🔍 Port Scan: %d/%d (%.1f%%)|Rate: %.0f ops/s|ETA: %v|Found: %d",current,totalOperations,percentage,rate,eta.Round(time.Second),foundOpenCount);displayMutexScan.Unlock()}
	case <-scanDoneSignal: return}}}()
	commonPorts := []int{80,443,21,22,23,25,53,110,135,139,143,445,993,995,1723,3306,3389,5900,5985,8080}; priorityPorts,regularPorts := []int{},[]int{}; portSet:=make(map[int]bool); for _,p:=range portsToScan{portSet[p]=true}; for _,p:=range commonPorts{if portSet[p]{priorityPorts=append(priorityPorts,p);delete(portSet,p)}}; for p:=range portSet{regularPorts=append(regularPorts,p)}; orderedPorts:=append(priorityPorts,regularPorts...)
	for _,host := range hostsToScan { for _,port := range orderedPorts { wg.Add(1); go scanPortWithRecovery(host,port,&displayMutexScan) }}
	wg.Wait(); scanDoneSignal<-true; scanProgressTicker.Stop(); time.Sleep(150*time.Millisecond)
	finalScannedCount:=atomic.LoadInt64(&scannedPorts); if finalScannedCount>totalOperations{finalScannedCount=totalOperations}; mutex.Lock();finalOpenCount:=len(results);mutex.Unlock()
	displayMutexScan.Lock();fmt.Printf("\r\033[K🔍 Port Scan Complete: %d/%d ops. Found %d open.\n",finalScannedCount,totalOperations,finalOpenCount);displayMutexScan.Unlock()
	elapsedScanTime:=time.Since(startScanTime); fmt.Printf("✅ Port scan completed in %v\n",elapsedScanTime.Round(time.Second))
	if totalOperations>0&&elapsedScanTime.Seconds()>0{fmt.Printf("⚡ Avg rate: %.0f ops/s\n",float64(totalOperations)/elapsedScanTime.Seconds())}
	if finalOpenCount>0{serviceCount:=make(map[string]int); for _,res:=range results{if strings.ToLower(res.State)=="open"||strings.Contains(strings.ToLower(res.State),"open|filtered"){serviceKey:=res.Service;if serviceKey==""{serviceKey="unknown_service"};serviceCount[serviceKey]++}}; if len(serviceCount)>0{fmt.Println("🎯 Top services:");for service,count:=range serviceCount{fmt.Printf("    %s: %d\n",service,count)}}}
	return results
}

func validateConfig() bool { fmt.Println("🔧 Validating configuration..."); isValid:=true; if config.TargetHost==""&&config.TargetFile==""{fmt.Println("❌ No target.");isValid=false}; if len(parsePortRange(config.PortRange))==0&&config.NmapResultsFile==""{fmt.Println("❌ No port range.");isValid=false}; if config.TargetFile!=""{if _,err:=os.Stat(config.TargetFile);os.IsNotExist(err){fmt.Printf("❌ Target file missing: %s\n",config.TargetFile);isValid=false}}; if config.ScanTimeout<50||config.ScanTimeout>10000{fmt.Println("⚠️ Scan timeout recommend 50-10000ms.")}; if config.MaxConcurrency<1||config.MaxConcurrency>10000{fmt.Println("⚠️ Max concurrency recommend 1-10000.")}; if config.PingSweep{if len(parsePortRange(config.PingSweepPorts))==0{fmt.Println("❌ Ping sweep enabled, no ping ports.");isValid=false};if config.PingSweepTimeout<=0{fmt.Println("❌ Ping sweep enabled, invalid timeout.");isValid=false}}; if config.VulnMapping&&config.NVDAPIKey==""{fmt.Println("⚠️ Vuln mapping on, NVD API key missing.")}; if isValid{fmt.Println("✅ Config OK.")}else{fmt.Println("❌ Config validation failed.")}; return isValid }
func debugCIDRParsing(cidr string) { fmt.Printf("🔍 Debug Parse: '%s'\n",cidr);ips:=parseSingleTarget(cidr);fmt.Printf("📊 IPs: %d\n",len(ips));dc:=len(ips);if dc>20{dc=20};for i:=0;i<dc;i++{fmt.Printf("  %d: %s\n",i+1,ips[i])};if len(ips)>20{fmt.Printf("  ... %d more\n",len(ips)-20)}}
func parseNmapResults() { if config.NmapResultsFile==""{config.NmapResultsFile=askForString("📁 Nmap XML path: ");if config.NmapResultsFile==""{fmt.Println("❌ No Nmap file.");return}};file,err:=os.Open(config.NmapResultsFile);if err!=nil{fmt.Printf("❌ Error Nmap file '%s': %v\n",config.NmapResultsFile,err);return};defer file.Close();data,err:=io.ReadAll(file);if err!=nil{fmt.Printf("❌ Error reading Nmap file '%s': %v\n",config.NmapResultsFile,err);return};var nmapRun NmapRun;if err:=xml.Unmarshal(data,&nmapRun);err!=nil{fmt.Printf("❌ Error parsing Nmap XML '%s': %v\n",config.NmapResultsFile,err);return};newResults:=[]EnhancedScanResult{};parsedCount:=0;for _,host:=range nmapRun.Hosts{var hostIP,hostMAC,macVendor string;for _,addr:=range host.Addresses{if addr.AddrType=="ipv4"{hostIP=addr.Addr};if addr.AddrType=="ipv6"&&hostIP==""{hostIP=addr.Addr};if addr.AddrType=="mac"{hostMAC=addr.Addr;if addr.Vendor!=""{macVendor=addr.Vendor}}};if hostIP==""{continue};for _,port:=range host.Ports.Ports{isConsideredOpen:=strings.ToLower(port.State.State)=="open"||(port.Protocol=="udp"&&strings.Contains(strings.ToLower(port.State.State),"open|filtered"));if !config.OnlyOpenPorts||isConsideredOpen{result:=EnhancedScanResult{Host:hostIP,Port:port.PortID,Protocol:port.Protocol,State:port.State.State,Service:port.Service.Name,Version:strings.TrimSpace(port.Service.Version),Timestamp:time.Now().UTC()};result.OSGuess=guessOS(&result);if hostMAC!=""{result.MACAddress=strings.ToUpper(hostMAC);if macVendor!=""{result.MACVendor=macVendor}else{result.MACVendor=LookupMACVendor(result.MACAddress)}};newResults=append(newResults,result);parsedCount++}}};results=newResults;fmt.Printf("✅ Parsed %d ports from %s ('OnlyOpen': %t)\n",parsedCount,config.NmapResultsFile,config.OnlyOpenPorts);if len(results)>0{displayResults();if config.VulnMapping{if askForBool("🔍 Vuln map Nmap results? (y/N): "){performVulnerabilityMapping()}}}else{fmt.Println("ℹ️ No ports matched from Nmap file.")}}
func mapVulnerabilities(result *EnhancedScanResult) { if !config.VulnMapping{return};serviceKey:=strings.ToLower(strings.TrimSpace(result.Service));versionKey:=strings.TrimSpace(result.Version);productKey:=fmt.Sprintf("%s %s",result.Service,result.Version);if cves,found:=customCVEs[productKey];found{result.Vulnerabilities=cves;return};lowerServiceProductKey:=fmt.Sprintf("%s %s",serviceKey,versionKey);if cves,found:=customCVEs[lowerServiceProductKey];found{result.Vulnerabilities=cves;return};if versionKey==""||versionKey=="unknown"||serviceKey=="unknown"||serviceKey==""{result.Vulnerabilities=[]string{"Version/Service unknown - NVD skip"};return};cpeInfo,cpeMapExists:=serviceToCPE[serviceKey];if !cpeMapExists{if strings.Contains(serviceKey,"apache")&&(strings.Contains(serviceKey,"httpd")||serviceKey=="http"||serviceKey=="https"){cpeInfo=struct{Vendor,Product string}{"apache","http_server"}}else if strings.Contains(serviceKey,"openssh"){cpeInfo=struct{Vendor,Product string}{"openssh","openssh"}}else if strings.Contains(serviceKey,"nginx"){cpeInfo=struct{Vendor,Product string}{"nginx","nginx"}}else if strings.Contains(serviceKey,"mysql"){cpeInfo=struct{Vendor,Product string}{"oracle","mysql"}}else{result.Vulnerabilities=[]string{fmt.Sprintf("Service '%s' not in CPE map",result.Service)};return}};cpeVersion:=versionKey;if strings.HasPrefix(strings.ToLower(versionKey),cpeInfo.Product+" "){cpeVersion=strings.TrimPrefix(strings.ToLower(versionKey),cpeInfo.Product+" ")};if idx:=strings.Index(cpeVersion," ");idx!=-1{cpeVersion=cpeVersion[:idx]};if idx:=strings.Index(cpeVersion,"(");idx!=-1{cpeVersion=cpeVersion[:idx]};cpeString:=fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*",cpeInfo.Vendor,cpeInfo.Product,strings.ToLower(cpeVersion));nvdCacheKey:=cpeString;if cachedVulns,found:=nvdCache.Load(nvdCacheKey);found{if cvs,ok:=cachedVulns.([]string);ok{result.Vulnerabilities=cvs;return}};nvdCVEs,err:=queryNVD(cpeString);if err!=nil{result.Vulnerabilities=[]string{fmt.Sprintf("NVD lookup error: %s",err.Error())};nvdCache.Store(nvdCacheKey,result.Vulnerabilities);return};nvdCache.Store(nvdCacheKey,nvdCVEs);if len(nvdCVEs)>0{result.Vulnerabilities=nvdCVEs}else{fuzzyKey:=fmt.Sprintf("%s %s",result.Service,versionKey);if similar:=findSimilarKey(fuzzyKey);similar!=""{if localCVEs,found:=vulnDB[similar];found{result.Vulnerabilities=append([]string{"(Local DB Match):"},localCVEs...);return}};result.Vulnerabilities=[]string{"No known vulnerabilities found (NVD/Local)"}}}
func performVulnerabilityMapping() { if len(results)==0{fmt.Println("❌ No results for vuln map.");return};if !config.VulnMapping{fmt.Println("ℹ️ Vuln mapping disabled.");return};if config.NVDAPIKey==""{fmt.Println("⚠️ NVD API Key missing.");if !askForBool("Continue vuln map without NVD API key? (y/N): "){return}};fmt.Println("🔍 Mapping vulnerabilities...");var mappedCountAtomic int32;var wgVuln sync.WaitGroup;vulnSemMax:=10;if config.NVDAPIKey==""{vulnSemMax=2};vulnSem:=make(chan struct{},vulnSemMax);tempResults:=make([]EnhancedScanResult,len(results));copy(tempResults,results);totalToMap:=len(tempResults);mapProgressTicker:=time.NewTicker(1*time.Second);var displayMutexMap sync.Mutex;mapDoneSignal:=make(chan bool);go func(){for{select{case <-mapProgressTicker.C:current:=atomic.LoadInt32(&mappedCountAtomic);if totalToMap==0{continue};percentage:=float64(current)/float64(totalToMap)*100;displayMutexMap.Lock();fmt.Printf("\r\033[K🔍 Vuln Mapping: %d/%d (%.1f%%)",current,totalToMap,percentage);displayMutexMap.Unlock()
case <-mapDoneSignal:return}}}();for i:=range tempResults{wgVuln.Add(1);go func(idx int){defer wgVuln.Done();vulnSem<-struct{}{};defer func(){<-vulnSem}();mapVulnerabilities(&tempResults[idx]);atomic.AddInt32(&mappedCountAtomic,1)}(i)};wgVuln.Wait();mapDoneSignal<-true;mapProgressTicker.Stop();time.Sleep(150*time.Millisecond);mutex.Lock();results=tempResults;mutex.Unlock();finalMappedCount:=atomic.LoadInt32(&mappedCountAtomic);displayMutexMap.Lock();fmt.Printf("\r\033[K✅ Vuln mapping complete for %d results.\n",finalMappedCount);displayMutexMap.Unlock();displayResults()}
func generateTopologyMap() { if len(results)==0{fmt.Println("❌ No results for topology.");return};fmt.Println("🌐 Generating topology map...");var dotGraph strings.Builder;dotGraph.WriteString("digraph NetworkTopology {\n  rankdir=LR;\n  node [shape=record, style=\"rounded,filled\", fillcolor=\"#E6F5FF\"];\n  edge [style=dashed, color=gray40];\n");hostServices:=make(map[string]map[string][]string);for _,result:=range results{isConsideredOpen:=strings.ToLower(result.State)=="open"||(result.Protocol=="udp"&&strings.Contains(strings.ToLower(result.State),"open|filtered"));if isConsideredOpen{if _,ok:=hostServices[result.Host];!ok{hostServices[result.Host]=make(map[string][]string)};serviceKey:=result.Service;if serviceKey==""||serviceKey=="unknown"{serviceKey=fmt.Sprintf("port_%d",result.Port)};portProto:=fmt.Sprintf("%d/%s",result.Port,result.Protocol);hostServices[result.Host][serviceKey]=append(hostServices[result.Host][serviceKey],portProto)}};for host,servicesMap:=range hostServices{var serviceDetails[]string;for service,portsProtos:=range servicesMap{serviceDetails=append(serviceDetails,fmt.Sprintf("<%s> %s: %s",sanitizeForDotID(service),service,strings.Join(portsProtos,", ")))};nodeID:=sanitizeForDotID(host);label:=fmt.Sprintf("{%s|%s}",host,strings.Join(serviceDetails,"\\n"));dotGraph.WriteString(fmt.Sprintf("  \"%s\" [id=\"%s_node\" label=\"%s\"];\n",nodeID,nodeID,label))};dotGraph.WriteString("}\n");filename:=fmt.Sprintf("%s_topology.dot",strings.ReplaceAll(config.OutputFile,".","_"));if err:=os.WriteFile(filename,[]byte(dotGraph.String()),0644);err!=nil{fmt.Printf("❌ Failed topology file '%s': %v\n",filename,err);return};fmt.Printf("✅ Topology map saved to %s\n",filename);fmt.Printf("💡 Use Graphviz: dot -Tpng %s -o %s.png\n",filename,strings.TrimSuffix(filename,".dot"))}
func sanitizeForDotID(input string) string {sanitized:=strings.Map(func(r rune)rune{if(r>='a'&&r<='z')||(r>='A'&&r<='Z')||(r>='0'&&r<='9')||r=='_'{return r};return '_'},input);if len(sanitized)>0&&(sanitized[0]>='0'&&sanitized[0]<='9'){isNumeric:=true;for _,char:=range sanitized{if !(char>='0'&&char<='9'){isNumeric=false;break}};if isNumeric{return "id_"+sanitized}};return sanitized}
func displayResults() { mutex.Lock();defer mutex.Unlock();if len(results)==0{fmt.Println("❌ No results.");return};displayData:=results;if config.OnlyOpenPorts{filteredResults:=[]EnhancedScanResult{};for _,result:=range results{isConsideredOpen:=strings.ToLower(result.State)=="open"||(result.Protocol=="udp"&&strings.Contains(strings.ToLower(result.State),"open|filtered"));if isConsideredOpen{filteredResults=append(filteredResults,result)}};displayData=filteredResults};if len(displayData)==0{if config.OnlyOpenPorts{fmt.Println("ℹ️  No open/open|filtered ports to display.")}else{fmt.Println("ℹ️  No results to display.")};return};fmt.Printf("\n📊 Scan Results (%d entries):\n",len(displayData));fmt.Println("┌──────────────────────┬───────┬───────┬──────────────┬────────────────────┬─────────────────────────┬───────────────────┬──────────────────────┬────────────────────┬─────────────────┐");fmt.Println("│ Host                 │ Port  │ Proto │ State        │ Service            │ Version                 │ MAC Address       │ MAC Vendor           │ Vulnerabilities    │ OS Guess        │");fmt.Println("├──────────────────────┼───────┼───────┼──────────────┼────────────────────┼─────────────────────────┼───────────────────┼──────────────────────┼────────────────────┼─────────────────┤");for _,result:=range displayData{vulnStr:="N/A";if config.VulnMapping&&len(result.Vulnerabilities)>0{if len(result.Vulnerabilities)==1&&(strings.HasPrefix(result.Vulnerabilities[0],"No known")||strings.HasPrefix(result.Vulnerabilities[0],"Version/Service unknown")||strings.HasPrefix(result.Vulnerabilities[0],"Service '")||strings.HasPrefix(result.Vulnerabilities[0],"NVD lookup error")){vulnStr=result.Vulnerabilities[0]}else if strings.HasPrefix(result.Vulnerabilities[0],"(Local DB Match):")&&len(result.Vulnerabilities)>1{vulnStr=fmt.Sprintf("%d CVEs (Local)",len(result.Vulnerabilities)-1)}else{cveCount:=0;for _,v:=range result.Vulnerabilities{if strings.HasPrefix(v,"CVE-"){cveCount++}};if cveCount>0{vulnStr=fmt.Sprintf("%d CVEs",cveCount)}else if len(result.Vulnerabilities)>0{vulnStr="Info"}else{vulnStr="None"}}};macAddrStr:=result.MACAddress;if macAddrStr==""{macAddrStr="N/A"};macVendorStr:=result.MACVendor;if macVendorStr==""{macVendorStr="N/A"};fmt.Printf("│ %-20s │ %-5d │ %-5s │ %-12s │ %-18s │ %-25s │ %-17s │ %-20s │ %-18s │ %-15s │\n",truncateString(result.Host,20),result.Port,result.Protocol,truncateString(result.State,12),truncateString(result.Service,18),truncateString(result.Version,25),truncateString(macAddrStr,17),truncateString(macVendorStr,20),truncateString(vulnStr,18),truncateString(result.OSGuess,15))};fmt.Println("└──────────────────────┴───────┴───────┴──────────────┴────────────────────┴─────────────────────────┴───────────────────┴──────────────────────┴────────────────────┴─────────────────┘")}
func truncateString(s string, maxLen int) string {if len(s)>maxLen{if maxLen>3{return s[:maxLen-3]+"..."};return s[:maxLen]};return s}
func saveResults() {mutex.Lock();defer mutex.Unlock();if len(results)==0{fmt.Println("❌ No results to save.");return};filename:=fmt.Sprintf("%s.json",config.OutputFile);data,err:=json.MarshalIndent(results,"","  ");if err!=nil{fmt.Printf("❌ Error JSON marshal: %v\n",err);return};if err:=os.WriteFile(filename,data,0644);err!=nil{fmt.Printf("❌ Error writing JSON '%s': %v\n",filename,err);return};fmt.Printf("✅ JSON results saved to %s\n",filename)}
func exportResults() {mutex.Lock();currentResults:=make([]EnhancedScanResult,len(results));copy(currentResults,results);mutex.Unlock();if len(currentResults)==0{fmt.Println("❌ No results to export.");return};fmt.Println("📤 Export format:\n1. JSON\n2. CSV\n3. XML\n4. HTML");fmt.Print("Choose: ");choice:=getUserChoice();switch choice{case 1:exportJSON(currentResults);case 2:exportCSV(currentResults);case 3:exportXML(currentResults);case 4:exportHTML(currentResults);default:fmt.Println("❌ Invalid.")}}
func exportJSON(dataToExport []EnhancedScanResult) {filename:=fmt.Sprintf("%s_export.json",config.OutputFile);data,err:=json.MarshalIndent(dataToExport,"","  ");if err!=nil{fmt.Printf("❌ Error JSON export marshal: %v\n",err);return};if err:=os.WriteFile(filename,data,0644);err!=nil{fmt.Printf("❌ Error writing export JSON '%s': %v\n",filename,err);return};fmt.Printf("✅ JSON exported to %s\n",filename)}
func exportCSV(dataToExport []EnhancedScanResult) {filename:=fmt.Sprintf("%s.csv",config.OutputFile);file,err:=os.Create(filename);if err!=nil{fmt.Printf("❌ Error CSV create '%s': %v\n",filename,err);return};defer file.Close();writer:=bufio.NewWriter(file);header:=[]string{"Host","Port","Protocol","State","Service","Version","ResponseTime(ms)","Timestamp","MACAddress","MACVendor","Vulnerabilities","OSGuess"};writer.WriteString(strings.Join(header,",")+"\n");for _,result:=range dataToExport{vulnStr:=strings.ReplaceAll(strings.Join(result.Vulnerabilities,"; "),"\"","\"\"");record:=[]string{escapeCSVField(result.Host),strconv.Itoa(result.Port),escapeCSVField(result.Protocol),escapeCSVField(result.State),escapeCSVField(result.Service),escapeCSVField(result.Version),strconv.FormatInt(result.ResponseTime.Milliseconds(),10),result.Timestamp.Format(time.RFC3339),escapeCSVField(result.MACAddress),escapeCSVField(result.MACVendor),escapeCSVField(vulnStr),escapeCSVField(result.OSGuess)};writer.WriteString(strings.Join(record,",")+"\n")};writer.Flush();fmt.Printf("✅ CSV exported to %s\n",filename)}
func escapeCSVField(field string) string {if strings.ContainsAny(field,",\"\n"){return "\""+strings.ReplaceAll(field,"\"","\"\"")+"\""};return field}
func exportXML(dataToExport []EnhancedScanResult) {filename:=fmt.Sprintf("%s.xml",config.OutputFile);file,err:=os.Create(filename);if err!=nil{fmt.Printf("❌ Error XML create '%s': %v\n",filename,err);return};defer file.Close();type XMLScanResult struct {XMLName xml.Name `xml:"ScanResult"`;Host string `xml:"Host"`;Port int `xml:"Port"`;Protocol string `xml:"Protocol"`;State string `xml:"State"`;Service string `xml:"Service,omitempty"`;Version string `xml:"Version,omitempty"`;ResponseTimeMs int64 `xml:"ResponseTimeMs"`;Timestamp string `xml:"Timestamp"`;OSGuess string `xml:"OSGuess,omitempty"`;MACAddress string `xml:"MACAddress,omitempty"`;MACVendor string `xml:"MACVendor,omitempty"`;Vulnerabilities *struct{Vulnerability []string `xml:"Vulnerability,omitempty"`} `xml:"Vulnerabilities,omitempty"`};type XMLRoot struct {XMLName xml.Name `xml:"ReconRaptorResults"`;ScanInfo struct{ToolVersion string `xml:"ToolVersion"`;ExportTimestamp string `xml:"ExportTimestamp"`;Target string `xml:"Target,omitempty"`;FilterOpenOnly bool `xml:"FilterOpenOnly"`} `xml:"ScanInfo"`;Results []XMLScanResult `xml:"HostResults>Result"`};xmlData:=XMLRoot{};xmlData.ScanInfo.ToolVersion=VERSION;xmlData.ScanInfo.ExportTimestamp=time.Now().Format(time.RFC3339);xmlData.ScanInfo.FilterOpenOnly=config.OnlyOpenPorts;if config.TargetHost!=""{xmlData.ScanInfo.Target=config.TargetHost}else if config.TargetFile!=""{xmlData.ScanInfo.Target="File: "+config.TargetFile}else if config.NmapResultsFile!=""{xmlData.ScanInfo.Target="Nmap File: "+config.NmapResultsFile};for _,res:=range dataToExport{xmlRes:=XMLScanResult{Host:res.Host,Port:res.Port,Protocol:res.Protocol,State:res.State,Service:res.Service,Version:res.Version,ResponseTimeMs:res.ResponseTime.Milliseconds(),Timestamp:res.Timestamp.Format(time.RFC3339),OSGuess:res.OSGuess,MACAddress:res.MACAddress,MACVendor:res.MACVendor};if len(res.Vulnerabilities)>0{xmlRes.Vulnerabilities=&struct{Vulnerability []string `xml:"Vulnerability,omitempty"`}{Vulnerability:res.Vulnerabilities}};xmlData.Results=append(xmlData.Results,xmlRes)};encoder:=xml.NewEncoder(file);encoder.Indent("","  ");file.WriteString(xml.Header);if err:=encoder.Encode(xmlData);err!=nil{fmt.Printf("❌ Error XML marshal: %v\n",err);return};fmt.Printf("✅ XML exported to %s\n",filename)}
func exportHTML(dataToExport []EnhancedScanResult) {filename:=fmt.Sprintf("%s.html",config.OutputFile);file,err:=os.Create(filename);if err!=nil{fmt.Printf("❌ Error HTML create '%s': %v\n",filename,err);return};defer file.Close();type HTMLReportData struct {ToolVersion string;ExportTimestamp string;TargetInfo string;Results []EnhancedScanResult;FilterOpenOnly bool;TotalResults int};reportData:=HTMLReportData{ToolVersion:VERSION,ExportTimestamp:time.Now().Format("January 2, 2006 15:04:05 MST"),Results:dataToExport,FilterOpenOnly:config.OnlyOpenPorts,TotalResults:len(dataToExport)};if config.TargetHost!=""{reportData.TargetInfo=config.TargetHost}else if config.TargetFile!=""{reportData.TargetInfo="File: "+config.TargetFile}else if config.NmapResultsFile!=""{reportData.TargetInfo="Nmap File: "+config.NmapResultsFile}else{reportData.TargetInfo="N/A"};htmlTemplate:=`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>ReconRaptor Scan Report - {{.TargetInfo}}</title><style>body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;margin:0;background-color:#f0f2f5;color:#333;line-height:1.6}.container{max-width:1300px;margin:20px auto;padding:20px;background-color:#fff;box-shadow:0 0 15px rgba(0,0,0,0.1);border-radius:8px}h1,h2{color:#2c3e50;border-bottom:2px solid #3498db;padding-bottom:10px;margin-top:0}.header{background-color:#3498db;color:white;padding:20px;text-align:center;border-radius:8px 8px 0 0}.header h1{color:white;border-bottom:none;margin:0;font-size:2em}.summary{background-color:#eaf5ff;padding:20px;border-left:5px solid #3498db;margin-bottom:25px;border-radius:5px}.summary p{margin:5px 0}table{border-collapse:collapse;width:100%;margin-top:20px;font-size:0.85em}th,td{border:1px solid #ddd;padding:8px 10px;text-align:left;word-break:break-word}th{background-color:#3498db;color:white;font-weight:600}tr:nth-child(even){background-color:#f9f9f9}tr:hover{background-color:#f1f1f1}.footer{text-align:center;margin-top:30px;font-size:0.9em;color:#777;padding:15px;background-color:#ecf0f1;border-radius:0 0 8px 8px}.no-results{padding:20px;background-color:#fff0f0;border:1px solid #e9c6c6;color:#721c24;border-radius:5px;text-align:center;font-weight:bold}.vuln-list{list-style-type:none;padding-left:0;margin:0}.vuln-list li{padding:1px 0;font-size:0.95em}.vuln-list li:not(:last-child){border-bottom:1px dotted #eee;margin-bottom:2px;padding-bottom:2px}.tag{display:inline-block;padding:2px 6px;font-size:0.8em;border-radius:3px;margin-right:5px;color:white !important}.tag-open{background-color:#2ecc71}.tag-open-filtered{background-color:#f39c12}.tag-closed{background-color:#e74c3c}.tag-unknown{background-color:#95a5a6}</style></head><body><div class="container"><div class="header"><h1>ReconRaptor Scan Report</h1></div><div class="summary"><h2>Scan Summary</h2><p><strong>Target(s):</strong> {{.TargetInfo}}</p><p><strong>Tool Version:</strong> {{.ToolVersion}}</p><p><strong>Report Generated:</strong> {{.ExportTimestamp}}</p><p><strong>Total Results Displayed:</strong> {{.TotalResults}}</p>{{if .FilterOpenOnly}}<p><strong>Filter Active:</strong> Showing only open / open|filtered ports.</p>{{else}}<p><strong>Filter Active:</strong> Showing all collected port states.</p>{{end}}</div><h2>Detailed Scan Results</h2>{{if .Results}}<table><thead><tr><th>Host</th><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Version</th><th>MAC Address</th><th>MAC Vendor</th><th>Vulnerabilities</th><th>OS Guess</th><th>Timestamp</th></tr></thead><tbody>{{range .Results}}<tr><td>{{.Host}}</td><td>{{.Port}}</td><td>{{.Protocol}}</td><td>{{if eq (lower .State) "open"}}<span class="tag tag-open">{{.State}}</span>{{else if contains (lower .State) "open|filtered"}}<span class="tag tag-open-filtered">{{.State}}</span>{{else if contains (lower .State) "closed"}}<span class="tag tag-closed">{{.State}}</span>{{else}}<span class="tag tag-unknown">{{.State}}</span>{{end}}</td><td>{{.Service}}</td><td>{{.Version}}</td><td>{{if .MACAddress}}{{.MACAddress}}{{else}}N/A{{end}}</td><td>{{if .MACVendor}}{{.MACVendor}}{{else}}N/A{{end}}</td><td>{{if .Vulnerabilities}}<ul class="vuln-list">{{range .Vulnerabilities}}<li>{{.}}</li>{{end}}</ul>{{else}}N/A{{end}}</td><td>{{.OSGuess}}</td><td>{{.Timestamp.Format "2006-01-02 15:04:05"}}</td></tr>{{end}}</tbody></table>{{else}}<p class="no-results">No results match the current criteria.</p>{{end}}</div><div class="footer">Report generated by ReconRaptor (v{{.ToolVersion}})</div></body></html>`;funcMap:=template.FuncMap{"lower":strings.ToLower,"contains":strings.Contains};tmpl,err:=template.New("report").Funcs(funcMap).Parse(htmlTemplate);if err!=nil{fmt.Printf("❌ Error HTML template: %v\n",err);return};if err:=tmpl.Execute(file,reportData);err!=nil{fmt.Printf("❌ Error HTML execute: %v\n",err);return};fmt.Printf("✅ HTML exported to %s\n",filename)}
func loadConfigFromEnv() { if val:=os.Getenv("NVD_API_KEY");val!=""&&config.NVDAPIKey==""{config.NVDAPIKey=val;fmt.Println("ℹ️ Loaded NVD_API_KEY.")};if val:=os.Getenv("RECONRAPTOR_TARGET_HOST");val!=""&&config.TargetHost==""{config.TargetHost=val};if val:=os.Getenv("RECONRAPTOR_TARGET_FILE");val!=""&&config.TargetFile==""{config.TargetFile=val};if val:=os.Getenv("RECONRAPTOR_PORTS");val!=""&&config.PortRange=="1-1000"{config.PortRange=val};if val:=os.Getenv("RECONRAPTOR_OUTPUT");val!=""&&config.OutputFile=="scan_results"{config.OutputFile=val};if val,err:=strconv.ParseBool(os.Getenv("RECONRAPTOR_PING_SWEEP"));err==nil&&os.Getenv("RECONRAPTOR_PING_SWEEP")!=""{config.PingSweep=val};if val:=os.Getenv("RECONRAPTOR_PING_PORTS");val!=""{config.PingSweepPorts=val};if val,err:=strconv.Atoi(os.Getenv("RECONRAPTOR_PING_TIMEOUT"));err==nil&&os.Getenv("RECONRAPTOR_PING_TIMEOUT")!=""{config.PingSweepTimeout=val};if val,err:=strconv.ParseBool(os.Getenv("RECONRAPTOR_MAC_LOOKUP"));err==nil&&os.Getenv("RECONRAPTOR_MAC_LOOKUP")!=""{config.EnableMACLookup=val} }
func parseCommandLineFlags() { flag.StringVar(&config.TargetHost,"target",config.TargetHost,"Target host(s)");flag.StringVar(&config.TargetFile,"target-file",config.TargetFile,"File of targets");flag.StringVar(&config.PortRange,"ports",config.PortRange,"Port range");flag.IntVar(&config.ScanTimeout,"timeout",config.ScanTimeout,"Scan timeout (ms)");flag.IntVar(&config.MaxConcurrency,"concurrency",config.MaxConcurrency,"Max concurrent scans");flag.StringVar(&config.OutputFile,"output",config.OutputFile,"Output file base name");flag.BoolVar(&config.UDPScan,"udp",config.UDPScan,"Enable UDP scan");flag.BoolVar(&config.VulnMapping,"vuln",config.VulnMapping,"Enable NVD vuln mapping");flag.BoolVar(&config.TopologyMapping,"topology",config.TopologyMapping,"Enable topology map");flag.StringVar(&config.NVDAPIKey,"nvd-key",config.NVDAPIKey,"NVD API key");flag.StringVar(&config.NmapResultsFile,"nmap-file",config.NmapResultsFile,"Import Nmap XML");flag.BoolVar(&config.OnlyOpenPorts,"open-only",config.OnlyOpenPorts,"Display/process only open ports");flag.StringVar(&config.CVEPluginFile,"cve-plugin",config.CVEPluginFile,"Custom CVE JSON file");flag.BoolVar(&config.PingSweep,"ping-sweep",config.PingSweep,"Enable TCP ping sweep");flag.StringVar(&config.PingSweepPorts,"ping-ports",config.PingSweepPorts,"Ports for TCP ping sweep");flag.IntVar(&config.PingSweepTimeout,"ping-timeout",config.PingSweepTimeout,"Timeout (ms) for ping sweep");flag.BoolVar(&config.EnableMACLookup,"mac-lookup",config.EnableMACLookup,"Attempt MAC lookup (LAN, experimental)");flag.Usage=func(){fmt.Fprintf(os.Stderr,"ReconRaptor (v%s) by %s\nUsage: %s [options]\nOptions:\n",VERSION,AUTHORS,os.Args[0]);flag.PrintDefaults();fmt.Fprintf(os.Stderr,"\nExamples:\n  %s -target 192.168.1.0/24 -ports 1-1024 -ping-sweep -vuln -mac-lookup\n  %s -nmap-file results.xml -vuln\n  %s (interactive)\n\n",os.Args[0],os.Args[0],os.Args[0])};flag.Parse()}

func performIPSweepAndSave() {
	fmt.Println("📡 Starting IP Sweep Only mode...")
	if config.TargetHost == "" && config.TargetFile == "" {
		fmt.Println("❌ No targets configured. Please configure targets first (Menu Option 2 or CLI).")
		// Optionally prompt for targets here if desired for pure interactive IP sweep mode
		// config.TargetHost = askForString("🎯 Enter target host(s) for sweep (comma-separated or CIDR): ")
		// if config.TargetHost == "" { fmt.Println("❌ No targets provided. Aborting."); return }
		return
	}

	initialHosts := parseTargets(config.TargetHost, config.TargetFile)
	if len(initialHosts) == 0 { fmt.Println("❌ No valid targets found for sweep."); return }

	var liveHosts []string
	pingPortsToTry := parsePortRange(config.PingSweepPorts)
	if len(pingPortsToTry) == 0 { fmt.Println("⚠️ No valid ping ports, defaulting to 80,443."); pingPortsToTry = []int{80, 443} }
	tcpPingTimeout := time.Duration(config.PingSweepTimeout) * time.Millisecond
	if tcpPingTimeout <= 0 { fmt.Println("⚠️ Invalid ping timeout, defaulting to 300ms."); tcpPingTimeout = 300 * time.Millisecond }
	
	var pingWg sync.WaitGroup; var liveHostsMutex sync.Mutex
	pingSemMax := config.MaxConcurrency; if pingSemMax > 200 { pingSemMax = 200 }; if pingSemMax <= 0 { pingSemMax = 50 }
	pingSem := make(chan struct{}, pingSemMax)
	fmt.Printf("📡 Pinging %d hosts (ports: %v, timeout: %v, concurrency: %d)...\n", len(initialHosts), pingPortsToTry, tcpPingTimeout, pingSemMax)
	
	var pingedCountAtomic int64; totalToPing := len(initialHosts)
	pingProgressTicker := time.NewTicker(1*time.Second); var displayMutexPing sync.Mutex; doneSignal := make(chan bool)
	go func(){for{select{case <-pingProgressTicker.C:current:=atomic.LoadInt64(&pingedCountAtomic);if totalToPing==0{continue};percentage:=float64(current)/float64(totalToPing)*100;liveHostsMutex.Lock();foundLive:=len(liveHosts);liveHostsMutex.Unlock();displayMutexPing.Lock();fmt.Printf("\r\033[K📡 IP Sweep: %d/%d (%.1f%%) | Live: %d",current,totalToPing,percentage,foundLive);displayMutexPing.Unlock()
	case <-doneSignal: return}}}()
	for _,host := range initialHosts { pingWg.Add(1); go func(h string){defer pingWg.Done();pingSem<-struct{}{};defer func(){<-pingSem}(); if isHostAliveTCP(h,pingPortsToTry,tcpPingTimeout){liveHostsMutex.Lock();liveHosts=append(liveHosts,h);liveHostsMutex.Unlock()}; atomic.AddInt64(&pingedCountAtomic,1)}(host)}
	pingWg.Wait(); doneSignal<-true; pingProgressTicker.Stop(); time.Sleep(150*time.Millisecond)
	finalLiveCount := len(liveHosts)
	displayMutexPing.Lock(); fmt.Printf("\r\033[K📡 IP Sweep Complete. Found %d live hosts out of %d.\n",finalLiveCount,totalToPing); displayMutexPing.Unlock()

	if finalLiveCount > 0 {
		fmt.Println("\n📢 Live Hosts Found:"); for i, host := range liveHosts { fmt.Printf("  %d. %s\n", i+1, host) }
		if askForBool("\n💾 Save list of live hosts? (y/N): ") {
			outputFileName := askForString("Filename for live hosts (e.g., live_hosts.txt): "); if outputFileName==""{outputFileName="reconraptor_live_hosts.txt"}
			file, err := os.Create(outputFileName); if err!=nil{fmt.Printf("❌ Error creating file '%s': %v\n",outputFileName,err);return}; defer file.Close()
			writer := bufio.NewWriter(file); for _,host := range liveHosts {_,_=writer.WriteString(host+"\n")}; writer.Flush()
			fmt.Printf("✅ Live hosts saved to %s\n", outputFileName)
		}
	} else { fmt.Println("ℹ️ No live hosts found in the sweep.") }
}
