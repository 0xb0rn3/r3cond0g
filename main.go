package main

import (
	"bufio"
	"bytes" 
	"context"
	"crypto/tls" 
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
	"os/exec" 
	"regexp"
	"runtime" 
	"sort"    
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// VERSION is the current version of the tool
const VERSION = "0.2.3 ReconRaptor" // Version codename
const APP_NAME = "r3cond0g"
const AUTHORS = "IG:theehiv3 Alias:0xbv1 | Github:0xb0rn3"

// Config for the tool's configuration
type Config struct {
	TargetHost           string `json:"target_host"`
	TargetFile           string `json:"target_file"`
	PortRange            string `json:"port_range"`
	ScanTimeout          int    `json:"scan_timeout"`          // Overall timeout for a port scan attempt (connect)
	ServiceDetectTimeout int    `json:"service_detect_timeout"` // Specific timeout for service detection phase
	MaxConcurrency       int    `json:"max_concurrency"`
	OutputFile           string `json:"output_file"`
	UDPScan              bool   `json:"udp_scan"`
	VulnMapping          bool   `json:"vuln_mapping"`
	TopologyMapping      bool   `json:"topology_mapping"`
	NVDAPIKey            string `json:"nvd_api_key"`
	NmapResultsFile      string `json:"nmap_results_file"`
	OnlyOpenPorts        bool   `json:"only_open_ports"`
	CVEPluginFile        string `json:"cve_plugin_file"`
	PingSweep            bool   `json:"ping_sweep"`
	PingSweepPorts       string `json:"ping_sweep_ports"`
	PingSweepTimeout     int    `json:"ping_sweep_timeout"`
	EnableMACLookup      bool   `json:"enable_mac_lookup"`
	ProbeFiles           string `json:"probe_files"` // Comma-separated list of probe definition files
}

// EnhancedScanResult with vulnerability data and OS guess
type EnhancedScanResult struct {
	Host                string        `json:"host"`
	Port                int           `json:"port"`
	Protocol            string        `json:"protocol"`
	State               string        `json:"state"`
	Service             string        `json:"service,omitempty"`
	Version             string        `json:"version,omitempty"`
	ResponseTime        time.Duration `json:"response_time"`
	Timestamp           time.Time     `json:"timestamp"`
	Vulnerabilities     []string      `json:"vulnerabilities,omitempty"`
	OSGuess             string        `json:"os_guess,omitempty"`
	MACAddress          string        `json:"mac_address,omitempty"`
	MACVendor           string        `json:"mac_vendor,omitempty"`
	DetectionConfidence int           `json:"detection_confidence,omitempty"` // From ServiceInfo
	ALPNProtocol        string        `json:"alpn_protocol,omitempty"`        // From ServiceInfo
	TLSCommonName       string        `json:"tls_common_name,omitempty"`      // From ServiceInfo.TLSInfo
}

// NmapRun represents the root XML structure
type NmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []NmapHost `xml:"host"`
}

// NmapHost represents a host in nmap results
type NmapHost struct {
	Addresses []NmapAddress `xml:"address"`
	Ports     NmapPorts     `xml:"ports"`
	Status    NmapStatus    `xml:"status"`
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

// --- BEGIN INTEGRATED PROBE ENGINE CODE ---

// ServiceInfo represents the result of service detection
type ServiceInfo struct {
	ServiceName    string            `json:"service_name"`
	ServiceVersion string            `json:"service_version"`
	TLSInfo        *TLSInfo          `json:"tls_info,omitempty"`
	ALPNProtocol   string            `json:"alpn_protocol,omitempty"`
	Confidence     int               `json:"confidence"` // 0-100
	ExtraData      map[string]string `json:"extra_data,omitempty"`
}

// TLSInfo holds information extracted from TLS certificates
type TLSInfo struct {
	CommonName         string   `json:"common_name"`
	SubjectAltNames    []string `json:"subject_alt_names"`
	Issuer             string   `json:"issuer"`
	NotBefore          string   `json:"not_before"`
	NotAfter           string   `json:"not_after"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
}

// ProbeDefinition represents a single service detection probe
type ProbeDefinition struct {
	Name               string   `json:"name"`
	Protocol           string   `json:"protocol"`           // TCP or UDP
	Ports              []int    `json:"ports"`              // Applicable ports
	Priority           int      `json:"priority"`           // Lower numbers = higher priority
	RequiresTLS        bool     `json:"requires_tls"`       // Whether TLS handshake is needed
	TLSALPNProtocols   []string `json:"tls_alpn_protocols"` // ALPN protocols to negotiate
	SendPayload        string   `json:"send_payload"`       // Data to send (may contain templates)
	ReadPattern        string   `json:"read_pattern"`       // Regex to match response
	ServiceOverride    string   `json:"service_override"`   // Override service name if matched
	VersionTemplate    string   `json:"version_template"`   // Template for version formatting
	TimeoutMs          int      `json:"timeout_ms"`         // Specific timeout for this probe
	NextProbeOnMatch   string   `json:"next_probe_on_match"`// Chain to another probe
	compiledRegex      *regexp.Regexp                      // Compiled regex (not in JSON)
}

// ProbeEngine manages and executes service detection probes
type ProbeEngine struct {
	probes         []ProbeDefinition
	probesByName   map[string]*ProbeDefinition
	fallbackProbes []ProbeDefinition // For future use: load generic fallback probes here
}

var probeEngineInstance *ProbeEngine // Global instance

// NewProbeEngine creates a new probe engine and loads probe definitions
func NewProbeEngine(probeFilePaths ...string) (*ProbeEngine, error) {
	engine := &ProbeEngine{
		probesByName: make(map[string]*ProbeDefinition),
	}
	fmt.Printf("ℹ️ Initializing %s Probe Engine...\n", APP_NAME)
	if len(probeFilePaths) == 0 || (len(probeFilePaths) == 1 && probeFilePaths[0] == "") {
		fmt.Fprintf(os.Stderr, "⚠️ No probe files specified for Probe Engine. Service detection will rely on basic port mapping and generic banner grabbing.\n")
		return engine, nil // Return an empty but usable engine
	}

	allProbes := []ProbeDefinition{}
	for _, file := range probeFilePaths {
		trimmedFile := strings.TrimSpace(file)
		if trimmedFile == "" {
			continue
		}
		fmt.Printf("  🔍 Loading probes from: %s\n", trimmedFile)
		loadedProbes, err := engine.loadProbesFromFile(trimmedFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ❌ Error loading probes from '%s': %v. This file will be skipped.\n", trimmedFile, err)
			continue // Skip this file and try the next
		}
		allProbes = append(allProbes, loadedProbes...)
	}

	if len(allProbes) == 0 {
		fmt.Fprintf(os.Stderr, "⚠️ No probes were successfully loaded from any specified files. Service detection will be limited.\n")
	} else {
		fmt.Printf("  ✅ Successfully prepared %d probe definitions in total.\n", len(allProbes))
	}
	engine.probes = allProbes

	// Sort probes by priority (lower number = higher priority)
	sort.Slice(engine.probes, func(i, j int) bool {
		return engine.probes[i].Priority < engine.probes[j].Priority
	})

	// Compile regex patterns and populate probesByName
	for i := range engine.probes {
		probe := &engine.probes[i] // Use pointer to modify the slice element directly
		if probe.ReadPattern != "" {
			compiled, err := regexp.Compile(probe.ReadPattern)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠️ Error compiling regex for probe '%s' (pattern: %s): %v. This probe's matching will be impaired.\n", probe.Name, probe.ReadPattern, err)
				probe.compiledRegex = nil 
			} else {
				probe.compiledRegex = compiled
			}
		}
		engine.probesByName[probe.Name] = probe
	}
	return engine, nil
}

// loadProbesFromFile loads probe definitions from a JSON file
func (pe *ProbeEngine) loadProbesFromFile(filename string) ([]ProbeDefinition, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("could not read probe file '%s': %w", filename, err)
	}
	if len(data) == 0 {
		return []ProbeDefinition{}, fmt.Errorf("probe file '%s' is empty", filename)
	}

	var probes []ProbeDefinition
	if err := json.Unmarshal(data, &probes); err != nil {
		return nil, fmt.Errorf("could not unmarshal JSON from probe file '%s': %w", filename, err)
	}
	return probes, nil
}

// getApplicableProbes returns probes that apply to the given port and protocol, already sorted by priority
func (pe *ProbeEngine) getApplicableProbes(port int, protocol string) []ProbeDefinition {
	var applicable []ProbeDefinition
	protocolLower := strings.ToLower(protocol)

	for _, probe := range pe.probes { // pe.probes is already sorted by priority
		if strings.ToLower(probe.Protocol) == protocolLower {
			appliesToPort := false
			if len(probe.Ports) == 0 { // Empty Ports array means probe can be a generic fallback (like Generic-TCP-Fallback-Banner)
				appliesToPort = true 
			} else {
				for _, p := range probe.Ports {
					if p == port {
						appliesToPort = true
						break
					}
				}
			}
			if appliesToPort {
				applicable = append(applicable, probe)
			}
		}
	}
	return applicable
}

// executeProbe runs a single probe against the connection
func (pe *ProbeEngine) executeProbe(originalConn net.Conn, probe ProbeDefinition, host string, overallTimeout time.Duration) (*ServiceInfo, error) {
	probeSpecificTimeoutMs := overallTimeout // Default to overall if not set in probe
	if probe.TimeoutMs > 0 {
		probeSpecificTimeoutMs = time.Duration(probe.TimeoutMs) * time.Millisecond
	}
	// Ensure probe timeout does not exceed overall service detection timeout
	if probeSpecificTimeoutMs > overallTimeout || probeSpecificTimeoutMs <= 0 {
		probeSpecificTimeoutMs = overallTimeout
	}
    if probeSpecificTimeoutMs <= 0 { // Final safety net for timeout
        probeSpecificTimeoutMs = 2 * time.Second // A reasonable minimum if everything else failed
    }

	ctx, cancel := context.WithTimeout(context.Background(), probeSpecificTimeoutMs)
	defer cancel()

	var currentConn net.Conn = originalConn
	var tlsConn *tls.Conn
	var tlsInfoResult *TLSInfo
	var alpnProtocolResult string
	
	if probe.RequiresTLS {
		if originalConn == nil {
			return nil, fmt.Errorf("cannot perform TLS handshake for probe '%s' on a nil connection", probe.Name)
		}
		// Check if it's already a TLS connection (e.g., from a chained probe)
		if _, ok := originalConn.(*tls.Conn); ok {
			tlsConn = originalConn.(*tls.Conn)
		} else {
			tlsClientConfig := &tls.Config{
				InsecureSkipVerify: true, // Standard for recon tools
				ServerName:         host,   // For SNI
			}
			if len(probe.TLSALPNProtocols) > 0 {
				tlsClientConfig.NextProtos = probe.TLSALPNProtocols
			}
			tlsConn = tls.Client(originalConn, tlsClientConfig)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				return nil, fmt.Errorf("TLS handshake for probe '%s' on %s failed: %w", probe.Name, host, err)
			}
		}
		currentConn = tlsConn // Use the TLS connection for I/O

		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			var sanIPs []string
			for _, ip := range cert.IPAddresses { sanIPs = append(sanIPs, ip.String()) }
			sAn := append(cert.DNSNames, sanIPs...)

			tlsInfoResult = &TLSInfo{
				CommonName:         cert.Subject.CommonName,
				SubjectAltNames:    sAn,
				Issuer:             cert.Issuer.String(),
				NotBefore:          cert.NotBefore.Format(time.RFC3339),
				NotAfter:           cert.NotAfter.Format(time.RFC3339),
				SignatureAlgorithm: cert.SignatureAlgorithm.String(),
			}
		}
		alpnProtocolResult = state.NegotiatedProtocol
	}

	// Send payload if specified
	if probe.SendPayload != "" {
		if currentConn == nil {
			return nil, fmt.Errorf("cannot send payload for probe '%s'; connection is nil", probe.Name)
		}
		payload := pe.processPayloadTemplate(probe.SendPayload, host)
		
		writeDeadline := time.Now().Add(probeSpecificTimeoutMs / 2) // Allocate half of probe timeout for write
		if err := currentConn.SetWriteDeadline(writeDeadline); err != nil {
            // Non-critical if SetWriteDeadline fails on some conn types, but log it
            // fmt.Fprintf(os.Stderr, "Debug: could not set write deadline for probe %s: %v\n", probe.Name, err)
        }

		if _, err := currentConn.Write([]byte(payload)); err != nil {
			return nil, fmt.Errorf("failed to send payload for probe '%s': %w", probe.Name, err)
		}
	}

	// Read response (even if no payload was sent, for banner-grabbing probes)
	if currentConn == nil && probe.ReadPattern != "" { // Need a connection to read a response
		return nil, fmt.Errorf("cannot read response for probe '%s'; connection is nil", probe.Name)
	}
    if currentConn == nil && probe.ReadPattern == "" && probe.SendPayload == "" { // Probe does nothing, can't determine service
        return nil, fmt.Errorf("probe '%s' has no send payload and no read pattern, cannot determine service", probe.Name)
    }


	readDeadline := time.Now().Add(probeSpecificTimeoutMs) // Use full remaining probe timeout for read
    if probe.SendPayload != "" { // If we sent something, give roughly half the remaining time for read
        readDeadline = time.Now().Add(probeSpecificTimeoutMs/2)
    }
	if err := currentConn.SetReadDeadline(readDeadline); err != nil {
        // fmt.Fprintf(os.Stderr, "Debug: could not set read deadline for probe %s: %v\n", probe.Name, err)
    }

	buffer := make([]byte, 16384) // Increased buffer for potentially large banners/responses
	n, readErr := currentConn.Read(buffer)

	// Handle read errors carefully
	if readErr != nil && readErr != io.EOF { // Genuine error other than EOF
		if n == 0 { // No data read AND an error
			return nil, fmt.Errorf("error reading response for probe '%s': %w", probe.Name, readErr)
		}
		// If n > 0 and an error, process the data read so far, error might be due to timeout cutting it short
	}
	if n == 0 && readErr == io.EOF && probe.SendPayload != "" { // Sent something, got immediate EOF
		return nil, fmt.Errorf("immediate EOF after sending payload for probe '%s'", probe.Name)
	}
	if n == 0 && probe.ReadPattern != "" { // Expected to read something due to ReadPattern, but got nothing
		return nil, fmt.Errorf("no data received for probe '%s' when a response was expected", probe.Name)
	}


	response := string(buffer[:n])
	serviceName := probe.ServiceOverride
	if serviceName == "" {
		serviceName = "unknown"
	}
	serviceVersion := "unknown"
	confidence := 30 // Base confidence for getting any response

	if probe.compiledRegex != nil && response != "" {
		matches := probe.compiledRegex.FindStringSubmatch(response)
		if matches != nil {
			confidence = 80 
			if probe.VersionTemplate != "" {
				serviceVersion = pe.processVersionTemplate(probe.VersionTemplate, matches)
			} else if len(matches) > 1 {
				serviceVersion = strings.TrimSpace(matches[1])
			}
			// If ServiceOverride is empty, and regex has a group that could be service name, consider using it.
			// This logic needs to be carefully designed with probe definitions.
			// For now, relying on ServiceOverride or later normalization.
		} else {
			confidence = 20 // Regex was defined but didn't match the non-empty response
		}
	} else if response == "" && probe.compiledRegex != nil {
        // No response to match regex against
        confidence = 10
    }


	if probe.RequiresTLS && tlsInfoResult != nil { // If TLS was used, and we got cert info
		confidence = int(math.Max(float64(confidence), 50)) // Boost confidence if TLS info is present
		if serviceName == "unknown" && alpnProtocolResult == "" { // If service still unknown, but TLS was used
			serviceName = "ssl" // Generic SSL/TLS service
            if probe.ServiceOverride != "" { serviceName = probe.ServiceOverride } // Prefer explicit override
		}
	}
    if alpnProtocolResult != "" {
        confidence = int(math.Max(float64(confidence), 70)) // ALPN is a good indicator
		if serviceName == "unknown" || serviceName == "ssl" || serviceName == "http" || serviceName == "https" { // Refine service name based on ALPN
			// Simple ALPN to service mapping
			if strings.Contains(alpnProtocolResult, "h2") { serviceName = "http/2" }
			if strings.Contains(alpnProtocolResult, "http/1.1") { serviceName = "http" }
			if serviceName == "http" && probe.RequiresTLS { serviceName = "https" } // If it was http over TLS, it's https
		}
    }


	finalServiceName := pe.normalizeServiceName(serviceName)
	finalServiceVersion := pe.normalizeVersion(serviceVersion)
    
    // If version still unknown after normalization, but raw response seems like a version, use it.
    if finalServiceVersion == "unknown" && len(response) > 0 && len(response) < 50 && !strings.Contains(response, " ") && probe.compiledRegex == nil {
        isPrintable := true
        for _, r := range response { if r < 32 || r > 126 { isPrintable = false; break } }
        if isPrintable {
            finalServiceVersion = response
            confidence = int(math.Max(float64(confidence), 40))
        }
    }


	extraData := map[string]string{"raw_response_snippet": truncateString(response, 256)}
	if tlsInfoResult != nil && tlsInfoResult.CommonName != "" {
		extraData["tls_cn"] = tlsInfoResult.CommonName
	}

	return &ServiceInfo{
		ServiceName:    finalServiceName,
		ServiceVersion: finalServiceVersion,
		TLSInfo:        tlsInfoResult,
		ALPNProtocol:   alpnProtocolResult,
		Confidence:     confidence,
		ExtraData:      extraData,
	}, nil
}

// processPayloadTemplate processes template variables in probe payloads
func (pe *ProbeEngine) processPayloadTemplate(payload, host string) string {
	payload = strings.ReplaceAll(payload, "{{TARGET_HOST}}", host)
	// Handle hex encoded data, e.g., \xHH
	var processedPayload strings.Builder
	i := 0
	for i < len(payload) {
		if payload[i] == '\\' && i+1 < len(payload) {
			switch payload[i+1] {
			case 'r':
				processedPayload.WriteByte('\r')
				i += 2
			case 'n':
				processedPayload.WriteByte('\n')
				i += 2
			case 't':
				processedPayload.WriteByte('\t')
				i += 2
			case 'x':
				if i+3 < len(payload) {
					byteVal, err := strconv.ParseUint(payload[i+2:i+4], 16, 8)
					if err == nil {
						processedPayload.WriteByte(byte(byteVal))
						i += 4
						continue
					}
				}
				// If not valid hex, write \x literally
				processedPayload.WriteByte(payload[i])
				i++
			case '\\':
				processedPayload.WriteByte('\\')
				i += 2
			default:
				processedPayload.WriteByte(payload[i]) // Write backslash
				processedPayload.WriteByte(payload[i+1]) // Write next char
				i += 2
			}
		} else {
			processedPayload.WriteByte(payload[i])
			i++
		}
	}
	return processedPayload.String()
}

// processVersionTemplate processes version templates using regex capture groups
func (pe *ProbeEngine) processVersionTemplate(template string, matches []string) string {
	result := template
	for i, matchVal := range matches { // matches[0] is full match, matches[1] is group 1, etc.
		placeholder := fmt.Sprintf("{{group_%d}}", i)
		result = strings.ReplaceAll(result, placeholder, strings.TrimSpace(matchVal))
	}
	return strings.TrimSpace(result)
}

// normalizeServiceName normalizes service names to standard format
func (pe *ProbeEngine) normalizeServiceName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	// More comprehensive normalization
	switch {
	case name == "" || name == "unknown" || name == "ssl" || name == "tls": // Keep these as is if no better info
		return name
	case strings.Contains(name, "ssh"):
		return "ssh"
	case strings.Contains(name, "ftp"):
		return "ftp"
	case strings.Contains(name, "smtp"):
		return "smtp"
	case name == "smtps":
		return "smtps"
	case strings.Contains(name, "pop3"):
		return "pop3"
	case name == "pop3s":
		return "pop3s"
	case strings.Contains(name, "imap"):
		return "imap"
	case name == "imaps":
		return "imaps"
	case strings.Contains(name, "http") || strings.Contains(name, "www"): // Catches http, https, http/2
		if strings.Contains(name, "https") || strings.Contains(name, "http/2") { // crude check for https if over tls
			return "https" // could be http/2 over tls
		}
		return "http"
	case strings.Contains(name, "rdp") || strings.Contains(name, "ms-wbt-server"):
		return "rdp"
	case strings.Contains(name, "mysql"):
		return "mysql"
	case strings.Contains(name, "postgres"):
		return "postgresql"
	case strings.Contains(name, "mongo"):
		return "mongodb"
	case strings.Contains(name, "redis"):
		return "redis"
	case strings.Contains(name, "vnc"):
		return "vnc"
	case strings.Contains(name, "ldap"): // Catches ldap and ldaps
		if strings.Contains(name, "ldaps") { return "ldaps"}
		return "ldap"
	case strings.Contains(name, "dns"):
		return "dns"
	case strings.Contains(name, "ntp"):
		return "ntp"
	case strings.Contains(name, "snmp"):
		return "snmp"
	case strings.Contains(name, "dhcp"):
		return "dhcp"
	case strings.Contains(name, "tftp"):
		return "tftp"
	case strings.Contains(name, "netbios"):
		return "netbios"
	case strings.Contains(name, "mdns"):
		return "mdns"
	case strings.Contains(name, "sip"):
		if strings.Contains(name, "sips") { return "sips" }
		return "sip"
	case strings.Contains(name, "xmpp"):
		return "xmpp"
	case strings.Contains(name, "kerberos"):
		return "kerberos"
	case strings.Contains(name, "rpcbind") || strings.Contains(name, "portmap"):
		return "rpcbind"
	}
	return name // Return as is if no specific normalization rule matched
}

// normalizeVersion normalizes version strings
func (pe *ProbeEngine) normalizeVersion(version string) string {
	if version == "" || version == "unknown" || strings.HasPrefix(version, "banner:") {
		return version // Keep "unknown" or raw banner prefix as is
	}
	version = strings.TrimSpace(version)
	if strings.HasPrefix(strings.ToLower(version), "v") {
		version = version[1:]
	}
	// Remove common OS/distro suffixes like (Ubuntu), (Debian)
	re := regexp.MustCompile(`\s*\([^)]*\)\s*$`)
	version = re.ReplaceAllString(version, "")
	// Remove trailing dots or commas often found in banners
	version = strings.TrimRight(version, ".,")
	return strings.TrimSpace(version)
}

// detectServiceBasic provides fallback basic service detection based on port
func detectServiceBasic(port int, protocol string) (string, string) {
	defaultServices := map[int]string{21:"ftp", 22:"ssh", 23:"telnet", 25:"smtp", 53:"dns", 67:"dhcp",68:"dhcp",69:"tftp", 80:"http",110:"pop3", 111:"rpcbind", 123:"ntp",135:"msrpc",137:"netbios-ns",138:"netbios-dgm",139:"netbios-ssn", 143:"imap", 161:"snmp", 162:"snmptrap", 389:"ldap", 443:"https", 445:"microsoft-ds", 465:"smtps",514:"syslog",587:"submission",636:"ldaps",993:"imaps",995:"pop3s",1080:"socks",1433:"mssql",1521:"oracle",1723:"pptp",2049:"nfs",3000:"http-alt",3268:"globalcatLDAP",3269:"globalcatLDAPssl",3306:"mysql", 3389:"ms-wbt-server", 5060:"sip",5061:"sips",5222:"xmpp-client",5353:"mdns",5432:"postgresql", 5900:"vnc",5985:"winrm",5986:"winrm-ssl",6379:"redis",8000:"http-alt",8080:"http-proxy", 8443:"https-alt", 27017:"mongodb"}
	if service, exists := defaultServices[port]; exists {
		return service, "unknown (default port)"
	}
	return "unknown", "unknown"
}

// detectServiceWithTimeout is the main exported function for service detection.
func detectServiceWithTimeout(conn net.Conn, port int, protocol string, serviceDetectionTimeout time.Duration) *ServiceInfo {
	defaultService, defaultVersion := detectServiceBasic(port, protocol)
	result := &ServiceInfo{
		ServiceName:    defaultService,
		ServiceVersion: defaultVersion,
		Confidence:     10, // Low confidence for basic port mapping
	}

	if probeEngineInstance == nil || len(probeEngineInstance.probes) == 0 {
		if probeEngineInstance == nil {
			fmt.Fprintf(os.Stderr, "⚠️ Probe engine not initialized. Using basic service detection for %s:%d/%s.\n", conn.RemoteAddr().String(), port, protocol)
		} else {
			// Engine is initialized but has no probes loaded successfully
			// fmt.Fprintf(os.Stderr, "Debug: Probe engine has no probes. Using basic service detection for %s:%d/%s.\n", conn.RemoteAddr().String(), port, protocol)
		}
		// Attempt generic banner grab even if probe engine is not fully up
		if strings.ToLower(protocol) == "tcp" && conn != nil {
			if bannerResult := tryGenericBannerGrab(conn, port, serviceDetectionTimeout); bannerResult != nil {
				return bannerResult // Return generic banner result
			}
		}
		return result // Return basic port mapped result
	}

	host := "target" // Default for SNI, templates
	if conn != nil {
		if remoteAddr := conn.RemoteAddr(); remoteAddr != nil {
			if h, _, err := net.SplitHostPort(remoteAddr.String()); err == nil {
				host = h
			} else if ipAddr, ok := remoteAddr.(interface{ IP() net.IP }); ok {
                host = ipAddr.IP().String()
            }
		}
	}
    if host == "" || host == "[]" || host == "[::]" { host = "target" }


	applicableProbes := probeEngineInstance.getApplicableProbes(port, protocol)
	if len(applicableProbes) == 0 && strings.ToLower(protocol) == "tcp" && conn != nil { // No specific probes, try generic TCP
		if bannerResult := tryGenericBannerGrab(conn, port, serviceDetectionTimeout); bannerResult != nil {
			return bannerResult
		}
        return result // Return basic if generic grab also fails
	}
    if len(applicableProbes) == 0 { // No specific probes and not TCP for generic grab
        return result
    }


	var bestResult *ServiceInfo = result // Start with basic result
	// var lastErr error // For debugging

	for _, probe := range applicableProbes {
		// Skip "Generic-TCP-Fallback-Banner" if other probes already gave a decent result
		if probe.Name == "Generic-TCP-Fallback-Banner" && bestResult != nil && bestResult.Confidence > 30 {
			continue
		}

		probeRes, err := probeEngineInstance.executeProbe(conn, probe, host, serviceDetectionTimeout)
		if err != nil {
			// lastErr = err
			// fmt.Fprintf(os.Stderr, "Debug: Probe '%s' for %s:%d/%s failed: %v\n", probe.Name, host, port, protocol, err)
			continue
		}

		if probeRes != nil {
			if bestResult == nil || probeRes.Confidence > bestResult.Confidence {
				bestResult = probeRes
			} else if probeRes.Confidence == bestResult.Confidence && len(probeRes.ServiceVersion) > len(bestResult.ServiceVersion) && bestResult.ServiceVersion == "unknown" {
                // Prefer a result with some version info if confidence is same
                bestResult = probeRes
            }


			// Handle probe chaining (simple version, might need more sophisticated state)
			if probe.NextProbeOnMatch != "" && probeRes.Confidence >= 50 { // Confidence threshold for chaining
				if nextProbeDef, exists := probeEngineInstance.probesByName[probe.NextProbeOnMatch]; exists {
					// Use the connection state as it is (e.g., potentially after TLS handshake from previous probe)
					nextRes, chainErr := probeEngineInstance.executeProbe(conn, *nextProbeDef, host, serviceDetectionTimeout)
					if chainErr == nil && nextRes != nil {
						if bestResult == nil || nextRes.Confidence > bestResult.Confidence {
							bestResult = nextRes
						} else if nextRes.Confidence == bestResult.Confidence && len(nextRes.ServiceVersion) > len(bestResult.ServiceVersion) && bestResult.ServiceVersion == "unknown" {
                           bestResult = nextRes
                        }
					} // else { lastErr = chainErr }
				}
			}
            if bestResult.Confidence >= 90 { break } // Stop if very confident
		}
	}
    
    // If service name is still "unknown" or empty from probes, but ALPN or TLS info suggests HTTP/S, refine it
    if bestResult != nil && (bestResult.ServiceName == "unknown" || bestResult.ServiceName == "" || bestResult.ServiceName == "ssl") {
        refined := false
        if bestResult.ALPNProtocol != "" {
            if strings.Contains(bestResult.ALPNProtocol, "h2") { bestResult.ServiceName = "http/2"; refined = true }
            if !refined && strings.Contains(bestResult.ALPNProtocol, "http/1") { bestResult.ServiceName = "http"; refined = true }
            if refined && bestResult.TLSInfo != nil { bestResult.ServiceName = "https" } // Assume https if http over TLS
        }
        if !refined && bestResult.TLSInfo != nil { // If TLS was involved, likely HTTPS if service is unknown
            bestResult.ServiceName = "https"
        }
		if bestResult.ServiceName == "" { bestResult.ServiceName = "unknown" } // Ensure it's not empty
    }


	return bestResult
}


var (
	config = Config{
		TargetHost:       "",
		TargetFile:       "",
		PortRange:        "1-1000",
		ScanTimeout:      1000, 
		ServiceDetectTimeout: 500, 
		MaxConcurrency:   100,
		OutputFile:       "r3cond0g_scan",
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
		ProbeFiles:       "tcp_probes.json,udp_probes.json", 
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
		"http":          {"apache", "httpd"}, "https": {"apache", "httpd"}, "http/2": {"apache", "httpd"}, // Added http/2
		"ssh": {"openssh", "openssh"}, "ftp":   {"proftpd", "proftpd"}, "mysql": {"oracle", "mysql"}, 
		"dns":           {"isc", "bind"}, "smtp":  {"postfix", "postfix"}, "smtps": {"postfix", "postfix"},
		"redis":         {"redis", "redis"}, "rdp":   {"microsoft", "remote_desktop_services"},
		"ms-wbt-server": {"microsoft", "remote_desktop_services"}, "microsoft-ds": {"microsoft", "windows"},
		"netbios-ssn":   {"microsoft", "windows"}, "winrm": {"microsoft", "windows_remote_management"},
		"snmp":          {"net-snmp", "net-snmp"}, 
		"pop3":          {"dovecot", "dovecot"}, "pop3s": {"dovecot", "dovecot"},
		"imap":          {"dovecot", "dovecot"}, "imaps": {"dovecot", "dovecot"},
		"postgresql":    {"postgresql", "postgresql"}, "mongodb": {"mongodb", "mongodb"},
		"ldap":          {"openldap", "openldap"}, "ldaps": {"openldap", "openldap"},
		"vnc":           {"realvnc", "vnc"}, // Example, VNC CPEs are varied
	}
)

func main() {
	printBanner()
	loadConfigFromEnv()
	parseCommandLineFlags() 
	
	var probeFilePaths []string
	if config.ProbeFiles != "" {
		probeFilePaths = strings.Split(config.ProbeFiles, ",")
		for i, p := range probeFilePaths { // Trim spaces from each file path
			probeFilePaths[i] = strings.TrimSpace(p)
		}
	}

	var err error
	probeEngineInstance, err = NewProbeEngine(probeFilePaths...) // Initialize global instance
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Critical error initializing Probe Engine: %v. Service detection will use basic methods only.\n", err)
	}


	loadCustomCVEs()

	runDirectly := false
	if (config.TargetHost != "" || config.TargetFile != "") && config.PortRange != "" {
		if config.NmapResultsFile == "" || (config.NmapResultsFile != "" && (config.TargetHost != "" || config.TargetFile != "")) {
			runDirectly = true
		}
	}
	if config.NmapResultsFile != "" && !(config.TargetHost != "" || config.TargetFile != "") {
		runDirectly = true
	}

	if runDirectly || isAnyFlagSetBesidesHelpAndDefaults() {
		if (config.TargetHost != "" || config.TargetFile != "") && config.PortRange != "" {
			fmt.Printf("ℹ️  %s attempting direct scan...\n", APP_NAME)
			if validateConfig() {
				results = runUltraFastScan() 
				if config.VulnMapping && len(results) > 0 { performVulnerabilityMapping() }
				if config.TopologyMapping && len(results) > 0 { generateTopologyMap() }
				if len(results) > 0 { displayResults(); saveResults()
				} else { fmt.Println("ℹ️  Direct scan completed. No open ports matching criteria found on live hosts.") }
			} else { fmt.Println("❌ Direct scan aborted due to invalid configuration.") }
		} else if config.NmapResultsFile != "" {
			fmt.Printf("ℹ️  %s attempting direct Nmap parse from '%s'...\n", APP_NAME, config.NmapResultsFile)
			parseNmapResults()
			if len(results) > 0 {
				saveResults()
				if config.VulnMapping {
					fmt.Println("ℹ️  Attempting vulnerability mapping on parsed Nmap results...")
					performVulnerabilityMapping()
				}
			}
		}
		fmt.Printf("👋 Exiting %s v%s\n", APP_NAME, VERSION)
		return
	}

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
		case 10: fmt.Printf("👋 Exiting %s v%s\n", APP_NAME, VERSION); return
		case 11: cidr := askForString("🔍 Enter CIDR/Target to debug parsing: "); debugCIDRParsing(cidr)
		default: fmt.Println("❌ Invalid option.")
		}
	}
}

func isAnyFlagSetBesidesHelpAndDefaults() bool {
	if flag.NFlag() == 0 { 
		return false
	}
	helpSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "h" || f.Name == "help" {
			helpSet = true
		}
	})
	if flag.NFlag() == 1 && helpSet {
		return false 
	}
	return flag.NFlag() > 0
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
	fmt.Printf("\n=== %s 𓃦 - Main Menu ===\n", strings.ToUpper(APP_NAME))
	fmt.Println("1. 🚀 Run Network Scan (Ports & Services)")
	fmt.Println("2. 🛠️  Configure Settings")
	fmt.Println("3. 📋 Display Scan Results")
	fmt.Println("4. 💾 Save Scan Results (JSON)")
	fmt.Println("5. 📄 Parse Nmap XML Results")
	fmt.Println("6. 🔍 Perform Vulnerability Mapping")
	fmt.Println("7. 🌐 Generate Network Topology Map (DOT)")
	fmt.Println("8. 📤 Export Scan Results (CSV, XML, HTML)")
	fmt.Println("9. 📡 IP Sweep & Save Live Hosts")
	fmt.Println("10. ❌ Exit")
	fmt.Print("Choose an option: ")
}

func getUserChoice() int {
	var choiceStr string
	fmt.Scanln(&choiceStr)
	choice, err := strconv.Atoi(choiceStr)
	if err != nil {
		return -1
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
		fmt.Println("\n=== ⚙️ Configuration Settings ===")
		fmt.Printf(" 1. Target Host(s):         %s\n", config.TargetHost)
		fmt.Printf(" 2. Target File:            %s\n", config.TargetFile)
		fmt.Printf(" 3. Port Range:             %s\n", config.PortRange)
		fmt.Printf(" 4. Scan Connect Timeout(ms):%d\n", config.ScanTimeout)
		fmt.Printf(" 5. Service Detect Timeout(ms):%d\n", config.ServiceDetectTimeout)
		fmt.Printf(" 6. Max Concurrency:        %d\n", config.MaxConcurrency)
		fmt.Printf(" 7. Output File Base Name:  %s\n", config.OutputFile)
		fmt.Printf(" 8. UDP Scan Enabled:       %t\n", config.UDPScan)
		fmt.Printf(" 9. Vuln Mapping Enabled:   %t\n", config.VulnMapping)
		fmt.Printf("10. Topology Map Enabled:    %t\n", config.TopologyMapping)
		fmt.Printf("11. NVD API Key:             %s\n", maskAPIKey(config.NVDAPIKey))
		fmt.Printf("12. Nmap Results File (Import):%s\n", config.NmapResultsFile)
		fmt.Printf("13. Display Only Open Ports: %t\n", config.OnlyOpenPorts)
		fmt.Printf("14. Custom CVE Plugin File:  %s\n", config.CVEPluginFile)
		fmt.Printf("15. Ping Sweep Enabled:      %t\n", config.PingSweep)
		fmt.Printf("16. Ping Sweep Ports:        %s\n", config.PingSweepPorts)
		fmt.Printf("17. Ping Sweep Timeout (ms): %d\n", config.PingSweepTimeout)
		fmt.Printf("18. MAC Lookup Enabled:      %t\n", config.EnableMACLookup)
		fmt.Printf("19. Probe Definition Files:  %s\n", config.ProbeFiles)
		fmt.Println(" 0. Back to Main Menu")
		fmt.Print("⚙️ Choose a setting to update (0-19): ")

		choice := getUserChoice()
		var tempInt int
		var tempStr string
		var tempBool bool

		switch choice {
		case 1: config.TargetHost = askForString("🎯 New Target Host(s) (current: " + config.TargetHost + "): ")
		case 2: config.TargetFile = askForString("📁 New Target File Path (current: " + config.TargetFile + "): ")
		case 3: config.PortRange = askForString("🔢 New Port Range (current: " + config.PortRange + "): ")
		case 4: 
			tempStr = askForString(fmt.Sprintf("⏱️ New Scan Connect Timeout (ms) (current: %d): ", config.ScanTimeout))
			if val, err := strconv.Atoi(tempStr); err == nil && val > 0 { config.ScanTimeout = val }
		case 5:
			tempStr = askForString(fmt.Sprintf("⏱️ New Service Detect Timeout (ms) (current: %d): ", config.ServiceDetectTimeout))
			if val, err := strconv.Atoi(tempStr); err == nil && val > 0 { config.ServiceDetectTimeout = val }
		case 6: 
			tempStr = askForString(fmt.Sprintf("🔄 New Max Concurrency (current: %d): ", config.MaxConcurrency))
			if val, err := strconv.Atoi(tempStr); err == nil && val > 0 { config.MaxConcurrency = val }
		case 7: config.OutputFile = askForString("📄 New Output File Base Name (current: " + config.OutputFile + "): ")
		case 8: 
			tempBool = askForBool(fmt.Sprintf("🛡️ Enable UDP Scan? (current: %t, true/false): ", config.UDPScan))
			config.UDPScan = tempBool
		case 9: 
			tempBool = askForBool(fmt.Sprintf("🔍 Enable Vulnerability Mapping? (current: %t, true/false): ", config.VulnMapping))
			config.VulnMapping = tempBool
		case 10:
			tempBool = askForBool(fmt.Sprintf("🌐 Enable Topology Mapping? (current: %t, true/false): ", config.TopologyMapping))
			config.TopologyMapping = tempBool
		case 11: config.NVDAPIKey = askForString("🔑 New NVD API Key (current: " + maskAPIKey(config.NVDAPIKey) + "): ")
		case 12: config.NmapResultsFile = askForString("📁 New Nmap Results File Path (Import) (current: " + config.NmapResultsFile + "): ")
		case 13:
			tempBool = askForBool(fmt.Sprintf("🎯 Display Only Open Ports? (current: %t, true/false): ", config.OnlyOpenPorts))
			config.OnlyOpenPorts = tempBool
		case 14: config.CVEPluginFile = askForString("📄 New Custom CVE Plugin File Path (current: " + config.CVEPluginFile + "): ")
		case 15:
			tempBool = askForBool(fmt.Sprintf("📡 Enable TCP Ping Sweep? (current: %t, true/false): ", config.PingSweep))
			config.PingSweep = tempBool
		case 16: config.PingSweepPorts = askForString(fmt.Sprintf("🎯 New Ping Sweep Ports (current: %s): ", config.PingSweepPorts))
		case 17: 
			tempStr = askForString(fmt.Sprintf("⏱️ New Ping Sweep Timeout (ms) (current: %d): ", config.PingSweepTimeout))
			if val, err := strconv.Atoi(tempStr); err == nil && val > 0 { config.PingSweepTimeout = val }
		case 18:
			tempBool = askForBool(fmt.Sprintf("🏷️ Enable MAC Address Lookup? (current: %t, true/false): ", config.EnableMACLookup))
			config.EnableMACLookup = tempBool
		case 19: 
			config.ProbeFiles = askForString(fmt.Sprintf("🧬 New Probe Definition Files (comma-separated, current: %s): ", config.ProbeFiles))
			// Re-initialize probe engine if files change
			var probeFilePaths []string
			if config.ProbeFiles != "" {
				probeFilePaths = strings.Split(config.ProbeFiles, ",")
				for i, p := range probeFilePaths { probeFilePaths[i] = strings.TrimSpace(p) }
			}
			newInstance, err := NewProbeEngine(probeFilePaths...)
			if err != nil {
				fmt.Fprintf(os.Stderr, "❌ Error re-initializing Probe Engine with new files: %v. Using previous/basic detection.\n", err)
			} else {
				probeEngineInstance = newInstance
				fmt.Println("✅ Probe Engine re-initialized with new probe files.")
			}
		case 0: return
		default: fmt.Println("❌ Invalid choice.")
		}
	}
}


func LookupMACVendor(macAddr string) string {
	if macAddr == "" {
		return ""
	}
	mac, err := net.ParseMAC(macAddr)
	if err != nil {
		return ""
	}
	ouiPrefix := fmt.Sprintf("%02X:%02X:%02X", mac[0], mac[1], mac[2])
	vendor, found := ouiData[strings.ToUpper(ouiPrefix)]
	if found {
		return vendor
	}
	return "Unknown Vendor"
}

func AttemptToGetMACAddress(ipAddr string, timeout time.Duration) string {
	var cmd *exec.Cmd
	var arpOutput []byte
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	quickDialTimeout := 50 * time.Millisecond
	if timeout < quickDialTimeout {
		quickDialTimeout = timeout / 2
		if quickDialTimeout < 10*time.Millisecond {
			quickDialTimeout = 10 * time.Millisecond
		}
	}
	tempConn, _ := net.DialTimeout("tcp", net.JoinHostPort(ipAddr, "80"), quickDialTimeout)
	if tempConn != nil {
		tempConn.Close()
	}

	switch runtime.GOOS {
	case "linux", "darwin":
		cmd = exec.CommandContext(ctx, "arp", "-n", ipAddr)
	case "windows":
		cmd = exec.CommandContext(ctx, "arp", "-a", ipAddr)
	default:
		return ""
	}

	arpOutput, err = cmd.Output()
	if err != nil {
		return ""
	}

	outputStr := string(arpOutput)
	lines := strings.Split(outputStr, "\n")
	macRegex := regexp.MustCompile(`([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
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
					fmt.Fprintf(os.Stderr, "⚠️  Warning: Invalid port range values in '%s'.\n", r)
				}
			} else {
				fmt.Fprintf(os.Stderr, "⚠️  Warning: Invalid port range format '%s'.\n", r)
			}
		} else {
			port, err := strconv.Atoi(r)
			if err == nil && port > 0 && port <= 65535 {
				if !seen[port] {
					ports = append(ports, port)
					seen[port] = true
				}
			} else {
				fmt.Fprintf(os.Stderr, "⚠️  Warning: Invalid port number '%s'.\n", r)
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
			fmt.Fprintf(os.Stderr, "❌ Error opening target file '%s': %v\n", targetFile, err)
		} else {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					tempTargets = append(tempTargets, line)
				}
			}
			if err := scanner.Err(); err != nil {
				fmt.Fprintf(os.Stderr, "❌ Error reading target file '%s': %v\n", targetFile, err)
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
		fmt.Printf("📊 Total unique targets to process: %d\n", len(parsedTargets))
	}
	return parsedTargets
}

func parseSingleTarget(target string) []string {
	target = strings.TrimSpace(target)
	if strings.Contains(target, "/") {
		ip, ipnet, err := net.ParseCIDR(target)
		if err != nil {
			if parsedIP := net.ParseIP(target); parsedIP != nil {
				return []string{parsedIP.String()}
			}
			return []string{target}
		}

		var ips []string
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
			ips = append(ips, ip.String())
			if len(ips) >= 131072 {
				fmt.Fprintf(os.Stderr, "⚠️  CIDR %s too large, limiting to %d IPs.\n", target, len(ips))
				break
			}
		}
		ones, bits := ipnet.Mask.Size()
		if bits == 32 && ones > 0 && ones < 31 && len(ips) >= 2 {
			if ips[0] == ipnet.IP.Mask(ipnet.Mask).String() {
				ips = ips[1:]
			}
			if len(ips) > 0 {
				broadcastIP := make(net.IP, len(ipnet.IP))
				for i := range ipnet.IP {
					broadcastIP[i] = ipnet.IP[i] | ^ipnet.Mask[i]
				}
				if ips[len(ips)-1] == broadcastIP.String() {
					ips = ips[:len(ips)-1]
				}
			}
		}
		return ips
	}
	if parsedIP := net.ParseIP(target); parsedIP != nil {
		return []string{parsedIP.String()}
	}
	return []string{target}
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func isHostAliveTCP(host string, ports []int, timeout time.Duration) bool {
	if len(ports) == 0 {
		return true
	}

	var wgHostPing sync.WaitGroup
	aliveChan := make(chan bool, 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, port := range ports {
		wgHostPing.Add(1)
		go func(p int) {
			defer wgHostPing.Done()
			dialCtx, dialCancel := context.WithTimeout(ctx, timeout)
			defer dialCancel()

			dialer := net.Dialer{}
			conn, err := dialer.DialContext(dialCtx, "tcp", fmt.Sprintf("%s:%d", host, p))
			if err == nil {
				conn.Close()
				select {
				case aliveChan <- true:
				default:
				}
				cancel()
			}
		}(port)
	}

	go func() {
		wgHostPing.Wait()
		select {
		case aliveChan <- false:
		default:
		}
	}()

	return <-aliveChan
}

func getUDPProbe(port int) []byte {
	switch port {
	case 53:
		return []byte{
			0xAA, 0xBB, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
			0x00, 0x01, 0x00, 0x01,
		}
	case 123:
		return []byte{0x1B, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	case 161:
		return []byte{
			0x30, 0x26, 0x02, 0x01, 0x00,
			0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',
			0xA0, 0x19,
			0x02, 0x04, 0x01, 0x02, 0x03, 0x04,
			0x02, 0x01, 0x00,
			0x02, 0x01, 0x00,
			0x30, 0x0B,
			0x30, 0x09, 0x06, 0x05, 0x2B, 0x06, 0x01, 0x02, 0x01,
			0x05, 0x00,
		}
	default:
		return []byte(APP_NAME + "UDPDiscovery")
	}
}

func isCommonUDPPort(port int) bool {
	common := []int{53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 1900, 4500, 5353}
	for _, p := range common {
		if p == port {
			return true
		}
	}
	return false
}

func guessOS(result *EnhancedScanResult) string {
	currentGuess := result.OSGuess
	if currentGuess == "" {
		currentGuess = "Unknown"
	}

	serviceLower := strings.ToLower(result.Service)
	versionLower := strings.ToLower(result.Version)
	macVendorLower := strings.ToLower(result.MACVendor)

	if macVendorLower != "" && macVendorLower != "unknown vendor" {
		if strings.Contains(macVendorLower, "vmware") { return "Virtual Machine (VMware)" }
		if strings.Contains(macVendorLower, "oracle") && (strings.Contains(macVendorLower, "virtualbox") || result.Service == "virtualbox") { return "Virtual Machine (VirtualBox)" }
		if strings.Contains(macVendorLower, "microsoft corporation") && (currentGuess == "Unknown" || currentGuess == "Windows (Port Hint)" || currentGuess == "Dell Hardware" || currentGuess == "HP Hardware") { currentGuess = "Windows (Microsoft NIC)" }
		if strings.Contains(macVendorLower, "apple") { return "Apple Device (macOS/iOS)" }
		if strings.Contains(macVendorLower, "raspberry pi") { return "Linux (Raspberry Pi)" }
		if strings.Contains(macVendorLower, "cisco") { currentGuess = "Network Device (Cisco)" }
		if strings.Contains(macVendorLower, "juniper") { currentGuess = "Network Device (Juniper)" }
		if strings.Contains(macVendorLower, "arista") { currentGuess = "Network Device (Arista)" }
		if strings.Contains(macVendorLower, "dell") && (currentGuess == "Unknown" || strings.HasPrefix(currentGuess, "Windows (Port Hint)")) { currentGuess = "Dell Hardware" }
		if strings.Contains(macVendorLower, "hewlett packard") || strings.Contains(macVendorLower, "hp enterprise") { currentGuess = "HP Hardware" }
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
		if strings.Contains(vl, "esxi") || strings.Contains(vl, "vmware esxi") {return "VMware ESXi (SNMP)"}
		if len(vl) > 5 && (currentGuess == "Unknown" || currentGuess == "Windows (Port Hint)" || strings.HasPrefix(currentGuess, "Device (") || strings.HasSuffix(currentGuess, "Hardware")) {
			currentGuess = "Device (SNMP: " + truncateString(result.Version, 20) + ")"
		}
	}
	if strings.Contains(serviceLower, "http") || result.ALPNProtocol == "http/1.1" || result.ALPNProtocol == "h2" {
		if strings.Contains(versionLower, "iis") || strings.Contains(versionLower, "microsoft-httpapi") { currentGuess = "Windows (IIS)" }
		else if strings.Contains(versionLower, "apache") { 
			if strings.Contains(versionLower, "win32")||strings.Contains(versionLower,"win64"){ currentGuess = "Windows (Apache)"
			} else if (currentGuess == "Unknown" || currentGuess == "Windows (Port Hint)") { currentGuess = "Linux/Unix (Apache)" }
		} else if strings.Contains(versionLower, "nginx") && (currentGuess == "Unknown" || currentGuess == "Windows (Port Hint)") { currentGuess = "Linux/Unix (Nginx)" }
	}
	if strings.Contains(serviceLower, "ssh") {
		if strings.Contains(versionLower, "openssh") {
			if strings.Contains(versionLower, "windows") { currentGuess = "Windows (OpenSSH)"
			} else if (currentGuess == "Unknown" || currentGuess == "Windows (Port Hint)" || strings.HasPrefix(currentGuess, "Device (") || strings.HasSuffix(currentGuess, "Hardware")) { currentGuess = "Linux/Unix (OpenSSH)" }
		} else if strings.Contains(versionLower, "dropbear") { currentGuess = "Linux/Embedded (Dropbear)" }
	}
	if serviceLower == "ms-wbt-server" || serviceLower == "rdp" { currentGuess = "Windows (RDP)" }
	if serviceLower == "microsoft-ds" || serviceLower == "netbios-ssn" { 
		if (currentGuess == "Unknown" || currentGuess == "Windows (Port Hint)" || strings.HasPrefix(currentGuess, "Device (") || strings.HasSuffix(currentGuess, "Hardware")) { currentGuess = "Windows (SMB)" }
	}
	if serviceLower == "winrm" || strings.Contains(serviceLower, "ws-management") { currentGuess = "Windows (WinRM)" }
	
	if currentGuess == "Unknown" {
		switch result.Port {
		case 135,139,445,3389,5985,5986: currentGuess = "Windows (Port Hint)"
		}
	} else if currentGuess == "Dell Hardware" || currentGuess == "HP Hardware" || currentGuess == "Windows (Microsoft NIC)" {
		isWindowsService := serviceLower == "ms-wbt-server" || serviceLower == "rdp" || 
							serviceLower == "microsoft-ds" || serviceLower == "netbios-ssn" || 
							serviceLower == "winrm" || (strings.Contains(serviceLower, "http") && (strings.Contains(versionLower, "iis") || strings.Contains(versionLower, "microsoft-httpapi")))
		if isWindowsService { currentGuess = "Windows" }
	}
	return currentGuess
}

func queryNVD(cpe string) ([]string, error) {
	if err := limiter.Wait(context.Background()); err != nil { return nil, fmt.Errorf("rate limiter error: %w", err) }
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=%s&resultsPerPage=100", cpe)
	req, err := http.NewRequest("GET", url, nil); if err != nil { return nil, fmt.Errorf("failed to create NVD API request: %w", err) }
	req.Header.Set("User-Agent", APP_NAME+"/"+VERSION)
	currentRateLimit := limiter.Limit()
	if config.NVDAPIKey != "" {
		req.Header.Set("apiKey", config.NVDAPIKey)
		if currentRateLimit < 1 { limiter.SetLimit(rate.Every(30*time.Second/50)); limiter.SetBurst(50) }
	} else {
		if currentRateLimit > (rate.Every(30*time.Second/5)+0.01) { limiter.SetLimit(rate.Every(30*time.Second/5)); limiter.SetBurst(5) }
	}
	var cves []string; maxRetries := 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		resp, err := httpClient.Do(req)
		if err != nil { if attempt == maxRetries-1 { return nil, fmt.Errorf("NVD request failed after %d retries: %w", maxRetries, err) }; time.Sleep(time.Duration(math.Pow(2,float64(attempt)))*time.Second); continue }
		body, readErr := io.ReadAll(resp.Body); resp.Body.Close(); if readErr != nil { return nil, fmt.Errorf("failed to read NVD API response body: %w", readErr) }
		switch resp.StatusCode {
		case http.StatusOK:
			var nvdResp struct{Vulnerabilities []struct{CVE struct{ID string `json:"id"`} `json:"cve"`} `json:"vulnerabilities"`}
			if err := json.Unmarshal(body, &nvdResp); err != nil { return nil, fmt.Errorf("failed to parse NVD JSON response: %w. Body: %s", err, string(body)) }
			for _, vuln := range nvdResp.Vulnerabilities { cves = append(cves, vuln.CVE.ID) }; return cves, nil
		case http.StatusNotFound: return []string{}, nil
		case http.StatusForbidden: errorMsg:="NVD API request forbidden (403)"; if config.NVDAPIKey==""{errorMsg+=" - an NVD API key is recommended."}else{errorMsg+=" - check key/quota."}; return nil, fmt.Errorf("%s Response: %s", errorMsg, string(body))
		case http.StatusTooManyRequests:
			retryAfterStr := resp.Header.Get("Retry-After"); waitTime := time.Duration(math.Pow(2,float64(attempt+1)))*time.Second
			if retryAfterSec, errConv := strconv.Atoi(retryAfterStr); errConv == nil { waitTime = time.Duration(retryAfterSec)*time.Second }
			if waitTime > 60*time.Second { waitTime = 60*time.Second }
			fmt.Fprintf(os.Stderr, "⏳ NVD API rate limit hit (status %d). Waiting %v before retry %d/%d for %s\n", resp.StatusCode, waitTime, attempt+1, maxRetries, cpe)
			time.Sleep(waitTime); if attempt == maxRetries-1 { return nil, fmt.Errorf("NVD rate limit exceeded after %d retries for %s. Body: %s", maxRetries, cpe, string(body)) }; continue
		default: if attempt == maxRetries-1 { return nil, fmt.Errorf("NVD API returned error %d for %s after %d retries. Body: %s", resp.StatusCode, cpe, maxRetries, string(body)) }; time.Sleep(time.Duration(math.Pow(2,float64(attempt)))*time.Second)
		}
	}
	return nil, fmt.Errorf("NVD query failed after maximum retries for %s", cpe)
}

func findSimilarKey(key string) string {
	parts := strings.Fields(strings.ToLower(key)); if len(parts)<1{return ""}; serviceName:=parts[0]; var bestMatch string; highestSimilarity:=-1
	for dbKey:=range vulnDB{dbKeyLower:=strings.ToLower(dbKey); dbParts:=strings.Fields(dbKeyLower); if len(dbParts)<1{continue}; dbServiceName:=dbParts[0]; currentSimilarity:=0; if serviceName==dbServiceName{currentSimilarity+=10}; if currentSimilarity>highestSimilarity{highestSimilarity=currentSimilarity; bestMatch=dbKey}}
	if highestSimilarity>=10{return bestMatch}; return ""
}

func loadCustomCVEs() {
	if config.CVEPluginFile==""{return}; file,err:=os.Open(config.CVEPluginFile); if err!=nil{fmt.Fprintf(os.Stderr, "❌ Error opening CVE plugin file '%s': %v\n",config.CVEPluginFile,err);return}; defer file.Close()
	data,err:=io.ReadAll(file); if err!=nil{fmt.Fprintf(os.Stderr, "❌ Error reading content of CVE plugin file '%s': %v\n",config.CVEPluginFile,err);return}
	if err:=json.Unmarshal(data,&customCVEs);err!=nil{fmt.Fprintf(os.Stderr, "❌ Error parsing JSON from CVE plugin file '%s': %v\n",config.CVEPluginFile,err);return}
	fmt.Printf("✅ Loaded %d custom CVE mappings from %s\n",len(customCVEs),config.CVEPluginFile)
}

func runUltraFastScan() []EnhancedScanResult {
	fmt.Println("🚀 Starting Network Scan...")
	results = nil; atomic.StoreInt64(&scannedPorts, 0)
	initialHosts := parseTargets(config.TargetHost, config.TargetFile)
	if len(initialHosts) == 0 { fmt.Println("❌ No valid targets."); return nil }
	var liveHosts []string
	if config.PingSweep {
		fmt.Println("🔎 Performing TCP Ping Sweep...")
		pingPortsToTry := parsePortRange(config.PingSweepPorts)
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
	if len(portsToScan)==0{fmt.Println("❌ No valid ports for scan."); return nil}; if len(hostsToScan)==0{fmt.Println("❌ No live hosts to scan."); return nil}
	totalScansPerProtocol := int64(len(hostsToScan)*len(portsToScan)); totalOperations := totalScansPerProtocol; if config.UDPScan{totalOperations*=2}
	fmt.Printf("📊 Port Scanning %d live hosts on %d ports. Total operations: ~%d\n", len(hostsToScan), len(portsToScan), totalOperations)
	if totalOperations == 0 {fmt.Println("ℹ️ No scan operations to perform."); return nil}
	if totalOperations > 50000 && len(hostsToScan)>10 {fmt.Fprintf(os.Stderr, "⚠️ This is a large scan involving ~%d operations. It might take a while.\n",totalOperations); if !askForBool("Do you want to continue? (y/N): "){fmt.Println("❌ Scan cancelled by user.");return nil}}
	sem = make(chan struct{}, config.MaxConcurrency); startScanTime := time.Now()
	scanProgressTicker := time.NewTicker(1*time.Second); var displayMutexScan sync.Mutex; scanDoneSignal := make(chan bool)
	go func(){for{select{case <-scanProgressTicker.C: current:=atomic.LoadInt64(&scannedPorts); if totalOperations==0{continue}; if current > 0 { percentage:=float64(current)/float64(totalOperations)*100; elapsed:=time.Since(startScanTime);rate:=0.0;if elapsed.Seconds()>0{rate=float64(current)/elapsed.Seconds()}; var eta time.Duration; if rate>0&&current<totalOperations{eta=time.Duration(float64(totalOperations-current)/rate)*time.Second}; mutex.Lock();foundOpenCount:=len(results);mutex.Unlock(); displayMutexScan.Lock();fmt.Printf("\r\033[K🔍 Port Scan: %d/%d (%.1f%%) | Rate: %.0f ops/s | ETA: %v | Open/Found: %d",current,totalOperations,percentage,rate,eta.Round(time.Second),foundOpenCount);displayMutexScan.Unlock()}
	case <-scanDoneSignal: return}}}()
	commonPorts := []int{80,443,21,22,23,25,53,110,135,139,143,445,993,995,1723,3306,3389,5900,5985,8080}; priorityPorts,regularPorts := []int{},[]int{}; portSet:=make(map[int]bool); for _,p:=range portsToScan{portSet[p]=true}; for _,p:=range commonPorts{if portSet[p]{priorityPorts=append(priorityPorts,p);delete(portSet,p)}}; for p:=range portSet{regularPorts=append(regularPorts,p)}; orderedPorts:=append(priorityPorts,regularPorts...)
	for _,host := range hostsToScan { for _,port := range orderedPorts { wg.Add(1); go scanPortWithRecovery(host,port,&displayMutexScan) }}
	wg.Wait(); scanDoneSignal<-true; scanProgressTicker.Stop(); time.Sleep(150*time.Millisecond)
	finalScannedCount:=atomic.LoadInt64(&scannedPorts); if finalScannedCount>totalOperations{finalScannedCount=totalOperations}; mutex.Lock();finalOpenCount:=len(results);mutex.Unlock()
	displayMutexScan.Lock();fmt.Printf("\r\033[K🔍 Port Scan Complete: %d/%d operations performed. Found %d open/interesting ports/services.\n",finalScannedCount,totalOperations,finalOpenCount);displayMutexScan.Unlock()
	elapsedScanTime:=time.Since(startScanTime); fmt.Printf("✅ Port scan finished in %v\n",elapsedScanTime.Round(time.Second))
	if totalOperations>0&&elapsedScanTime.Seconds()>0{fmt.Printf("⚡ Average scan rate: %.0f ops/s\n",float64(finalScannedCount)/elapsedScanTime.Seconds())}
	if finalOpenCount>0{serviceCount:=make(map[string]int); for _,res:=range results{if strings.ToLower(res.State)=="open"||strings.Contains(strings.ToLower(res.State),"open|filtered"){serviceKey:=res.Service;if serviceKey==""{serviceKey="unknown_service"};serviceCount[serviceKey]++}}; if len(serviceCount)>0{fmt.Println("🎯 Top discovered services from open/open|filtered ports:"); for service,count:=range serviceCount{fmt.Printf("    %s: %d\n",service,count)}}}
	return results
}

func scanPortWithRecovery(host string, port int, displayMutex *sync.Mutex) {
	defer wg.Done(); defer func() { if r:=recover();r!=nil{displayMutex.Lock();fmt.Fprintf(os.Stderr, "\n❌ CRITICAL PANIC during scan of %s:%d: %v. Recovered.\n",host,port,r);displayMutex.Unlock()}; <-sem }()
	sem <- struct{}{}
	if resultTCP := scanTCPPort(host, port); resultTCP != nil {
		if config.EnableMACLookup { parsedIP:=net.ParseIP(host); if parsedIP!=nil && (parsedIP.IsPrivate()||parsedIP.IsLinkLocalUnicast()||parsedIP.IsLoopback()){ mac:=AttemptToGetMACAddress(host,250*time.Millisecond); if mac!=""{ resultTCP.MACAddress=mac; resultTCP.MACVendor=LookupMACVendor(mac); resultTCP.OSGuess = guessOS(resultTCP) }}}
		mutex.Lock(); results=append(results,*resultTCP); mutex.Unlock()
		displayMutex.Lock(); fmt.Printf("\r\033[K✅ TCP Open: %s:%d (%s %s)\n",host,port,resultTCP.Service,resultTCP.Version); displayMutex.Unlock()
	}
	atomic.AddInt64(&scannedPorts,1)
	if config.UDPScan {
		if resultUDP := scanUDPPort(host, port); resultUDP != nil {
			if config.EnableMACLookup { parsedIP:=net.ParseIP(host); if parsedIP!=nil && (parsedIP.IsPrivate()||parsedIP.IsLinkLocalUnicast()||parsedIP.IsLoopback()){ mac:=AttemptToGetMACAddress(host,250*time.Millisecond); if mac!=""{ resultUDP.MACAddress=mac; resultUDP.MACVendor=LookupMACVendor(mac); resultUDP.OSGuess = guessOS(resultUDP) }}}
			mutex.Lock(); results=append(results,*resultUDP); mutex.Unlock()
			displayMutex.Lock(); fmt.Printf("\r\033[K✅ UDP Open/Filtered: %s:%d (%s %s)\n",host,port,resultUDP.Service,resultUDP.Version); displayMutex.Unlock()
		}
		atomic.AddInt64(&scannedPorts,1)
	}
}

func validateConfig() bool {
	fmt.Println("🔧 Validating configuration...")
	isValid := true
	if config.TargetHost == "" && config.TargetFile == "" {
		fmt.Fprintf(os.Stderr, "❌ Configuration Error: No target host or target file specified.\n")
		isValid = false
	}
	if len(parsePortRange(config.PortRange)) == 0 && config.NmapResultsFile == "" {
		fmt.Fprintf(os.Stderr, "❌ Configuration Error: No port range specified and not parsing Nmap results.\n")
		isValid = false
	}
	if config.TargetFile != "" {
		if _, err := os.Stat(config.TargetFile); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "❌ Configuration Error: Target file '%s' does not exist.\n", config.TargetFile)
			isValid = false
		}
	}
	if config.ScanTimeout < 50 || config.ScanTimeout > 10000 {
		fmt.Fprintf(os.Stderr, "⚠️ Configuration Warning: Scan connect timeout (%dms) is outside recommended range (50-10000ms).\n", config.ScanTimeout)
	}
	if config.ServiceDetectTimeout < 50 || config.ServiceDetectTimeout > 10000 {
		fmt.Fprintf(os.Stderr, "⚠️ Configuration Warning: Service Detect timeout (%dms) is outside recommended range (50-10000ms).\n", config.ServiceDetectTimeout)
	}
	if config.MaxConcurrency < 1 || config.MaxConcurrency > 10000 {
		fmt.Fprintf(os.Stderr, "⚠️ Configuration Warning: Max concurrency (%d) is outside recommended range (1-10000).\n", config.MaxConcurrency)
	}
	if config.PingSweep {
		if len(parsePortRange(config.PingSweepPorts)) == 0 {
			fmt.Fprintf(os.Stderr, "❌ Configuration Error: Ping sweep enabled, but no valid ping sweep ports are specified.\n")
			isValid = false
		}
		if config.PingSweepTimeout <= 0 {
			fmt.Fprintf(os.Stderr, "❌ Configuration Error: Ping sweep enabled, but ping sweep timeout (%dms) is invalid (must be > 0).\n", config.PingSweepTimeout)
			isValid = false
		}
	}
	if config.VulnMapping && config.NVDAPIKey == "" {
		fmt.Fprintf(os.Stderr, "⚠️ Configuration Warning: Vulnerability mapping enabled, but NVD API key is not set. NVD lookups will be severely rate-limited or may fail.\n")
	}
	if isValid { fmt.Println("✅ Configuration seems OK.")
	} else { fmt.Fprintf(os.Stderr, "❌ Configuration validation failed. Please check settings using option '2' or command-line flags.\n") }
	return isValid
}

func debugCIDRParsing(cidr string) {
	fmt.Printf("🔍 Debugging CIDR/Target Parsing for: '%s'\n", cidr)
	ips := parseSingleTarget(cidr)
	fmt.Printf("📊 Found %d IP(s) after parsing:\n", len(ips))
	displayCount := len(ips)
	if displayCount > 20 { displayCount = 20 }
	for i := 0; i < displayCount; i++ { fmt.Printf("  %d: %s\n", i+1, ips[i]) }
	if len(ips) > 20 { fmt.Printf("  ... and %d more IPs (not shown).\n", len(ips)-20) }
}

func parseNmapResults() {
	if config.NmapResultsFile == "" {
		config.NmapResultsFile = askForString("📁 Enter path to Nmap XML results file: ")
		if config.NmapResultsFile == "" { fmt.Println("❌ No Nmap XML file specified. Aborting parse."); return }
	}
	file, err := os.Open(config.NmapResultsFile); if err != nil { fmt.Fprintf(os.Stderr, "❌ Error opening Nmap XML file '%s': %v\n", config.NmapResultsFile, err); return }; defer file.Close()
	data, err := io.ReadAll(file); if err != nil { fmt.Fprintf(os.Stderr, "❌ Error reading Nmap XML file '%s': %v\n", config.NmapResultsFile, err); return }
	var nmapRun NmapRun; if err := xml.Unmarshal(data, &nmapRun); err != nil { fmt.Fprintf(os.Stderr, "❌ Error parsing Nmap XML data from '%s': %v\n", config.NmapResultsFile, err); return }
	newResults := []EnhancedScanResult{}; parsedCount := 0
	for _, host := range nmapRun.Hosts {
		var hostIP, hostMAC, macVendor string
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" { hostIP = addr.Addr }
			if addr.AddrType == "ipv6" && hostIP == "" { hostIP = addr.Addr }
			if addr.AddrType == "mac" { hostMAC = addr.Addr; if addr.Vendor != "" { macVendor = addr.Vendor } }
		}
		if hostIP == "" { continue }
		for _, portEntry := range host.Ports.Ports {
			isConsideredOpen := strings.ToLower(portEntry.State.State) == "open" || (portEntry.Protocol == "udp" && strings.Contains(strings.ToLower(portEntry.State.State), "open|filtered"))
			if !config.OnlyOpenPorts || isConsideredOpen {
				result := EnhancedScanResult{Host: hostIP, Port: portEntry.PortID, Protocol: portEntry.Protocol, State: portEntry.State.State, Service: portEntry.Service.Name, Version: strings.TrimSpace(portEntry.Service.Version), Timestamp: time.Now().UTC(), DetectionConfidence: 75} 
				if hostMAC != "" { result.MACAddress = strings.ToUpper(hostMAC); if macVendor != "" { result.MACVendor = macVendor } else { result.MACVendor = LookupMACVendor(result.MACAddress) } }
				result.OSGuess = guessOS(&result); newResults = append(newResults, result); parsedCount++
			}
		}
	}
	results = newResults
	fmt.Printf("✅ Successfully parsed %d port entries from Nmap file '%s' (Filter 'OnlyOpenPorts': %t)\n", parsedCount, config.NmapResultsFile, config.OnlyOpenPorts)
	if len(results) > 0 {
		displayResults()
		if config.VulnMapping { if askForBool("🔍 Perform vulnerability mapping on these Nmap results? (y/N): ") { performVulnerabilityMapping() } }
	} else { fmt.Println("ℹ️ No ports matching the criteria were found in the Nmap file.") }
}

func mapVulnerabilities(result *EnhancedScanResult) {
	if !config.VulnMapping { return }
	serviceKey := strings.ToLower(strings.TrimSpace(result.Service)); versionKey := strings.TrimSpace(result.Version)
	productKey := fmt.Sprintf("%s %s", result.Service, result.Version)
	if cves, found := customCVEs[productKey]; found { result.Vulnerabilities = cves; return }
	lowerServiceProductKey := fmt.Sprintf("%s %s", serviceKey, strings.ToLower(versionKey))
	if cves, found := customCVEs[lowerServiceProductKey]; found { result.Vulnerabilities = cves; return }
	
	if versionKey == "" || versionKey == "unknown" || strings.HasPrefix(versionKey, "banner:") || serviceKey == "" || serviceKey == "unknown" {
		result.Vulnerabilities = []string{"Version/Service too generic - NVD skip"}
		return
	}
	cpeInfo, cpeMapExists := serviceToCPE[serviceKey]
	if !cpeMapExists { 
		if strings.Contains(serviceKey, "apache") && (strings.Contains(serviceKey, "httpd") || serviceKey == "http" || serviceKey == "https" || serviceKey == "http/2") {
			cpeInfo = struct{ Vendor, Product string }{"apache", "http_server"}; cpeMapExists = true
		} else if strings.Contains(serviceKey, "openssh") {
			cpeInfo = struct{ Vendor, Product string }{"openssh", "openssh"}; cpeMapExists = true
		} else if strings.Contains(serviceKey, "nginx") {
			cpeInfo = struct{ Vendor, Product string }{"nginx", "nginx"}; cpeMapExists = true
		} else if strings.Contains(serviceKey, "mysql") {
			cpeInfo = struct{ Vendor, Product string }{"oracle", "mysql"}; cpeMapExists = true
		} else if strings.Contains(serviceKey, "postgresql") {
            cpeInfo = struct{ Vendor, Product string }{"postgresql", "postgresql"}; cpeMapExists = true
        } else if strings.Contains(serviceKey, "mongodb") {
            cpeInfo = struct{ Vendor, Product string }{"mongodb", "mongodb"}; cpeMapExists = true
        } else if strings.Contains(serviceKey, "redis") {
            cpeInfo = struct{ Vendor, Product string }{"redis", "redis"}; cpeMapExists = true
        } else {
			result.Vulnerabilities = []string{fmt.Sprintf("Service '%s' not in CPE map for NVD", result.Service)}
			return
		}
	}
	cpeVersion := versionKey
	if strings.HasPrefix(strings.ToLower(versionKey), cpeInfo.Product+" ") {
		cpeVersion = strings.TrimPrefix(strings.ToLower(versionKey), cpeInfo.Product+" ")
	}
	if idx := strings.Index(cpeVersion, " "); idx != -1 { cpeVersion = cpeVersion[:idx] }
	if idx := strings.Index(cpeVersion, "("); idx != -1 { cpeVersion = cpeVersion[:idx] }
	cpeVersion = strings.TrimSuffix(cpeVersion, "-patch")

	cpeString := fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", cpeInfo.Vendor, cpeInfo.Product, strings.ToLower(cpeVersion))
	nvdCacheKey := cpeString
	if cachedVulns, found := nvdCache.Load(nvdCacheKey); found {
		if cvs, ok := cachedVulns.([]string); ok { result.Vulnerabilities = cvs; return }
	}
	nvdCVEs, err := queryNVD(cpeString); if err != nil { result.Vulnerabilities = []string{fmt.Sprintf("NVD lookup error: %s", err.Error())}; nvdCache.Store(nvdCacheKey, result.Vulnerabilities); return }
	nvdCache.Store(nvdCacheKey, nvdCVEs)
	if len(nvdCVEs) > 0 { result.Vulnerabilities = nvdCVEs
	} else {
		fuzzyKey := fmt.Sprintf("%s %s", result.Service, versionKey)
		if similar := findSimilarKey(fuzzyKey); similar != "" {
			if localCVEs, found := vulnDB[similar]; found { result.Vulnerabilities = append([]string{"(Local DB Match):"}, localCVEs...); return }
		}
		result.Vulnerabilities = []string{"No known vulnerabilities found (NVD/Local DB)"}
	}
}

func performVulnerabilityMapping() {
	if len(results) == 0 { fmt.Println("❌ No results for vuln map."); return }
	if !config.VulnMapping { fmt.Println("ℹ️ Vuln mapping disabled."); return }
	if config.NVDAPIKey == "" { fmt.Println("⚠️ NVD API Key missing."); if !askForBool("Continue vuln map without NVD API key? (y/N): ") { return } }
	fmt.Println("🔍 Mapping vulnerabilities...")
	var mappedCountAtomic int32; var wgVuln sync.WaitGroup; vulnSemMax := 10; if config.NVDAPIKey == "" { vulnSemMax = 2 }; vulnSem := make(chan struct{}, vulnSemMax)
	tempResults := make([]EnhancedScanResult, len(results)); copy(tempResults, results); totalToMap := len(tempResults)
	mapProgressTicker := time.NewTicker(1*time.Second); var displayMutexMap sync.Mutex; mapDoneSignal := make(chan bool)
	go func(){for{select{case <-mapProgressTicker.C:current:=atomic.LoadInt32(&mappedCountAtomic);if totalToMap==0{continue};percentage:=float64(current)/float64(totalToMap)*100;displayMutexMap.Lock();fmt.Printf("\r\033[K🔍 Vuln Mapping: %d/%d (%.1f%%)",current,totalToMap,percentage);displayMutexMap.Unlock()
	case <-mapDoneSignal:return}}}()
	for i := range tempResults {
		isConsideredOpen := strings.ToLower(tempResults[i].State) == "open" || (tempResults[i].Protocol == "udp" && strings.Contains(strings.ToLower(tempResults[i].State), "open|filtered"))
		if isConsideredOpen && tempResults[i].Service != "" && tempResults[i].Service != "unknown" {
			wgVuln.Add(1); go func(idx int){defer wgVuln.Done();vulnSem<-struct{}{};defer func(){<-vulnSem}();mapVulnerabilities(&tempResults[idx]);atomic.AddInt32(&mappedCountAtomic,1)}(i)
		} else { atomic.AddInt32(&mappedCountAtomic,1) }
	}
	wgVuln.Wait(); mapDoneSignal<-true; mapProgressTicker.Stop(); time.Sleep(150*time.Millisecond)
	mutex.Lock(); results=tempResults; mutex.Unlock()
	finalMappedCount:=atomic.LoadInt32(&mappedCountAtomic); displayMutexMap.Lock(); fmt.Printf("\r\033[K✅ Vuln mapping complete for %d results.\n",finalMappedCount); displayMutexMap.Unlock()
	displayResults()
}

func generateTopologyMap() {
	if len(results) == 0 { fmt.Println("❌ No results for topology."); return }
	fmt.Println("🌐 Generating topology map...")
	var dotGraph strings.Builder
	dotGraph.WriteString("digraph NetworkTopology {\n  rankdir=LR;\n  graph [bgcolor=\"#f0f0f0\"];\n  node [shape=Mrecord, style=\"rounded,filled\", fillcolor=\"#E6F5FF\", fontname=\"Arial\", fontsize=10];\n  edge [style=dashed, color=gray40, fontname=\"Arial\", fontsize=9];\n\n")
	dotGraph.WriteString("  subgraph cluster_legend {\n    label=\"Legend\";\n    style=filled;\n    color=lightgrey;\n    node [style=filled, shape=box];\n    Windows_Legend [label=\"Windows Host\", fillcolor=\"#add8e6\"];\n    Linux_Legend [label=\"Linux Host\", fillcolor=\"#90ee90\"];\n    Network_Legend [label=\"Network Device\", fillcolor=\"#f0e68c\"];\n    Unknown_Legend [label=\"Unknown OS Host\", fillcolor=\"#E6F5FF\"];\n  }\n\n")
	hostServices := make(map[string]map[string][]string); hostOSMap := make(map[string]string)
	for _, result := range results {
		isConsideredOpen := strings.ToLower(result.State) == "open" || (result.Protocol == "udp" && strings.Contains(strings.ToLower(result.State), "open|filtered"))
		if isConsideredOpen {
			if _, ok := hostServices[result.Host]; !ok { hostServices[result.Host] = make(map[string][]string) }
			serviceKey := result.Service; if serviceKey == "" || serviceKey == "unknown" { serviceKey = fmt.Sprintf("port_%d", result.Port) }
			portProto := fmt.Sprintf("%d/%s", result.Port, result.Protocol); hostServices[result.Host][serviceKey] = append(hostServices[result.Host][serviceKey], portProto)
			if _, ok := hostOSMap[result.Host]; !ok && result.OSGuess != "" && result.OSGuess != "Unknown" { hostOSMap[result.Host] = result.OSGuess }
		}
	}
	for host, servicesMap := range hostServices {
		var serviceDetails[]string; for service, portsProtos := range servicesMap { serviceDetails = append(serviceDetails, fmt.Sprintf("<%s> %s: %s", sanitizeForDotID(service), service, strings.Join(portsProtos,", "))) }
		nodeID := sanitizeForDotID(host); label := fmt.Sprintf("{ %s | { %s } }", host, strings.Join(serviceDetails," | "))
		nodeColor := "#E6F5FF"; osGuessLower := strings.ToLower(hostOSMap[host])
		if strings.Contains(osGuessLower, "windows") { nodeColor = "#add8e6" }
		if strings.Contains(osGuessLower, "linux") { nodeColor = "#90ee90" }
		if strings.Contains(osGuessLower, "cisco") || strings.Contains(osGuessLower, "juniper") || strings.Contains(osGuessLower, "fortinet") || strings.Contains(osGuessLower, "router") { nodeColor = "#f0e68c" }
		dotGraph.WriteString(fmt.Sprintf("  \"%s\" [id=\"node_%s\" label=\"%s\" fillcolor=\"%s\"];\n", nodeID, nodeID, label, nodeColor))
	}
	dotGraph.WriteString("}\n")
	filename := fmt.Sprintf("%s_topology.dot", strings.ReplaceAll(config.OutputFile, ".", "_"))
	if err := os.WriteFile(filename, []byte(dotGraph.String()), 0644); err != nil { fmt.Fprintf(os.Stderr, "❌ Failed to write topology DOT file '%s': %v\n", filename, err); return }
	fmt.Printf("✅ Network topology map saved to %s\n", filename)
	fmt.Printf("💡 To visualize, use Graphviz: dot -Tpng %s -o %s_topology.png\n", filename, strings.TrimSuffix(filename, ".dot"))
}

func sanitizeForDotID(input string) string {
	sanitized := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' { return r }
		return '_'
	}, input)
	if len(sanitized) > 0 && (sanitized[0] >= '0' && sanitized[0] <= '9') {
		isPurelyNumericOrSimpleVersion := true
		for _, char := range sanitized { if !((char >= '0' && char <= '9') || char == '.') { isPurelyNumericOrSimpleVersion = false; break } }
		if isPurelyNumericOrSimpleVersion { return "p_" + sanitized }
	}
	return sanitized
}

func truncateString(s string, maxLen int) string {
	if len(s) > maxLen { if maxLen > 3 { return s[:maxLen-3] + "..." }; return s[:maxLen] }
	return s
}

func saveResults() {
	mutex.Lock(); defer mutex.Unlock()
	if len(results) == 0 { fmt.Println("❌ No results to save."); return }
	filename := fmt.Sprintf("%s.json", config.OutputFile)
	data, err := json.MarshalIndent(results, "", "  "); if err != nil { fmt.Fprintf(os.Stderr, "❌ Error marshaling results to JSON: %v\n", err); return }
	if err := os.WriteFile(filename, data, 0644); err != nil { fmt.Fprintf(os.Stderr, "❌ Error writing JSON results to file '%s': %v\n", filename, err); return }
	fmt.Printf("✅ JSON results saved to %s\n", filename)
}

func exportResults() {
	mutex.Lock(); currentResults := make([]EnhancedScanResult, len(results)); copy(currentResults, results); mutex.Unlock()
	if len(currentResults) == 0 { fmt.Println("❌ No results to export."); return }
	fmt.Println("📤 Select an export format:\n1. JSON\n2. CSV\n3. XML\n4. HTML")
	fmt.Print("Choose an option (1-4): ")
	choice := getUserChoice()
	switch choice {
	case 1: exportJSON(currentResults)
	case 2: exportCSV(currentResults)
	case 3: exportXML(currentResults)
	case 4: exportHTML(currentResults)
	default: fmt.Println("❌ Invalid export format choice.")
	}
}

func loadConfigFromEnv() {
	if val := os.Getenv("NVD_API_KEY"); val != "" && config.NVDAPIKey == "" { config.NVDAPIKey = val; fmt.Println("ℹ️ Loaded NVD_API_KEY from environment.") }
	if val := os.Getenv("R3COND0G_TARGET_HOST"); val != "" && config.TargetHost == "" { config.TargetHost = val }
	if val := os.Getenv("R3COND0G_TARGET_FILE"); val != "" && config.TargetFile == "" { config.TargetFile = val }
	if val := os.Getenv("R3COND0G_PORTS"); val != "" && config.PortRange == "1-1000" { config.PortRange = val }
	if val := os.Getenv("R3COND0G_OUTPUT"); val != "" && config.OutputFile == "r3cond0g_scan" { config.OutputFile = val }
	if valStr := os.Getenv("R3COND0G_SCAN_TIMEOUT"); valStr != "" { if val, err := strconv.Atoi(valStr); err == nil && val > 0 { config.ScanTimeout = val } }
	if valStr := os.Getenv("R3COND0G_SERVICE_DETECT_TIMEOUT"); valStr != "" { if val, err := strconv.Atoi(valStr); err == nil && val > 0 { config.ServiceDetectTimeout = val } }
	if valStr := os.Getenv("R3COND0G_PING_SWEEP"); valStr != "" { if val, err := strconv.ParseBool(valStr); err == nil { config.PingSweep = val } }
	if val := os.Getenv("R3COND0G_PING_PORTS"); val != "" { config.PingSweepPorts = val }
	if valStr := os.Getenv("R3COND0G_PING_TIMEOUT"); valStr != "" { if val, err := strconv.Atoi(valStr); err == nil && val > 0 { config.PingSweepTimeout = val } }
	if valStr := os.Getenv("R3COND0G_MAC_LOOKUP"); valStr != "" { if val, err := strconv.ParseBool(valStr); err == nil { config.EnableMACLookup = val } }
	if val := os.Getenv("R3COND0G_PROBE_FILES"); val != "" && config.ProbeFiles == "tcp_probes.json,udp_probes.json" { config.ProbeFiles = val }
}

func parseCommandLineFlags() {
	flag.StringVar(&config.TargetHost, "target", config.TargetHost, "Target host(s), CIDR(s), or domain(s), comma-separated")
	flag.StringVar(&config.TargetFile, "target-file", config.TargetFile, "Path to a file containing target hosts/CIDRs/domains")
	flag.StringVar(&config.PortRange, "ports", config.PortRange, "Port range to scan (e.g., 1-1024, 80,443, 22-25)")
	flag.IntVar(&config.ScanTimeout, "timeout", config.ScanTimeout, "Timeout in milliseconds for initial port connection attempts")
	flag.IntVar(&config.ServiceDetectTimeout, "service-timeout", config.ServiceDetectTimeout, "Timeout in milliseconds for the service detection phase (per probe/attempt)")
	flag.IntVar(&config.MaxConcurrency, "concurrency", config.MaxConcurrency, "Maximum number of concurrent scan operations")
	flag.StringVar(&config.OutputFile, "output", config.OutputFile, "Base name for output files (e.g., r3cond0g_scan -> r3cond0g_scan.json)")
	flag.BoolVar(&config.UDPScan, "udp", config.UDPScan, "Enable UDP port scanning")
	flag.BoolVar(&config.VulnMapping, "vuln", config.VulnMapping, "Enable vulnerability mapping using NVD and local databases")
	flag.BoolVar(&config.TopologyMapping, "topology", config.TopologyMapping, "Enable generation of a network topology map (DOT format)")
	flag.StringVar(&config.NVDAPIKey, "nvd-key", config.NVDAPIKey, "NVD API key for vulnerability lookups (or set NVD_API_KEY env var)")
	flag.StringVar(&config.NmapResultsFile, "nmap-file", config.NmapResultsFile, "Path to Nmap XML results file to import and process")
	flag.BoolVar(&config.OnlyOpenPorts, "open-only", config.OnlyOpenPorts, "Display and process only 'open' or 'open|filtered' ports")
	flag.StringVar(&config.CVEPluginFile, "cve-plugin", config.CVEPluginFile, "Path to a custom JSON file for CVE mappings")
	flag.BoolVar(&config.PingSweep, "ping-sweep", config.PingSweep, "Enable TCP ping sweep to find live hosts before port scanning")
	flag.StringVar(&config.PingSweepPorts, "ping-ports", config.PingSweepPorts, "Ports to use for TCP ping sweep (e.g., 80,443,22)")
	flag.IntVar(&config.PingSweepTimeout, "ping-timeout", config.PingSweepTimeout, "Timeout in milliseconds for TCP ping sweep attempts per port")
	flag.BoolVar(&config.EnableMACLookup, "mac-lookup", config.EnableMACLookup, "Attempt MAC address lookup for hosts on the local network (experimental)")
	flag.StringVar(&config.ProbeFiles, "probe-files", config.ProbeFiles, "Comma-separated list of probe definition JSON files (e.g., tcp_probes.json,my_custom_probes.json)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s (Version: %s) by %s\n", strings.ToUpper(APP_NAME), VERSION, AUTHORS)
		fmt.Fprintf(os.Stderr, "An advanced network reconnaissance and service detection tool.\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -target 192.168.1.0/24 -ports 1-1024 -ping-sweep -vuln -mac-lookup\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -target-file hosts.txt -ports 80,443,8000-8080 -udp -output company_scan\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -nmap-file nmap_results.xml -vuln -nvd-key YOUR_NVD_API_KEY\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s (runs in interactive mode if no direct action flags are provided)\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "For NVD API key, visit: https://nvd.nist.gov/developers/request-an-api-key\n")
		fmt.Fprintf(os.Stderr, "Ensure 'tcp_probes.json' and 'udp_probes.json' (or custom specified files via --probe-files) are present for enhanced service detection.\n")
	}
	flag.Parse()
}

func performIPSweepAndSave() {
	fmt.Println("📡 Starting IP Sweep Only mode...")
	if config.TargetHost == "" && config.TargetFile == "" {
		fmt.Println("❌ No targets configured. Please configure targets first (Menu Option 2 or CLI).")
		return
	}

	initialHosts := parseTargets(config.TargetHost, config.TargetFile)
	if len(initialHosts) == 0 {
		fmt.Println("❌ No valid targets found for sweep.")
		return
	}

	var liveHosts []string
	pingPortsToTry := parsePortRange(config.PingSweepPorts)
	if len(pingPortsToTry) == 0 {
		fmt.Println("⚠️ No valid ping ports, defaulting to 80,443.")
		pingPortsToTry = []int{80, 443}
	}
	tcpPingTimeout := time.Duration(config.PingSweepTimeout) * time.Millisecond
	if tcpPingTimeout <= 0 {
		fmt.Println("⚠️ Invalid ping timeout, defaulting to 300ms.")
		tcpPingTimeout = 300 * time.Millisecond
	}

	var pingWg sync.WaitGroup
	var liveHostsMutex sync.Mutex
	pingSemMax := config.MaxConcurrency
	if pingSemMax > 200 { pingSemMax = 200 }
	if pingSemMax <= 0 { pingSemMax = 50 }
	pingSem := make(chan struct{}, pingSemMax)
	fmt.Printf("📡 Pinging %d hosts (ports: %v, timeout: %v, concurrency: %d)...\n", len(initialHosts), pingPortsToTry, tcpPingTimeout, pingSemMax)

	var pingedCountAtomic int64
	totalToPing := len(initialHosts)
	pingProgressTicker := time.NewTicker(1*time.Second)
	var displayMutexPing sync.Mutex
	doneSignal := make(chan bool)
	go func(){for{select{case <-pingProgressTicker.C:current:=atomic.LoadInt64(&pingedCountAtomic);if totalToPing==0{continue};percentage:=float64(current)/float64(totalToPing)*100;liveHostsMutex.Lock();foundLive:=len(liveHosts);liveHostsMutex.Unlock();displayMutexPing.Lock();fmt.Printf("\r\033[K📡 IP Sweep: %d/%d (%.1f%%) | Live: %d",current,totalToPing,percentage,foundLive);displayMutexPing.Unlock()
	case <-doneSignal: return}}}()
	for _,host := range initialHosts { pingWg.Add(1); go func(h string){defer pingWg.Done();pingSem<-struct{}{};defer func(){<-pingSem}(); if isHostAliveTCP(h,pingPortsToTry,tcpPingTimeout){liveHostsMutex.Lock();liveHosts=append(liveHosts,h);liveHostsMutex.Unlock()}; atomic.AddInt64(&pingedCountAtomic,1)}(host)}
	pingWg.Wait(); doneSignal<-true; pingProgressTicker.Stop(); time.Sleep(150*time.Millisecond)
	finalLiveCount := len(liveHosts)
	displayMutexPing.Lock(); fmt.Printf("\r\033[K📡 IP Sweep Complete. Found %d live hosts out of %d.\n",finalLiveCount,totalToPing); displayMutexPing.Unlock()

	if finalLiveCount > 0 {
		fmt.Println("\n📢 Live Hosts Found:"); for i, host := range liveHosts { fmt.Printf("  %d. %s\n", i+1, host) }
		if askForBool("\n💾 Save list of live hosts? (y/N): ") {
			outputFileName := askForString("Filename for live hosts (e.g., live_hosts.txt): "); if outputFileName==""{outputFileName=strings.ToLower(APP_NAME)+"_live_hosts.txt"}
			file, err := os.Create(outputFileName); if err!=nil{fmt.Fprintf(os.Stderr, "❌ Error creating file '%s': %v\n",outputFileName,err);return}; defer file.Close()
			writer := bufio.NewWriter(file); for _,host := range liveHosts {_,_=writer.WriteString(host+"\n")}; writer.Flush()
			fmt.Printf("✅ Live hosts saved to %s\n", outputFileName)
		}
	} else { fmt.Println("ℹ️ No live hosts found in the sweep.") }
}
