package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// Constants
const (
	AppName    = "r3cond0g"
	AppVersion = "1.0.1"
	ConfigDir  = ".r3cond0g"
	ConfigFile = "config.json"
	AuditLog   = "audit.log"
)

// Config holds tool configuration
type Config struct {
	NmapFile     string   `json:"nmap_file"`
	Targets      string   `json:"targets"`
	Ports        string   `json:"ports"`
	Timeout      int      `json:"timeout"`
	OutputFile   string   `json:"output_file"`
	OutputFormat string   `json:"output_format"`
	SniffIface   string   `json:"sniff_iface"`
	SniffFilter  string   `json:"sniff_filter"`
	SniffPcap    string   `json:"sniff_pcap"`
	SniffTimeout int      `json:"sniff_timeout"`
	Threads      int      `json:"threads"`
	Verbose      bool     `json:"verbose"`
	AuthToken    string   `json:"auth_token"`
	AllowedIPs   []string `json:"allowed_ips"`
}

// ScanResult holds parsed scan results
type ScanResult struct {
	IP      string       `json:"ip"`
	Ports   []PortInfo   `json:"ports"`
	Banners map[int]string `json:"banners"`
}

// PortInfo describes an open port
type PortInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
}

// SniffSummary holds packet sniffing results
type SniffSummary struct {
	Interface   string            `json:"interface"`
	Filter      string            `json:"filter"`
	Packets     int               `json:"packets"`
	TCPSummary  map[string]int    `json:"tcp_summary"`
	UDPSummary  map[string]int    `json:"udp_summary"`
	DNSSummary  []string          `json:"dns_summary"`
	HTTPSummary []string          `json:"http_summary"`
	PcapFile    string            `json:"pcap_file"`
	Errors      []string          `json:"errors"`
	StartTime   time.Time         `json:"start_time"`
	EndTime     time.Time         `json:"end_time"`
}

// NmapRun represents Nmap XML structure
type NmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []Host   `xml:"host"`
}

// Host represents a host in Nmap XML
type Host struct {
	Address Address   `xml:"address"`
	Ports   NmapPorts `xml:"ports"`
}

// Address holds IP address
type Address struct {
	Addr string `xml:"addr,attr"`
}

// NmapPorts holds port information
type NmapPorts struct {
	Ports []NmapPort `xml:"port"`
}

// NmapPort represents a port in Nmap XML
type NmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   string      `xml:"portid,attr"`
	State    NmapState   `xml:"state"`
	Service  NmapService `xml:"service"`
}

// NmapState holds port state
type NmapState struct {
	State string `xml:"state,attr"`
}

// NmapService holds service information
type NmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

// Global configuration
var config Config
var auditLogger *log.Logger

// init sets default configuration and audit logging
func init() {
	config.Timeout = 3000
	config.OutputFormat = "text"
	config.Threads = 10
	config.SniffTimeout = 60
	config.Verbose = false

	// Initialize audit logger
	home, err := os.UserHomeDir()
	if err == nil {
		auditPath := filepath.Join(home, ConfigDir, AuditLog)
		f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err == nil {
			auditLogger = log.New(f, "AUDIT: ", log.LstdFlags)
		}
	}
	if auditLogger == nil {
		auditLogger = log.New(os.Stderr, "AUDIT: ", log.LstdFlags)
	}
}

// main is the entry point
func main() {
	// Parse command-line flags
	parseFlags()

	// Load configuration
	loadConfig()

	// Validate authorization
	if !validateAuth() {
		log.Fatal("Error: Invalid or missing authorization token")
	}

	// Validate targets
	if !validateTargets() {
		log.Fatal("Error: Targets not in allowed IP range")
	}

	// Log operation start
	auditLogger.Printf("Operation started: nmap_file=%s, targets=%s, sniff_iface=%s", config.NmapFile, config.Targets, config.SniffIface)

	// Run analysis or sniffing
	if config.NmapFile != "" {
		results := parseNmapResults()
		saveReport(results)
	} else if config.SniffIface != "" {
		summary := runPacketSniffer()
		saveReport(summary)
	} else {
		log.Fatal("Error: Specify Nmap file or sniffing interface")
	}

	// Save configuration
	saveConfig()
	auditLogger.Println("Operation completed")
}

// parseFlags handles command-line arguments
func parseFlags() {
	flag.StringVar(&config.NmapFile, "nmap-file", "", "Path to Nmap XML file")
	flag.StringVar(&config.Targets, "targets", "", "Comma-separated IPs or CIDR")
	flag.StringVar(&config.Ports, "ports", "80,443,22,21", "Comma-separated ports")
	flag.IntVar(&config.Timeout, "timeout", config.Timeout, "Timeout in ms")
	flag.StringVar(&config.OutputFile, "output", "", "Output file prefix")
	flag.StringVar(&config.OutputFormat, "format", config.OutputFormat, "Output format (text, json)")
	flag.StringVar(&config.SniffIface, "sniff-iface", "", "Network interface for sniffing")
	flag.StringVar(&config.SniffFilter, "sniff-filter", "", "BPF filter for sniffing")
	flag.StringVar(&config.SniffPcap, "sniff-pcap", "", "PCAP output file")
	flag.IntVar(&config.SniffTimeout, "sniff-timeout", config.SniffTimeout, "Sniffing duration in seconds")
	flag.IntVar(&config.Threads, "threads", config.Threads, "Concurrent threads")
	flag.BoolVar(&config.Verbose, "verbose", config.Verbose, "Enable verbose logging")
	flag.StringVar(&config.AuthToken, "auth-token", "", "Client authorization token")
	flag.Parse()
}

// loadConfig loads configuration from JSON file
func loadConfig() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	configPath := filepath.Join(home, ConfigDir, ConfigFile)
	data, err := os.ReadFile(configPath)
	if err != nil {
		return
	}
	if err := json.Unmarshal(data, &config); err != nil {
		log.Printf("Warning: Failed to parse config: %v", err)
	}
	auditLogger.Printf("Loaded config from %s", configPath)
}

// saveConfig saves configuration to JSON file
func saveConfig() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	configPath := filepath.Join(home, ConfigDir, ConfigFile)
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		log.Printf("Warning: Failed to marshal config: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(configPath), 0750); err != nil {
		log.Printf("Warning: Failed to create config dir: %v", err)
		return
	}
	if err := os.WriteFile(configPath, data, 0640); err != nil {
		log.Printf("Warning: Failed to write config: %v", err)
	}
	auditLogger.Printf("Saved config to %s", configPath)
}

// validateAuth checks client authorization token
func validateAuth() bool {
	if config.AuthToken == "" {
		return false
	}
	// Mock token validation (replace with real validation in production)
	if len(config.AuthToken) < 8 {
		auditLogger.Printf("Invalid token: %s", config.AuthToken)
		return false
	}
	auditLogger.Printf("Validated token: %s", config.AuthToken)
	return true
}

// validateTargets ensures targets are in allowed IP ranges
func validateTargets() bool {
	if config.Targets == "" || len(config.AllowedIPs) == 0 {
		return true // No targets or no restrictions
	}
	for _, target := range strings.Split(config.Targets, ",") {
		target = strings.TrimSpace(target)
		ip := net.ParseIP(target)
		if ip == nil {
			auditLogger.Printf("Invalid IP: %s", target)
			return false
		}
		allowed := false
		for _, cidr := range config.AllowedIPs {
			_, net, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			if net.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			auditLogger.Printf("Target %s not in allowed range", target)
			return false
		}
	}
	return true
}

// parseNmapResults parses Nmap XML output
func parseNmapResults() []ScanResult {
	log.Println("Parsing Nmap results...")
	file, err := os.Open(config.NmapFile)
	if err != nil {
		log.Fatalf("Error opening Nmap file: %v", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		log.Fatalf("Error reading Nmap file: %v", err)
	}

	var nmapRun NmapRun
	if err := xml.Unmarshal(data, &nmapRun); err != nil {
		log.Fatalf("Error parsing Nmap XML: %v", err)
	}

	var results []ScanResult
	for _, host := range nmapRun.Hosts {
		result := ScanResult{
			IP:      host.Address.Addr,
			Ports:   []PortInfo{},
			Banners: make(map[int]string),
		}
		for _, port := range host.Ports.Ports {
			if port.State.State != "open" {
				continue
			}
			portID, _ := strconv.Atoi(port.PortID)
			portInfo := PortInfo{
				Port:     portID,
				Protocol: port.Protocol,
				Service:  port.Service.Name,
			}
			if port.Service.Product != "" {
				portInfo.Service = port.Service.Product
				if port.Service.Version != "" {
					portInfo.Service += " " + port.Service.Version
				}
			}
			result.Ports = append(result.Ports, portInfo)
		}
		results = append(results, result)
	}
	log.Println("Nmap parsing completed")
	auditLogger.Printf("Parsed Nmap file: %s, found %d hosts", config.NmapFile, len(results))
	return results
}

// runPacketSniffer captures network packets
func runPacketSniffer() SniffSummary {
	log.Printf("Starting packet sniffer on %s...", config.SniffIface)
	summary := SniffSummary{
		Interface:   config.SniffIface,
		Filter:      config.SniffFilter,
		PcapFile:    config.SniffPcap,
		TCPSummary:  make(map[string]int),
		UDPSummary:  make(map[string]int),
		DNSSummary:  []string{},
		HTTPSummary: []string{},
		StartTime:   time.Now(),
	}

	handle, err := pcap.OpenLive(config.SniffIface, 1600, true, pcap.BlockForever)
	if err != nil {
		summary.Errors = append(summary.Errors, fmt.Sprintf("Open interface: %v", err))
		auditLogger.Printf("Sniffer error: %v", err)
		return summary
	}
	defer handle.Close()

	if config.SniffFilter != "" {
		if err := handle.SetBPFFilter(config.SniffFilter); err != nil {
			summary.Errors = append(summary.Errors, fmt.Sprintf("Set BPF filter: %v", err))
			auditLogger.Printf("Sniffer error: %v", err)
		}
	}

	var pcapWriter *pcapgo.Writer
	var pcapFile *os.File
	if config.SniffPcap != "" {
		var err error
		pcapFile, err = os.Create(config.SniffPcap)
		if err != nil {
			summary.Errors = append(summary.Errors, fmt.Sprintf("Create PCAP: %v", err))
			auditLogger.Printf("Sniffer error: %v", err)
		} else {
			defer pcapFile.Close()
			pcapWriter = pcapgo.NewWriter(pcapFile)
			if err := pcapWriter.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
				summary.Errors = append(summary.Errors, fmt.Sprintf("Write PCAP header: %v", err))
				auditLogger.Printf("Sniffer error: %v", err)
				pcapWriter = nil
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.SniffTimeout)*time.Second)
	defer cancel()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		select {
		case <-ctx.Done():
			break
		default:
		}
		summary.Packets++
		if pcapWriter != nil {
			if err := pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
				summary.Errors = append(summary.Errors, fmt.Sprintf("Write PCAP: %v", err))
				auditLogger.Printf("Sniffer error: %v", err)
				pcapWriter = nil
				if pcapFile != nil {
					pcapFile.Close()
					pcapFile = nil
				}
			}
		}
		processPacket(packet, &summary)
	}
	summary.EndTime = time.Now()
	log.Println("Packet sniffing completed")
	auditLogger.Printf("Sniffer completed: %d packets captured", summary.Packets)
	return summary
}

// processPacket analyzes captured packets
func processPacket(packet gopacket.Packet, summary *SniffSummary) {
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP := ip.SrcIP.String()
		dstIP := ip.DstIP.String()

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			key := fmt.Sprintf("%s:%d -> %s:%d", srcIP, tcp.SrcPort, dstIP, tcp.DstPort)
			summary.TCPSummary[key]++
			if tcp.SrcPort == 80 || tcp.DstPort == 80 || tcp.SrcPort == 443 || tcp.DstPort == 443 {
				summary.HTTPSummary = append(summary.HTTPSummary, key)
			}
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			key := fmt.Sprintf("%s:%d -> %s:%d", srcIP, udp.SrcPort, dstIP, udp.DstPort)
			summary.UDPSummary[key]++
			if udp.SrcPort == 53 || udp.DstPort == 53 {
				if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
					dns, _ := dnsLayer.(*layers.DNS)
					for _, q := range dns.Questions {
						summary.DNSSummary = append(summary.DNSSummary, fmt.Sprintf("%s (%s)", q.Name, q.Type))
					}
				}
			}
		}
	}
}

// saveReport saves scan or sniff results to file
func saveReport(data interface{}) {
	if config.OutputFile == "" {
		return
	}
	var output []byte
	var err error
	if config.OutputFormat == "json" {
		output, err = json.MarshalIndent(data, "", "  ")
		if err != nil {
			log.Printf("Error marshaling JSON: %v", err)
			auditLogger.Printf("Report error: %v", err)
			return
		}
	} else {
		output = formatTextReport(data)
	}
	outputPath := config.OutputFile + "." + config.OutputFormat
	if err := os.WriteFile(outputPath, output, 0644); err != nil {
		log.Printf("Error writing report: %v", err)
		auditLogger.Printf("Report error: %v", err)
		return
	}
	auditLogger.Printf("Saved report to %s", outputPath)
}

// formatTextReport generates a text report
func formatTextReport(data interface{}) []byte {
	var sb strings.Builder
	switch d := data.(type) {
	case []ScanResult:
		sb.WriteString("=== Nmap Analysis Report ===\n")
		for _, r := range d {
			sb.WriteString(fmt.Sprintf("IP: %s\n", r.IP))
			for _, p := range r.Ports {
				sb.WriteString(fmt.Sprintf("  Port: %d/%s (%s)\n", p.Port, p.Protocol, p.Service))
				if banner, ok := r.Banners[p.Port]; ok {
					sb.WriteString(fmt.Sprintf("    Banner: %s\n", banner))
				}
			}
		}
	case SniffSummary:
		sb.WriteString("=== Packet Analysis Report ===\n")
		sb.WriteString(fmt.Sprintf("Interface: %s\n", d.Interface))
		sb.WriteString(fmt.Sprintf("Filter: %s\n", d.Filter))
		sb.WriteString(fmt.Sprintf("Packets: %d\n", d.Packets))
		sb.WriteString(fmt.Sprintf("Duration: %v\n", d.EndTime.Sub(d.StartTime)))
		if len(d.TCPSummary) > 0 {
			sb.WriteString("TCP Connections:\n")
			for k, v := range d.TCPSummary {
				sb.WriteString(fmt.Sprintf("  %s: %d packets\n", k, v))
			}
		}
		if len(d.HTTPSummary) > 0 {
			sb.WriteString("HTTP Connections:\n")
			for _, k := range d.HTTPSummary {
				sb.WriteString(fmt.Sprintf("  %s\n", k))
			}
		}
		if len(d.DNSSummary) > 0 {
			sb.WriteString("DNS Queries:\n")
			for _, q := range d.DNSSummary {
				sb.WriteString(fmt.Sprintf("  %s\n", q))
			}
		}
		if len(d.Errors) > 0 {
			sb.WriteString("Errors:\n")
			for _, e := range d.Errors {
				sb.WriteString(fmt.Sprintf("  %s\n", e))
			}
		}
	}
	return []byte(sb.String())
}
