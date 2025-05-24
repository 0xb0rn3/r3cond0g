package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// Constants
const (
	AppName    = "r3cond0g"
	AppVersion = "1.0.0"
	ConfigDir  = ".r3cond0g"
	ConfigFile = "config.json"
)

// Config holds tool configuration
type Config struct {
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
}

// ScanResult holds port scanning results
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

// Global configuration
var config Config

// init sets default configuration
func init() {
	config.Timeout = 3000
	config.OutputFormat = "text"
	config.Threads = 10
	config.SniffTimeout = 60
	config.Verbose = false
}

// main is the entry point
func main() {
	// Parse command-line flags
	parseFlags()

	// Load configuration from file
	loadConfig()

	// Validate configuration
	if config.Targets == "" && config.SniffIface == "" {
		log.Fatal("Error: Specify targets or sniffing interface")
	}

	// Run scanning or sniffing based on configuration
	if config.SniffIface != "" {
		summary := runPacketSniffer()
		saveReport(summary)
	} else {
		results := runPortScanner()
		saveReport(results)
	}
}

// parseFlags handles command-line arguments
func parseFlags() {
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
}

// runPortScanner performs TCP port scanning and banner grabbing
func runPortScanner() []ScanResult {
	log.Println("Starting port scan...")
	targets := strings.Split(config.Targets, ",")
	var results []ScanResult
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, config.Threads)

	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(t string) {
			defer wg.Done()
			defer func() { <-sem }()
			result := scanTarget(t)
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(target)
	}
	wg.Wait()
	log.Println("Port scan completed")
	return results
}

// scanTarget scans a single target for open ports and banners
func scanTarget(target string) ScanResult {
	result := ScanResult{
		IP:      target,
		Ports:   []PortInfo{},
		Banners: make(map[int]string),
	}
	ports := parsePorts(config.Ports)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			addr := fmt.Sprintf("%s:%d", target, p)
			conn, err := net.DialTimeout("tcp", addr, time.Duration(config.Timeout)*time.Millisecond)
			if err != nil {
				return
			}
			defer conn.Close()
			portInfo := PortInfo{Port: p, Protocol: "tcp", Service: guessService(p)}
			mu.Lock()
			result.Ports = append(result.Ports, portInfo)
			mu.Unlock()
			banner := grabBanner(conn, portInfo)
			if banner != "" {
				mu.Lock()
				result.Banners[p] = banner
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	return result
}

// parsePorts converts port string to list of integers
func parsePorts(ports string) []int {
	var result []int
	for _, p := range strings.Split(ports, ",") {
		p = strings.TrimSpace(p)
		if port, err := strconv.Atoi(p); err == nil {
			result = append(result, port)
		}
	}
	return result
}

// guessService maps ports to common services
func guessService(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 80:
		return "http"
	case 443:
		return "https"
	default:
		return "unknown"
	}
}

// grabBanner attempts to read service banners
func grabBanner(conn net.Conn, portInfo PortInfo) string {
	conn.SetReadDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Millisecond))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil && err != io.EOF {
		return ""
	}
	banner := strings.TrimSpace(string(buffer[:n]))
	if portInfo.Service == "http" {
		conn.Write([]byte("HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n"))
		n, err = conn.Read(buffer)
		if err != nil && err != io.EOF {
			return ""
		}
		banner = strings.TrimSpace(string(buffer[:n]))
	}
	return banner
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
		return summary
	}
	defer handle.Close()

	if config.SniffFilter != "" {
		if err := handle.SetBPFFilter(config.SniffFilter); err != nil {
			summary.Errors = append(summary.Errors, fmt.Sprintf("Set BPF filter: %v", err))
		}
	}

	var pcapWriter *pcapgo.Writer
	var pcapFile *os.File
	if config.SniffPcap != "" {
		var err error
		pcapFile, err = os.Create(config.SniffPcap)
		if err != nil {
			summary.Errors = append(summary.Errors, fmt.Sprintf("Create PCAP: %v", err))
		} else {
			defer pcapFile.Close()
			pcapWriter = pcapgo.NewWriter(pcapFile)
			if err := pcapWriter.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
				summary.Errors = append(summary.Errors, fmt.Sprintf("Write PCAP header: %v", err))
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
			return
		}
	} else {
		output = formatTextReport(data)
	}
	if err := os.WriteFile(config.OutputFile+"."+config.OutputFormat, output, 0644); err != nil {
		log.Printf("Error writing report: %v", err)
	}
}

// formatTextReport generates a text report
func formatTextReport(data interface{}) []byte {
	var sb strings.Builder
	switch d := data.(type) {
	case []ScanResult:
		sb.WriteString("=== Port Scan Report ===\n")
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
		sb.WriteString("=== Packet Sniff Report ===\n")
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
