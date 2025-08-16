// Scan a single port
func (s *Scanner) scanPort(host string, port int, protocol string) *EnhancedScanResult {
	startTime := time.Now()
	
	var result *EnhancedScanResult
	
	switch protocol {
	case "tcp":
		if s.config.SYNScan {
			result = s.synScan(host, port)
		} else {
			result = s.tcpConnect(host, port)
		}
	case "udp":
		result = s.udpScan(host, port)
	}
	
	if result == nil {
		return nil
	}
	
	result.ResponseTime = time.Since(startTime)
	result.Timestamp = time.Now()
	
	// Service detection
	if result.State == "open" && s.config.ServiceDetect {
		s.detectService(result)
	}
	
	// Version detection
	if result.State == "open" && s.config.VersionDetect {
		s.detectVersion(result)
	}
	
	// OS detection
	if result.State == "open" && s.config.OSDetect {
		s.detectOS(result)
	}
	
	// Vulnerability mapping
	if result.State == "open" && s.config.VulnMapping {
		s.mapVulnerabilities(result)
	}
	
	// MAC address lookup
	if s.config.EnableMACLookup {
		s.lookupMAC(result)
	}
	
	return result
}

// TCP connect scan
func (s *Scanner) tcpConnect(host string, port int) *EnhancedScanResult {
	timeout := time.Duration(s.config.ScanTimeout) * time.Millisecond
	if timeout <= 0 {
		timeout = DEFAULT_TIMEOUT * time.Millisecond
	}
	
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		if isTimeout(err) {
			return &EnhancedScanResult{
				Host:     host,
				Port:     port,
				Protocol: "tcp",
				State:    "filtered",
			}
		}
		return &EnhancedScanResult{
			Host:     host,
			Port:     port,
			Protocol: "tcp",
			State:    "closed",
		}
	}
	defer conn.Close()
	
	s.metrics.OpenPorts.Add(1)
	
	result := &EnhancedScanResult{
		Host:     host,
		Port:     port,
		Protocol: "tcp",
		State:    "open",
	}
	
	// Grab banner if possible
	if s.config.ServiceDetect {
		serviceTimeout := time.Duration(s.config.ServiceDetectTimeout) * time.Millisecond
		if serviceTimeout <= 0 {
			serviceTimeout = DEFAULT_SERVICE_TIMEOUT * time.Millisecond
		}
		
		if serviceInfo := detectServiceWithTimeout(conn, port, "tcp", serviceTimeout); serviceInfo != nil {
			result.Service = serviceInfo.ServiceName
			result.Version = serviceInfo.ServiceVersion
			result.DetectionConfidence = serviceInfo.Confidence
			result.ALPNProtocol = serviceInfo.ALPNProtocol
			if serviceInfo.TLSInfo != nil {
				result.TLSCommonName = serviceInfo.TLSInfo.CommonName
			}
		}
	}
	
	return result
}

// SYN scan implementation
func (s *Scanner) synScan(host string, port int) *EnhancedScanResult {
	// Basic SYN scan implementation
	// This is a simplified version - full implementation would involve raw sockets
	timeout := time.Duration(s.config.ScanTimeout) * time.Millisecond
	if timeout <= 0 {
		timeout = DEFAULT_TIMEOUT * time.Millisecond
	}
	
	// Try to connect briefly to check if port is open
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		if isTimeout(err) {
			return &EnhancedScanResult{
				Host:     host,
				Port:     port,
				Protocol: "tcp",
				State:    "filtered",
			}
		}
		return &EnhancedScanResult{
			Host:     host,
			Port:     port,
			Protocol: "tcp",
			State:    "closed",
		}
	}
	conn.Close()
	
	s.metrics.OpenPorts.Add(1)
	return &EnhancedScanResult{
		Host:     host,
		Port:     port,
		Protocol: "tcp",
		State:    "open",
	}
}

// UDP scan implementation
func (s *Scanner) udpScan(host string, port int) *EnhancedScanResult {
	timeout := time.Duration(s.config.ScanTimeout) * time.Millisecond
	if timeout <= 0 {
		timeout = DEFAULT_TIMEOUT * time.Millisecond
	}
	
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return &EnhancedScanResult{
			Host:     host,
			Port:     port,
			Protocol: "udp",
			State:    "closed",
		}
	}
	defer conn.Close()
	
	// Send a probe packet
	_, err = conn.Write([]byte("probe"))
	if err != nil {
		return &EnhancedScanResult{
			Host:     host,
			Port:     port,
			Protocol: "udp",
			State:    "closed",
		}
	}
	
	// Try to read response with timeout
	conn.SetReadDeadline(time.Now().Add(timeout))
	buffer := make([]byte, 1024)
	_, err = conn.Read(buffer)
	
	// UDP is tricky - lack of response doesn't mean closed
	return &EnhancedScanResult{
		Host:     host,
		Port:     port,
		Protocol: "udp",
		State:    "open|filtered",
	}
}

// ICMP ping implementation
func (s *Scanner) isHostAliveICMP(host string, timeout time.Duration) bool {
	// Simplified ICMP ping
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false
	}
	defer conn.Close()
	
	dst, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return false
	}
	
	// Create ICMP message
	message := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("Hello, World!"),
		},
	}
	
	data, err := message.Marshal(nil)
	if err != nil {
		return false
	}
	
	// Send ping
	_, err = conn.WriteTo(data, dst)
	if err != nil {
		return false
	}
	
	// Wait for reply
	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return false
	}
	
	reply := make([]byte, 1500)
	_, _, err = conn.ReadFrom(reply)
	return err == nil
}

// TCP ping implementation
func (s *Scanner) isHostAliveTCP(host string, ports []int, timeout time.Duration) bool {
	for _, port := range ports {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

// Service detection
func (s *Scanner) detectService(result *EnhancedScanResult) {
	// Use probe engine if available
	if s.probeEngine != nil {
		if serviceInfo := s.probeEngine.DetectService(result.Host, result.Port, result.Protocol); serviceInfo != nil {
			result.Service = serviceInfo.ServiceName
			result.Version = serviceInfo.ServiceVersion
			result.DetectionConfidence = serviceInfo.Confidence
			result.ALPNProtocol = serviceInfo.ALPNProtocol
			if serviceInfo.TLSInfo != nil {
				result.TLSCommonName = serviceInfo.TLSInfo.CommonName
			}
		}
	}
}

// Version detection
func (s *Scanner) detectVersion(result *EnhancedScanResult) {
	// Enhanced version detection would go here
	// For now, use basic banner grabbing
	if result.Service != "" {
		result.Version = "detected"
	}
}

// OS detection
func (s *Scanner) detectOS(result *EnhancedScanResult) {
	// OS fingerprinting implementation
	if s.fingerprintDB != nil {
		// Use fingerprint database for OS detection
		result.OS = "Unknown"
	}
}

// Vulnerability mapping
func (s *Scanner) mapVulnerabilities(result *EnhancedScanResult) {
	if result.Service == "" {
		return
	}
	
	// Check local vulnerability database
	serviceKey := fmt.Sprintf("%s %s", result.Service, result.Version)
	if vulns, exists := vulnDB[serviceKey]; exists {
		result.Vulnerabilities = vulns
	}
	
	// Use CVE database if available
	if s.vulnDB != nil {
		if cves := s.vulnDB.SearchCVEs(result.Service, result.Version); len(cves) > 0 {
			result.CVEs = cves
		}
	}
}

// MAC address lookup
func (s *Scanner) lookupMAC(result *EnhancedScanResult) {
	// ARP lookup for MAC address (simplified)
	if result.MACAddress != "" {
		prefix := result.MACAddress[:8]
		if vendor, exists := s.ouiData[strings.ToUpper(prefix)]; exists {
			result.MACVendor = vendor
		}
	}
}

// Process results
func (s *Scanner) processResults() {
	for result := range s.results {
		if result == nil {
			continue
		}
		
		// Filter results if needed
		if s.config.OnlyOpenPorts && result.State != "open" {
			continue
		}
		
		// Store result
		mutex.Lock()
		results = append(results, *result)
		mutex.Unlock()
		
		// Log result if verbose
		if s.config.Verbose {
			s.logger.Info().
				Str("host", result.Host).
				Int("port", result.Port).
				Str("protocol", result.Protocol).
				Str("state", result.State).
				Str("service", result.Service).
				Msg("Port scan result")
		}
	}
}

// Handle errors
func (s *Scanner) handleErrors() {
	for err := range s.errors {
		if err != nil {
			s.logger.Error().Err(err).Msg("Scan error")
			s.metrics.Errors.Add(1)
		}
	}
}

// Print summary
func (s *Scanner) printSummary() {
	duration := s.metrics.EndTime.Sub(s.metrics.StartTime)
	
	fmt.Printf("\n=== SCAN SUMMARY ===\n")
	fmt.Printf("Duration: %v\n", duration)
	fmt.Printf("Total Hosts: %d\n", s.metrics.TotalHosts.Load())
	fmt.Printf("Total Ports: %d\n", s.metrics.TotalPorts.Load())
	fmt.Printf("Open Ports: %d\n", s.metrics.OpenPorts.Load())
	fmt.Printf("Closed Ports: %d\n", s.metrics.ClosedPorts.Load())
	fmt.Printf("Filtered Ports: %d\n", s.metrics.FilteredPorts.Load())
	fmt.Printf("Packets Sent: %d\n", s.metrics.PacketsSent.Load())
	fmt.Printf("Packets Received: %d\n", s.metrics.PacketsReceived.Load())
	fmt.Printf("Errors: %d\n", s.metrics.Errors.Load())
	
	// Print open ports
	fmt.Printf("\n=== OPEN PORTS ===\n")
	mutex.Lock()
	for _, result := range results {
		if result.State == "open" {
			fmt.Printf("%s:%d/%s %s %s\n", 
				result.Host, result.Port, result.Protocol, 
				result.Service, result.Version)
		}
	}
	mutex.Unlock()
}

// Load custom CVEs
func (s *Scanner) loadCustomCVEs() {
	if s.config.CVEPluginFile == "" {
		return
	}
	
	file, err := os.Open(s.config.CVEPluginFile)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to open CVE plugin file")
		return
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			service := strings.TrimSpace(parts[0])
			cve := strings.TrimSpace(parts[1])
			s.customCVEs[service] = append(s.customCVEs[service], cve)
		}
	}
}

// Cleanup resources
func (s *Scanner) cleanup() {
	// Close pcap handle
	if s.pcapHandle != nil {
		s.pcapHandle.Close()
	}
	
	// Close raw socket
	if s.rawSocket != 0 {
		unix.Close(s.rawSocket)
	}
	
	// Close database
	if s.db != nil {
		s.db.Close()
	}
	
	// Cancel context
	s.cancel()
}

// Helper functions
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
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
				}
			}
		} else {
			port, err := strconv.Atoi(r)
			if err == nil && port > 0 && port <= 65535 {
				if !seen[port] {
					ports = append(ports, port)
					seen[port] = true
				}
			}
		}
	}
	
	return ports
}

func getTopPorts(n int) []int {
	topPorts := []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
		1723, 3306, 3389, 5900, 8080, 8443, 8888, 10000, 32768, 49152, 49153,
		49154, 49155, 49156, 49157, 1433, 1521, 1434, 5432, 5984, 6379, 7001,
		8020, 8086, 9200, 9300, 11211, 27017, 27018, 27019, 50000, 50070,
		2049, 2181, 3000, 3001, 4444, 5000, 5001, 5060, 5555, 5601, 5672,
		6000, 6001, 6666, 7000, 7002, 8000, 8001, 8081, 8090, 8099, 8181,
		8649, 8834, 9000, 9001, 9090, 9091, 9999, 10001, 10002, 15672,
		27015, 28015, 29015, 30000, 31337, 32764, 32769, 49160, 49161,
	}
	
	if n > len(topPorts) {
		n = len(topPorts)
	}
	
	return topPorts[:n]
}

// Additional stub functions that need to be implemented
func NewServiceDatabase(cacheDir string) *ServiceDatabase {
	cache, _ := lru.New[string, *ServiceInfo](1000)
	return &ServiceDatabase{
		patterns: make(map[string][]*ServicePattern),
		cache:    cache,
	}
}

func NewFingerprintDatabase() *FingerprintDatabase {
	return &FingerprintDatabase{
		os:      make(map[string]*OSFingerprint),
		service: make(map[string]*ServiceFingerprint),
		app:     make(map[string]*AppFingerprint),
	}
}

func NewVulnerabilityDatabase(cacheDir, apiKey string) *VulnerabilityDatabase {
	cache, _ := lru.New[string, []*CVEInfo](1000)
	return &VulnerabilityDatabase{
		cache:     cache,
		apiKey:    apiKey,
		rateLimit: limiter,
	}
}

func (vdb *VulnerabilityDatabase) SearchCVEs(service, version string) []*CVEInfo {
	// Search for CVEs related to the service and version
	var cves []*CVEInfo
	
	// Check cache first
	key := fmt.Sprintf("%s:%s", service, version)
	if cached, ok := vdb.cache.Get(key); ok {
		return cached
	}
	
	// Simple lookup in local database
	serviceKey := fmt.Sprintf("%s %s", service, version)
	if vulns, exists := vulnDB[serviceKey]; exists {
		for _, vuln := range vulns {
			cve := &CVEInfo{
				ID:          vuln,
				CVSS:        7.5, // Default CVSS score
				Severity:    "HIGH",
				Description: fmt.Sprintf("Vulnerability in %s %s", service, version),
				Published:   time.Now().AddDate(-1, 0, 0), // Mock date
				References:  []string{fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", vuln)},
			}
			cves = append(cves, cve)
		}
	}
	
	// Cache the result
	vdb.cache.Add(key, cves)
	return cves
}

func NewScriptEngine() *ScriptEngine {
	return &ScriptEngine{
		scripts: make(map[string]*Script),
		timeout: 30 * time.Second,
	}
}

func (se *ScriptEngine) LoadScripts() error {
	// Load NSE-like scripts
	return nil
}

func NewMLEngine() *MLEngine {
	return &MLEngine{
		threshold: 0.8,
	}
}

func (ml *MLEngine) LoadModel() error {
	// Load ML model for intelligent scanning
	return nil
}

func NewWorkerPool(workers int, ctx context.Context) *WorkerPool {
	ctx, cancel := context.WithCancel(ctx)
	return &WorkerPool{
		workers: workers,
		queue:   make(chan Task, workers*2),
		results: make(chan interface{}, workers),
		errors:  make(chan error, workers),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Probe engine implementation
func NewProbeEngine(probeFilePaths ...string) (*ProbeEngine, error) {
	engine := &ProbeEngine{
		probesByName: make(map[string]*ProbeDefinition),
	}
	
	// Load default probes
	engine.loadDefaultProbes()
	
	// Load custom probe files if provided
	for _, path := range probeFilePaths {
		if err := engine.loadProbeFile(path); err != nil {
			return nil, fmt.Errorf("failed to load probe file %s: %w", path, err)
		}
	}
	
	return engine, nil
}

func (pe *ProbeEngine) loadDefaultProbes() {
	// HTTP probe
	pe.probes = append(pe.probes, ProbeDefinition{
		Name:            "HTTP",
		Protocol:        "tcp",
		Ports:           []int{80, 8080, 8000, 8081, 8090},
		Priority:        1,
		SendPayload:     "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: r3cond0g/3.0\r\nConnection: close\r\n\r\n",
		ReadPattern:     "HTTP/\\d\\.\\d (\\d+)",
		ServiceOverride: "http",
		TimeoutMs:       5000,
	})
	
	// HTTPS probe
	pe.probes = append(pe.probes, ProbeDefinition{
		Name:             "HTTPS",
		Protocol:         "tcp",
		Ports:            []int{443, 8443, 8834},
		Priority:         1,
		RequiresTLS:      true,
		TLSALPNProtocols: []string{"http/1.1", "h2"},
		SendPayload:      "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: r3cond0g/3.0\r\nConnection: close\r\n\r\n",
		ReadPattern:      "HTTP/\\d\\.\\d (\\d+)",
		ServiceOverride:  "https",
		TimeoutMs:        5000,
	})
	
	// SSH probe
	pe.probes = append(pe.probes, ProbeDefinition{
		Name:            "SSH",
		Protocol:        "tcp",
		Ports:           []int{22, 2222},
		Priority:        1,
		ReadPattern:     "SSH-([0-9.]+)",
		ServiceOverride: "ssh",
		TimeoutMs:       3000,
	})
	
	// FTP probe
	pe.probes = append(pe.probes, ProbeDefinition{
		Name:            "FTP",
		Protocol:        "tcp",
		Ports:           []int{21},
		Priority:        1,
		ReadPattern:     "220[- ](.+)",
		ServiceOverride: "ftp",
		TimeoutMs:       3000,
	})
	
	// Compile regex patterns
	for i := range pe.probes {
		if pe.probes[i].ReadPattern != "" {
			pe.probes[i].compiledRegex = regexp.MustCompile(pe.probes[i].ReadPattern)
		}
		pe.probesByName[pe.probes[i].Name] = &pe.probes[i]
	}
}

func (pe *ProbeEngine) loadProbeFile(path string) error {
	// Load custom probe definitions from file
	// This would parse JSON/YAML probe definitions
	return nil
}

func (pe *ProbeEngine) DetectService(host string, port int, protocol string) *ServiceInfo {
	// Find matching probes for this port
	var matchingProbes []ProbeDefinition
	for _, probe := range pe.probes {
		if probe.Protocol == protocol {
			for _, p := range probe.Ports {
				if p == port {
					matchingProbes = append(matchingProbes, probe)
					break
				}
			}
		}
	}
	
	// If no specific probes found, try generic probes
	if len(matchingProbes) == 0 {
		for _, probe := range pe.probes {
			if probe.Protocol == protocol && len(probe.Ports) == 0 {
				matchingProbes = append(matchingProbes, probe)
			}
		}
	}
	
	// Try each probe
	for _, probe := range matchingProbes {
		if info := pe.runProbe(host, port, &probe); info != nil {
			return info
		}
	}
	
	return nil
}

func (pe *ProbeEngine) runProbe(host string, port int, probe *ProbeDefinition) *ServiceInfo {
	timeout := time.Duration(probe.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	
	var conn net.Conn
	var err error
	
	if probe.RequiresTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         probe.TLSALPNProtocols,
		}
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", fmt.Sprintf("%s:%d", host, port), tlsConfig)
	} else {
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	}
	
	if err != nil {
		return nil
	}
	defer conn.Close()
	
	conn.SetDeadline(time.Now().Add(timeout))
	
	// Send probe payload if specified
	if probe.SendPayload != "" {
		payload := fmt.Sprintf(probe.SendPayload, host)
		_, err = conn.Write([]byte(payload))
		if err != nil {
			return nil
		}
	}
	
	// Read response
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil && n == 0 {
		return nil
	}
	
	response := string(buffer[:n])
	
	// Match against pattern
	info := &ServiceInfo{
		ServiceName: probe.ServiceOverride,
		Confidence:  50, // Base confidence
	}
	
	if probe.compiledRegex != nil {
		matches := probe.compiledRegex.FindStringSubmatch(response)
		if len(matches) > 1 {
			info.ServiceVersion = matches[1]
			info.Confidence = 90 // High confidence for regex match
		}
	}
	
	// Extract TLS info if TLS connection
	if tlsConn, ok := conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			info.TLSInfo = &TLSInfo{
				CommonName:         cert.Subject.CommonName,
				SubjectAltNames:    cert.DNSNames,
				Issuer:             cert.Issuer.CommonName,
				NotBefore:          cert.NotBefore.Format(time.RFC3339),
				NotAfter:           cert.NotAfter.Format(time.RFC3339),
				SignatureAlgorithm: cert.SignatureAlgorithm.String(),
			}
		}
		info.ALPNProtocol = state.NegotiatedProtocol
	}
	
	if info.ServiceName != "" {
		return info
	}
	
	return nil
}

func detectServiceWithTimeout(conn net.Conn, port int, protocol string, timeout time.Duration) *ServiceInfo {
	// Basic service detection with timeout
	conn.SetReadDeadline(time.Now().Add(timeout))
	
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return &ServiceInfo{
			ServiceName: "unknown",
			Confidence:  10,
		}
	}
	
	banner := string(buffer[:n])
	
	// Simple banner-based detection
	info := &ServiceInfo{
		ServiceName: "unknown",
		Confidence:  30,
	}
	
	// HTTP detection
	if strings.Contains(banner, "HTTP/") {
		info.ServiceName = "http"
		info.Confidence = 80
		if match := regexp.MustCompile(`Server:\s*([^\r\n]+)`).FindStringSubmatch(banner); len(match) > 1 {
			info.ServiceVersion = match[1]
			info.Confidence = 90
		}
	}
	
	// SSH detection
	if strings.HasPrefix(banner, "SSH-") {
		info.ServiceName = "ssh"
		info.Confidence = 95
		if match := regexp.MustCompile(`SSH-([0-9.]+)`).FindStringSubmatch(banner); len(match) > 1 {
			info.ServiceVersion = match[1]
		}
	}
	
	// FTP detection
	if strings.HasPrefix(banner, "220") && (strings.Contains(banner, "FTP") || strings.Contains(banner, "ftp")) {
		info.ServiceName = "ftp"
		info.Confidence = 85
	}
	
	return info
}

// Main function for testing
func main() {
	// Example configuration
	config := &Config{
		Targets:        []string{"127.0.0.1"},
		Ports:          "22,80,443,8080",
		MaxConcurrency: 50,
		ScanTimeout:    1000,
		ServiceDetect:  true,
		Verbose:        true,
		DBPath:         "./r3cond0g.db",
		CacheDir:       "./cache",
	}
	
	// Create scanner
	scanner, err := NewScanner(config)
	if err != nil {
		fmt.Printf("Error creating scanner: %v\n", err)
		return
	}
	
	// Run scan
	if err := scanner.Scan(); err != nil {
		fmt.Printf("Error running scan: %v\n", err)
		return
	}
}package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alphadose/haxmap"
	"github.com/dgraph-io/badger/v4"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/hashicorp/golang-lru/v2"
	"github.com/miekg/dns"
	"github.com/projectdiscovery/blackrock"
	"github.com/projectdiscovery/mapcidr"
	"github.com/rs/zerolog"
	"github.com/schollz/progressbar/v3"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/tevino/abool/v2"
	"github.com/valyala/fasthttp"
	"github.com/yl2chen/cidranger"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"golang.org/x/time/rate"
)

const (
	VERSION    = "3.0.0 HellHound"
	APP_NAME   = "r3cond0g"
	BUILD_DATE = "2025-08-16"
	AUTHORS    = "IG:theehiv3 Alias:0xbv1 | Github:0xb0rn3"
	
	// Performance defaults
	DEFAULT_TIMEOUT        = 1000 // ms
	DEFAULT_SERVICE_TIMEOUT = 5000 // ms
	DEFAULT_CONCURRENCY    = 100
	DEFAULT_PING_TIMEOUT   = 300 // ms
)

// Enhanced Config with all features from both versions
type Config struct {
	// Target configuration
	Targets        []string
	TargetHost     string `json:"target_host"`
	TargetFile     string `json:"target_file"`
	CIDR           string
	ExcludeHosts   []string
	
	// Port configuration
	Ports          string
	PortRange      string `json:"port_range"`
	TopPorts       int
	FastMode       bool
	UltraFastMode  bool
	
	// Timing and performance
	ScanTimeout          int           `json:"scan_timeout"`
	ServiceDetectTimeout int           `json:"service_detect_timeout"`
	Timeout              time.Duration
	MaxRetries           int
	MaxConcurrency       int    `json:"max_concurrency"`
	Concurrency          int
	RateLimit            int
	DelayJitter          time.Duration
	
	// Scan types
	SYNScan        bool
	ACKScan        bool
	UDPScan        bool   `json:"udp_scan"`
	NULLScan       bool
	FINScan        bool
	XmasScan       bool
	MaimonScan     bool
	WindowScan     bool
	IdleScan       bool
	
	// Discovery methods
	PingSweepTCP    bool   `json:"ping_sweep_tcp"`
	PingSweepICMP   bool   `json:"ping_sweep_icmp"`
	PingSweepPorts  string `json:"ping_sweep_ports"`
	PingSweepTimeout int   `json:"ping_sweep_timeout"`
	
	// Service detection
	ServiceDetect   bool
	VersionDetect   bool
	OSDetect        bool
	ScriptScan      bool
	AggressiveScan  bool
	ProbeFiles      string `json:"probe_files"`
	
	// Vulnerability scanning
	VulnMapping     bool   `json:"vuln_mapping"`
	NVDAPIKey       string `json:"nvd_api_key"`
	CVEPluginFile   string `json:"cve_plugin_file"`
	
	// Network analysis
	TopologyMapping bool   `json:"topology_mapping"`
	EnableMACLookup bool   `json:"enable_mac_lookup"`
	
	// Evasion techniques
	FragmentPackets bool
	DecoyHosts      []string
	SourcePort      int
	Spoofing        bool
	TTLValue        int
	BadSum          bool
	
	// Output options
	OutputFile      string `json:"output_file"`
	OutputFormat    string
	NmapResultsFile string `json:"nmap_results_file"`
	OnlyOpenPorts   bool   `json:"only_open_ports"`
	Verbose         bool
	Debug           bool
	Quiet           bool
	NoColor         bool
	JSONOutput      bool
	XMLOutput       bool
	GrepOutput      bool
	
	// Network options
	Interface       string
	SourceIP        string
	IPv6            bool
	
	// Database and caching
	UseCache        bool
	CacheDir        string
	DBPath          string
	
	// Advanced features
	EnableML        bool
	EnableAI        bool
	ProxyURL        string
	TorProxy        bool
	DNSServers      []string
	UserAgent       string
}

// Enhanced scan result combining both versions
type EnhancedScanResult struct {
	// Basic information
	Host         string        `json:"host"`
	IP           string        `json:"ip"`
	Port         int           `json:"port"`
	Protocol     string        `json:"protocol"`
	State        string        `json:"state"`
	
	// Service information
	Service             string        `json:"service,omitempty"`
	Version             string        `json:"version,omitempty"`
	Banner              string        `json:"banner,omitempty"`
	ServiceName         string        `json:"service_name,omitempty"`
	ServiceVersion      string        `json:"service_version,omitempty"`
	DetectionConfidence int           `json:"detection_confidence,omitempty"`
	
	// OS and hardware
	OS              string        `json:"os,omitempty"`
	OSGuess         string        `json:"os_guess,omitempty"`
	CPE             []string      `json:"cpe,omitempty"`
	MACAddress      string        `json:"mac_address,omitempty"`
	MACVendor       string        `json:"mac_vendor,omitempty"`
	
	// Security information
	Vulnerabilities []string      `json:"vulnerabilities,omitempty"`
	CVEs            []CVEInfo     `json:"cves,omitempty"`
	Scripts         map[string]string `json:"scripts,omitempty"`
	
	// TLS/SSL information
	SSLInfo         *SSLInfo      `json:"ssl_info,omitempty"`
	TLSInfo         *TLSInfo      `json:"tls_info,omitempty"`
	ALPNProtocol    string        `json:"alpn_protocol,omitempty"`
	TLSCommonName   string        `json:"tls_common_name,omitempty"`
	
	// HTTP information
	HTTPInfo        *HTTPInfo     `json:"http_info,omitempty"`
	
	// DNS information
	DNSInfo         *DNSInfo      `json:"dns_info,omitempty"`
	
	// NetBIOS information
	NetBIOSInfo     *NetBIOSInfo  `json:"netbios_info,omitempty"`
	
	// Timing and metadata
	ResponseTime    time.Duration `json:"response_time"`
	Timestamp       time.Time     `json:"timestamp"`
	TTL             int           `json:"ttl"`
	WindowSize      int           `json:"window_size"`
	Fingerprint     string        `json:"fingerprint"`
	Confidence      float64       `json:"confidence"`
	RawPacket       []byte        `json:"-"`
}

// CVE information structure
type CVEInfo struct {
	ID          string    `json:"id"`
	CVSS        float64   `json:"cvss"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Published   time.Time `json:"published"`
	References  []string  `json:"references"`
}

// SSL/TLS information
type SSLInfo struct {
	Version         string      `json:"version"`
	Cipher          string      `json:"cipher"`
	Certificates    []CertInfo  `json:"certificates"`
	ValidFrom       time.Time   `json:"valid_from"`
	ValidTo         time.Time   `json:"valid_to"`
	SubjectAltNames []string    `json:"subject_alt_names"`
	Vulnerabilities []string    `json:"vulnerabilities"`
}

// TLS information for probe results
type TLSInfo struct {
	CommonName         string   `json:"common_name"`
	SubjectAltNames    []string `json:"subject_alt_names"`
	Issuer             string   `json:"issuer"`
	NotBefore          string   `json:"not_before"`
	NotAfter           string   `json:"not_after"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
}

// Certificate information
type CertInfo struct {
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	Serial     string    `json:"serial"`
	Algorithm  string    `json:"algorithm"`
	ValidFrom  time.Time `json:"valid_from"`
	ValidTo    time.Time `json:"valid_to"`
}

// HTTP information
type HTTPInfo struct {
	StatusCode   int               `json:"status_code"`
	Headers      map[string]string `json:"headers"`
	Server       string            `json:"server"`
	Title        string            `json:"title"`
	Technologies []string          `json:"technologies"`
	Forms        []FormInfo        `json:"forms"`
	Links        []string          `json:"links"`
	Cookies      []CookieInfo      `json:"cookies"`
}

// Form information
type FormInfo struct {
	Action   string            `json:"action"`
	Method   string            `json:"method"`
	Fields   map[string]string `json:"fields"`
}

// Cookie information
type CookieInfo struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"http_only"`
}

// DNS information
type DNSInfo struct {
	Records     map[string][]string `json:"records"`
	Nameservers []string            `json:"nameservers"`
	MXRecords   []MXRecord          `json:"mx_records"`
	TXTRecords  []string            `json:"txt_records"`
	SOA         *SOARecord          `json:"soa"`
}

// MX record
type MXRecord struct {
	Priority int    `json:"priority"`
	Host     string `json:"host"`
}

// SOA record
type SOARecord struct {
	Mname   string `json:"mname"`
	Rname   string `json:"rname"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minimum uint32 `json:"minimum"`
}

// NetBIOS information
type NetBIOSInfo struct {
	Name       string   `json:"name"`
	Workgroup  string   `json:"workgroup"`
	MAC        string   `json:"mac"`
	Users      []string `json:"users"`
	Shares     []string `json:"shares"`
}

// Nmap XML structures for parsing
type NmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []NmapHost `xml:"host"`
}

type NmapHost struct {
	Addresses []NmapAddress `xml:"address"`
	Ports     NmapPorts     `xml:"ports"`
	Status    NmapStatus    `xml:"status"`
}

type NmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr,omitempty"`
}

type NmapStatus struct {
	State string `xml:"state,attr"`
}

type NmapPorts struct {
	Ports []NmapPort `xml:"port"`
}

type NmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    NmapState   `xml:"state"`
	Service  NmapService `xml:"service"`
}

type NmapState struct {
	State string `xml:"state,attr"`
}

type NmapService struct {
	Name    string `xml:"name,attr"`
	Version string `xml:"version,attr"`
}

// Probe definitions for service detection
type ProbeDefinition struct {
	Name               string   `json:"name"`
	Protocol           string   `json:"protocol"`
	Ports              []int    `json:"ports"`
	Priority           int      `json:"priority"`
	RequiresTLS        bool     `json:"requires_tls"`
	TLSALPNProtocols   []string `json:"tls_alpn_protocols"`
	SendPayload        string   `json:"send_payload"`
	ReadPattern        string   `json:"read_pattern"`
	ServiceOverride    string   `json:"service_override"`
	VersionTemplate    string   `json:"version_template"`
	TimeoutMs          int      `json:"timeout_ms"`
	NextProbeOnMatch   string   `json:"next_probe_on_match"`
	compiledRegex      *regexp.Regexp
}

// Probe engine for service detection
type ProbeEngine struct {
	probes         []ProbeDefinition
	probesByName   map[string]*ProbeDefinition
	fallbackProbes []ProbeDefinition
}

// Service info from probe detection
type ServiceInfo struct {
	ServiceName    string            `json:"service_name"`
	ServiceVersion string            `json:"service_version"`
	TLSInfo        *TLSInfo          `json:"tls_info,omitempty"`
	ALPNProtocol   string            `json:"alpn_protocol,omitempty"`
	Confidence     int               `json:"confidence"`
	ExtraData      map[string]string `json:"extra_data,omitempty"`
}

// Advanced scanner with all features
type Scanner struct {
	config          *Config
	logger          zerolog.Logger
	metrics         *Metrics
	cache           *lru.Cache[string, interface{}]
	db              *badger.DB
	limiter         *rate.Limiter
	blackrock       *blackrock.Blackrock
	cidranger       cidranger.Ranger
	portMap         *haxmap.Map[int, *PortInfo]
	serviceDB       *ServiceDatabase
	fingerprintDB   *FingerprintDatabase
	vulnDB          *VulnerabilityDatabase
	scriptEngine    *ScriptEngine
	probeEngine     *ProbeEngine
	ml              *MLEngine
	pcapHandle      *pcap.Handle
	dnsClient       *dns.Client
	httpClient      *fasthttp.Client
	sshConfig       *ssh.ClientConfig
	tlsConfig       *tls.Config
	rawSocket       int
	workers         *WorkerPool
	results         chan *EnhancedScanResult
	errors          chan error
	done            *abool.AtomicBool
	wg              sync.WaitGroup
	ctx             context.Context
	cancel          context.CancelFunc
	
	// From older version
	scannedPorts    int64
	activeHostPings int64
	nvdCache        sync.Map
	customCVEs      map[string][]string
	ouiData         map[string]string
}

// Metrics tracking
type Metrics struct {
	StartTime       time.Time
	EndTime         time.Time
	TotalHosts      atomic.Int64
	ScannedHosts    atomic.Int64
	TotalPorts      atomic.Int64
	OpenPorts       atomic.Int64
	ClosedPorts     atomic.Int64
	FilteredPorts   atomic.Int64
	PacketsSent     atomic.Int64
	PacketsReceived atomic.Int64
	BytesSent       atomic.Int64
	BytesReceived   atomic.Int64
	Errors          atomic.Int64
	Retries         atomic.Int64
}

// Port information
type PortInfo struct {
	Port        int
	Protocol    string
	Service     string
	Description string
	Frequency   float64
}

// Service database
type ServiceDatabase struct {
	db       *leveldb.DB
	patterns map[string][]*ServicePattern
	cache    *lru.Cache[string, *ServiceInfo]
}

// Service pattern
type ServicePattern struct {
	Pattern     []byte
	Service     string
	Version     string
	CPE         string
	Confidence  float64
}

// Fingerprint database structures
type FingerprintDatabase struct {
	os       map[string]*OSFingerprint
	service  map[string]*ServiceFingerprint
	app      map[string]*AppFingerprint
}

type OSFingerprint struct {
	Name        string
	Version     string
	Family      string
	Vendor      string
	Confidence  float64
	TTL         int
	WindowSize  int
	Options     []string
}

type ServiceFingerprint struct {
	Name       string
	Version    string
	Protocol   string
	Banner     string
	Probes     []string
	Matches    []string
}

type AppFingerprint struct {
	Name         string
	Version      string
	Technologies []string
	Headers      map[string]string
	Cookies      []string
	Scripts      []string
}

// Vulnerability database
type VulnerabilityDatabase struct {
	db        *badger.DB
	cache     *lru.Cache[string, []*CVEInfo]
	apiKey    string
	rateLimit *rate.Limiter
}

// Script engine
type ScriptEngine struct {
	scripts  map[string]*Script
	vm       interface{}
	sandbox  interface{}
	timeout  time.Duration
}

// Script definition
type Script struct {
	Name        string
	Category    string
	Description string
	Author      string
	License     string
	Code        string
	Ports       []int
	Services    []string
	OSTypes     []string
}

// ML engine
type MLEngine struct {
	model      interface{}
	features   interface{}
	predictor  interface{}
	threshold  float64
}

// Worker pool
type WorkerPool struct {
	workers    int
	queue      chan Task
	results    chan interface{}
	errors     chan error
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
}

// Task interface
type Task interface {
	Execute(ctx context.Context) (interface{}, error)
	Priority() int
}

// Global variables for compatibility with older version
var (
	config          Config
	results         []EnhancedScanResult
	mutex           sync.Mutex
	wg              sync.WaitGroup
	sem             chan struct{}
	scannedPorts    int64
	activeHostPings int64
	probeEngineInstance *ProbeEngine
	nvdCache        sync.Map
	customCVEs      = make(map[string][]string)
	httpClientSimple = &http.Client{Timeout: 10 * time.Second}
	limiter         = rate.NewLimiter(rate.Every(30*time.Second/5), 5)
	
	// Service to CPE mapping for vulnerability lookups
	serviceToCPE = map[string]struct{ Vendor, Product string }{
		"http":           {"apache", "http_server"},
		"https":          {"apache", "http_server"},
		"http/2":         {"apache", "http_server"},
		"nginx":          {"nginx", "nginx"},
		"ssh":            {"openssh", "openssh"},
		"ftp":            {"proftpd", "proftpd"},
		"mysql":          {"oracle", "mysql"},
		"dns":            {"isc", "bind"},
		"smtp":           {"postfix", "postfix"},
		"smtps":          {"postfix", "postfix"},
		"redis":          {"redis", "redis"},
		"rdp":            {"microsoft", "remote_desktop_services"},
		"ms-wbt-server":  {"microsoft", "remote_desktop_services"},
		"microsoft-ds":   {"microsoft", "windows"},
		"netbios-ssn":    {"microsoft", "windows"},
		"winrm":          {"microsoft", "windows_remote_management"},
		"snmp":           {"net-snmp", "net-snmp"},
		"pop3":           {"dovecot", "dovecot"},
		"pop3s":          {"dovecot", "dovecot"},
		"imap":           {"dovecot", "dovecot"},
		"imaps":          {"dovecot", "dovecot"},
		"postgresql":     {"postgresql", "postgresql"},
		"mongodb":        {"mongodb", "mongodb"},
		"ldap":           {"openldap", "openldap"},
		"ldaps":          {"openldap", "openldap"},
		"vnc":            {"realvnc", "vnc"},
		"telnet":         {"gnu", "inetutils"},
		"msrpc":          {"microsoft", "windows"},
		"oracle":         {"oracle", "database"},
		"mssql":          {"microsoft", "sql_server"},
	}
	
	// OUI database for MAC vendor lookup
	ouiData = map[string]string{
		"00:00:0C": "Cisco Systems, Inc",
		"00:05:85": "Juniper Networks, Inc",
		"00:0B:86": "Hewlett Packard Enterprise",
		"00:06:5B": "Dell Inc.",
		"00:0A:F7": "Broadcom Corporation",
		"00:1C:73": "Arista Networks, Inc",
		"00:15:6D": "Ubiquiti Inc",
		"00:0C:42": "Routerboard/MikroTikls SIA",
		"00:09:0F": "Fortinet Inc",
		"00:1B:17": "Palo Alto Networks",
		"00:09:5B": "NETGEAR, Inc",
		"00:05:5F": "D-Link Corporation",
		"00:03:2F": "Linksys",
		"00:02:B3": "Intel Corporation",
		"00:E0:4C": "REALTEK SEMICONDUCTOR CORP.",
		"00:02:C9": "Mellanox Technologies, Inc.",
		"00:0E:1E": "QLogic Corp",
		"00:02:55": "IBM Corporation",
		"00:25:90": "Super Micro Computer, Inc.",
		"00:05:69": "VMware, Inc.",
		"00:0C:29": "VMware, Inc.",
		"00:50:56": "VMware, Inc.",
		"00:03:FF": "Microsoft Corporation",
		"00:15:5D": "Microsoft Corporation",
		"00:16:3E": "XenSource, Inc.",
		"00:03:93": "Apple, Inc.",
		"00:07:AB": "Samsung Electronics Co.,Ltd",
		"00:01:64": "Lenovo Mobile Communication Technology Ltd.",
		"00:01:80": "ASUSTek COMPUTER INC.",
		"00:01:24": "Acer Incorporated",
		"3C:5A:B4": "Google, Inc.",
		"B8:27:EB": "Raspberry Pi Foundation",
		"24:0A:C4": "Espressif Inc.",
	}
	
	// Vulnerability database
	vulnDB = map[string][]string{
		"Apache HTTPD 2.4.44":  {"CVE-2020-9490"},
		"Apache HTTPD 2.4.48":  {"CVE-2019-17567"},
		"Apache HTTPD 2.4.50":  {"CVE-2021-41524"},
		"Apache HTTPD 2.4.53":  {"CVE-2022-22719"},
		"Apache HTTPD 2.4.54":  {"CVE-2022-26377", "CVE-2022-28330", "CVE-2022-28614", "CVE-2022-28615"},
		"OpenSSH 7.8p1":        {"CVE-2018-15473"},
		"OpenSSH 7.9p1":        {"CVE-2019-6110", "CVE-2019-6111"},
		"OpenSSH 8.5":          {"CVE-2021-28041"},
		"OpenSSH 9.2":          {"CVE-2023-25136"},
		"OpenSSH 9.3p2":        {"CVE-2023-38408"},
		"Nginx 1.6.1":          {"CVE-2014-3556"},
		"Nginx 1.6.2":          {"CVE-2014-3616"},
		"Nginx 1.9.10":         {"CVE-2016-0742", "CVE-2016-0746", "CVE-2016-0747"},
		"MySQL 5.7.31":         {"CVE-2018-2562"},
		"MySQL 8.0.22":         {"CVE-2020-2578", "CVE-2020-2621"},
		"PHP 7.4.28":           {"CVE-2021-21708"},
		"PHP 8.0.30":           {"CVE-2023-3824"},
		"OpenSSL 1.0.1g":       {"CVE-2014-0160"}, // Heartbleed
		"PostgreSQL 15.4":      {"CVE-2023-39418"},
	}
)

// Initialize scanner
func NewScanner(cfg *Config) (*Scanner, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	// Setup logger
	logger := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("app", APP_NAME).
		Str("version", VERSION).
		Logger()
	
	if cfg.Debug {
		logger = logger.Level(zerolog.DebugLevel)
	} else if cfg.Verbose {
		logger = logger.Level(zerolog.InfoLevel)
	} else {
		logger = logger.Level(zerolog.WarnLevel)
	}
	
	// Initialize cache
	cache, err := lru.New[string, interface{}](10000)
	if err != nil {
		return nil, fmt.Errorf("failed to create cache: %w", err)
	}
	
	// Initialize database
	var db *badger.DB
	if cfg.UseCache {
		opts := badger.DefaultOptions(cfg.DBPath)
		opts.Logger = nil
		db, err = badger.Open(opts)
		if err != nil {
			return nil, fmt.Errorf("failed to open database: %w", err)
		}
	}
	
	// Initialize rate limiter
	var rateLimiter *rate.Limiter
	if cfg.RateLimit > 0 {
		rateLimiter = rate.NewLimiter(rate.Limit(cfg.RateLimit), cfg.RateLimit)
	}
	
	// Initialize Blackrock for random port shuffling
	br := blackrock.New(65536, time.Now().UnixNano())
	
	// Initialize CIDR ranger
	ranger := cidranger.NewPCTrieRanger()
	
	// Initialize scanner
	s := &Scanner{
		config:          cfg,
		logger:          logger,
		metrics:         &Metrics{StartTime: time.Now()},
		cache:           cache,
		db:              db,
		limiter:         rateLimiter,
		blackrock:       br,
		cidranger:       ranger,
		portMap:         haxmap.New[int, *PortInfo](),
		done:            abool.New(),
		results:         make(chan *EnhancedScanResult, 1000),
		errors:          make(chan error, 100),
		ctx:             ctx,
		cancel:          cancel,
		customCVEs:      customCVEs,
		ouiData:         ouiData,
	}
	
	// Initialize components
	if err := s.initializeComponents(); err != nil {
		return nil, fmt.Errorf("failed to initialize components: %w", err)
	}
	
	return s, nil
}

// Initialize scanner components
func (s *Scanner) initializeComponents() error {
	// Initialize probe engine for service detection
	if s.config.ProbeFiles != "" {
		probeFiles := strings.Split(s.config.ProbeFiles, ",")
		for i := range probeFiles {
			probeFiles[i] = strings.TrimSpace(probeFiles[i])
		}
		var err error
		s.probeEngine, err = NewProbeEngine(probeFiles...)
		if err != nil {
			s.logger.Warn().Err(err).Msg("Failed to initialize probe engine")
		}
		probeEngineInstance = s.probeEngine // Set global instance for compatibility
	}
	
	// Initialize service database
	s.serviceDB = NewServiceDatabase(s.config.CacheDir)
	
	// Initialize fingerprint database
	s.fingerprintDB = NewFingerprintDatabase()
	
	// Initialize vulnerability database
	if s.config.VulnMapping {
		s.vulnDB = NewVulnerabilityDatabase(s.config.CacheDir, s.config.NVDAPIKey)
	}
	
	// Initialize script engine
	if s.config.ScriptScan {
		s.scriptEngine = NewScriptEngine()
		if err := s.scriptEngine.LoadScripts(); err != nil {
			return fmt.Errorf("failed to load scripts: %w", err)
		}
	}
	
	// Initialize ML engine
	if s.config.EnableML {
		s.ml = NewMLEngine()
		if err := s.ml.LoadModel(); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to load ML model")
		}
	}
	
	// Initialize network clients
	s.initializeClients()
	
	// Initialize raw socket for SYN scanning
	if s.config.SYNScan {
		if err := s.initializeRawSocket(); err != nil {
			return fmt.Errorf("failed to initialize raw socket: %w", err)
		}
	}
	
	// Initialize pcap for packet capture
	if s.config.Interface != "" {
		if err := s.initializePcap(); err != nil {
			return fmt.Errorf("failed to initialize pcap: %w", err)
		}
	}
	
	// Initialize worker pool
	concurrency := s.config.MaxConcurrency
	if concurrency <= 0 {
		concurrency = DEFAULT_CONCURRENCY
	}
	s.workers = NewWorkerPool(concurrency, s.ctx)
	
	// Load custom CVEs if provided
	if s.config.CVEPluginFile != "" {
		s.loadCustomCVEs()
	}
	
	return nil
}

// Initialize network clients
func (s *Scanner) initializeClients() {
	// HTTP client with custom settings
	s.httpClient = &fasthttp.Client{
		ReadTimeout:                   s.config.Timeout,
		WriteTimeout:                  s.config.Timeout,
		MaxIdleConnDuration:           time.Minute,
		MaxConnDuration:               time.Minute * 5,
		MaxConnsPerHost:               100,
		MaxResponseBodySize:           10 * 1024 * 1024, // 10MB
		DisableHeaderNamesNormalizing: true,
		DisablePathNormalizing:        true,
		NoDefaultUserAgentHeader:      true,
	}
	
	// DNS client
	s.dnsClient = &dns.Client{
		Timeout: s.config.Timeout,
		Net:     "tcp",
	}
	
	// TLS configuration
	s.tlsConfig = &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
	}
	
	// SSH configuration
	s.sshConfig = &ssh.ClientConfig{
		Timeout:         s.config.Timeout,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
}

// Initialize raw socket for SYN scanning
func (s *Scanner) initializeRawSocket() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		return fmt.Errorf("failed to create raw socket: %w", err)
	}
	
	// Set socket options
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		unix.Close(fd)
		return fmt.Errorf("failed to set IP_HDRINCL: %w", err)
	}
	
	s.rawSocket = fd
	return nil
}

// Initialize pcap for packet capture
func (s *Scanner) initializePcap() error {
	handle, err := pcap.OpenLive(
		s.config.Interface,
		65535,
		true,
		pcap.BlockForever,
	)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %w", s.config.Interface, err)
	}
	
	s.pcapHandle = handle
	
	// Start packet capture goroutine
	go s.capturePackets()
	
	return nil
}

// Capture packets
func (s *Scanner) capturePackets() {
	packetSource := gopacket.NewPacketSource(s.pcapHandle, s.pcapHandle.LinkType())
	
	for packet := range packetSource.Packets() {
		select {
		case <-s.ctx.Done():
			return
		default:
			s.processPacket(packet)
		}
	}
}

// Process captured packet
func (s *Scanner) processPacket(packet gopacket.Packet) {
	// Extract layers
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		
		// Process TCP packet
		if tcp.SYN && tcp.ACK {
			// SYN-ACK received, port is open
			s.metrics.OpenPorts.Add(1)
		} else if tcp.RST {
			// RST received, port is closed
			s.metrics.ClosedPorts.Add(1)
		}
	}
	
	s.metrics.PacketsReceived.Add(1)
}

// Main scan function incorporating old version features
func (s *Scanner) Scan() error {
	defer s.cleanup()
	
	s.logger.Info().
		Strs("targets", s.config.Targets).
		Str("ports", s.config.Ports).
		Msg("Starting scan")
	
	// Parse targets (supporting both old and new config styles)
	targets := s.parseAllTargets()
	if len(targets) == 0 {
		return fmt.Errorf("no valid targets specified")
	}
	
	// Parse ports
	ports := s.parseAllPorts()
	if len(ports) == 0 {
		return fmt.Errorf("no valid ports specified")
	}
	
	s.metrics.TotalHosts.Store(int64(len(targets)))
	s.metrics.TotalPorts.Store(int64(len(ports)))
	
	// Start result processor
	go s.processResults()
	
	// Start error handler
	go s.handleErrors()
	
	// Host discovery phase
	liveHosts := s.performHostDiscovery(targets)
	if len(liveHosts) == 0 {
		s.logger.Warn().Msg("No live hosts found")
		return nil
	}
	
	// Port scanning phase
	s.performPortScanning(liveHosts, ports)
	
	// Wait for completion
	s.wg.Wait()
	
	// Signal completion
	s.done.Set()
	close(s.results)
	close(s.errors)
	
	s.metrics.EndTime = time.Now()
	
	// Print summary
	s.printSummary()
	
	return nil
}

// Parse all target formats
func (s *Scanner) parseAllTargets() []string {
	var allTargets []string
	seen := make(map[string]bool)
	
	// From new config format
	allTargets = append(allTargets, s.config.Targets...)
	
	// From old config format (single host)
	if s.config.TargetHost != "" {
		for _, t := range strings.Split(s.config.TargetHost, ",") {
			allTargets = append(allTargets, strings.TrimSpace(t))
		}
	}
	
	// From target file
	if s.config.TargetFile != "" {
		if fileTargets := s.parseTargetFile(s.config.TargetFile); len(fileTargets) > 0 {
			allTargets = append(allTargets, fileTargets...)
		}
	}
	
	// From CIDR
	if s.config.CIDR != "" {
		if cidrTargets := s.parseCIDR(s.config.CIDR); len(cidrTargets) > 0 {
			allTargets = append(allTargets, cidrTargets...)
		}
	}
	
	// Expand CIDRs and deduplicate
	var finalTargets []string
	for _, target := range allTargets {
		expanded := s.expandTarget(target)
		for _, t := range expanded {
			if !seen[t] {
				finalTargets = append(finalTargets, t)
				seen[t] = true
			}
		}
	}
	
	// Remove excluded hosts
	if len(s.config.ExcludeHosts) > 0 {
		excludeMap := make(map[string]bool)
		for _, host := range s.config.ExcludeHosts {
			excludeMap[host] = true
		}
		
		var filtered []string
		for _, target := range finalTargets {
			if !excludeMap[target] {
				filtered = append(filtered, target)
			}
		}
		finalTargets = filtered
	}
	
	return finalTargets
}

// Parse target file
func (s *Scanner) parseTargetFile(filename string) []string {
	var targets []string
	
	file, err := os.Open(filename)
	if err != nil {
		s.logger.Error().Err(err).Str("file", filename).Msg("Failed to open target file")
		return targets
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}
	
	if err := scanner.Err(); err != nil {
		s.logger.Error().Err(err).Msg("Error reading target file")
	}
	
	return targets
}

// Parse CIDR notation
func (s *Scanner) parseCIDR(cidr string) []string {
	hosts, err := mapcidr.IPAddresses(cidr)
	if err != nil {
		s.logger.Error().Err(err).Str("cidr", cidr).Msg("Failed to parse CIDR")
		return nil
	}
	return hosts
}

// Expand target (handle CIDR, ranges, etc.)
func (s *Scanner) expandTarget(target string) []string {
	target = strings.TrimSpace(target)
	
	// Check if it's a CIDR
	if strings.Contains(target, "/") {
		ip, ipnet, err := net.ParseCIDR(target)
		if err != nil {
			// Not a valid CIDR, treat as single target
			return []string{target}
		}
		
		var ips []string
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
			ips = append(ips, ip.String())
			if len(ips) >= 131072 { // Safety limit
				s.logger.Warn().Str("cidr", target).Msg("CIDR too large, limiting expansion")
				break
			}
		}
		
		// Remove network and broadcast addresses for IPv4
		if len(ips) > 2 && ip.To4() != nil {
			ones, _ := ipnet.Mask.Size()
			if ones < 31 { // Not /31 or /32
				ips = ips[1 : len(ips)-1]
			}
		}
		
		return ips
	}
	
	// Single target
	return []string{target}
}

// Parse all port formats
func (s *Scanner) parseAllPorts() []int {
	var allPorts []int
	seen := make(map[int]bool)
	
	// From new config
	if s.config.Ports != "" {
		allPorts = append(allPorts, parsePortRange(s.config.Ports)...)
	}
	
	// From old config
	if s.config.PortRange != "" {
		allPorts = append(allPorts, parsePortRange(s.config.PortRange)...)
	}
	
	// Top ports
	if s.config.TopPorts > 0 {
		allPorts = append(allPorts, getTopPorts(s.config.TopPorts)...)
	}
	
	// Default ports if none specified
	if len(allPorts) == 0 {
		allPorts = getTopPorts(1000)
	}
	
	// Deduplicate
	var finalPorts []int
	for _, port := range allPorts {
		if !seen[port] && port > 0 && port <= 65535 {
			finalPorts = append(finalPorts, port)
			seen[port] = true
		}
	}
	
	// Shuffle for better distribution if fast mode
	if s.config.FastMode || s.config.UltraFastMode {
		shuffled := make([]int, len(finalPorts))
		for i, port := range finalPorts {
			shuffled[i] = int(s.blackrock.Shuffle(uint64(port)))
		}
		finalPorts = shuffled
	}
	
	return finalPorts
}

// Perform host discovery
func (s *Scanner) performHostDiscovery(targets []string) []string {
	if !s.config.PingSweepTCP && !s.config.PingSweepICMP {
		// No ping sweep, consider all targets as live
		s.logger.Info().Msg("No ping sweep enabled, considering all targets as live")
		return targets
	}
	
	s.logger.Info().Msg("Performing host discovery")
	
	var liveHosts []string
	var mu sync.Mutex
	
	// Parse ping ports
	pingPorts := parsePortRange(s.config.PingSweepPorts)
	if len(pingPorts) == 0 && s.config.PingSweepTCP {
		pingPorts = []int{80, 443, 22, 3389} // Default ports
	}
	
	pingTimeout := time.Duration(s.config.PingSweepTimeout) * time.Millisecond
	if pingTimeout <= 0 {
		pingTimeout = DEFAULT_PING_TIMEOUT * time.Millisecond
	}
	
	// Create progress bar
	var bar *progressbar.ProgressBar
	if !s.config.Quiet {
		bar = progressbar.NewOptions(len(targets),
			progressbar.OptionSetDescription("Host discovery"),
			progressbar.OptionShowCount(),
			progressbar.OptionShowIts(),
		)
	}
	
	// Perform discovery
	sem := make(chan struct{}, s.config.MaxConcurrency)
	var wg sync.WaitGroup
	
	for _, target := range targets {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			
			alive := false
			
			// Try ICMP first if enabled
			if s.config.PingSweepICMP {
				alive = s.isHostAliveICMP(host, pingTimeout)
			}
			
			// Try TCP if not alive and TCP enabled
			if !alive && s.config.PingSweepTCP {
				alive = s.isHostAliveTCP(host, pingPorts, pingTimeout)
			}
			
			if alive {
				mu.Lock()
				liveHosts = append(liveHosts, host)
				mu.Unlock()
			}
			
			if bar != nil {
				bar.Add(1)
			}
		}(target)
	}
	
	wg.Wait()
	
	s.logger.Info().Int("live_hosts", len(liveHosts)).Msg("Host discovery complete")
	return liveHosts
}

// Perform port scanning
func (s *Scanner) performPortScanning(hosts []string, ports []int) {
	totalScans := len(hosts) * len(ports)
	if s.config.UDPScan {
		totalScans *= 2 // Both TCP and UDP
	}
	
	s.logger.Info().
		Int("hosts", len(hosts)).
		Int("ports", len(ports)).
		Int("total_scans", totalScans).
		Msg("Starting port scanning")
	
	// Create progress bar
	var bar *progressbar.ProgressBar
	if !s.config.Quiet {
		bar = progressbar.NewOptions(totalScans,
			progressbar.OptionSetDescription("Port scanning"),
			progressbar.OptionShowCount(),
			progressbar.OptionShowIts(),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "=",
				SaucerHead:    ">",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}),
		)
	}
	
	// Semaphore for concurrency control
	sem = make(chan struct{}, s.config.MaxConcurrency)
	
	// Scan all host/port combinations
	for _, host := range hosts {
		for _, port := range ports {
			s.wg.Add(1)
			go func(h string, p int) {
				defer s.wg.Done()
				defer func() {
					if r := recover(); r != nil {
						s.logger.Error().
							Str("host", h).
							Int("port", p).
							Interface("panic", r).
							Msg("Panic during scan")
					}
				}()
				
				sem <- struct{}{}
				defer func() { <-sem }()
				
				// TCP scan
				if result := s.scanPort(h, p, "tcp"); result != nil {
					s.results <- result
				}
				
				// UDP scan if enabled
				if s.config.UDPScan {
					if result := s.scanPort(h, p, "udp"); result != nil {
						s.results <- result
					}
				}
				
				if bar != nil {
					bar.Add(1)
					if s.config.UDPScan {
						bar.Add(1)
					}
				}
				
				atomic.AddInt64(&s.scannedPorts, 1)
				if s.config.UDPScan {
					atomic.AddInt64(&s.scannedPorts, 1)
				}
			}(host, port)
		}
	}
}

//
