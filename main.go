package main

import (
    "bufio"
    "fmt"
    "net"
    "os"
    "strings"
    "sync"
    "sync/atomic"
    "time"
)

type Config struct {
    TargetHost     string
    TargetFile     string
    PortRange      string
    ScanTimeout    int
    MaxConcurrency int
    UDPScan        bool
    VulnMapping    bool
}

type EnhancedScanResult struct {
    Host         string
    Port         int
    Protocol     string
    State        string
    Service      string
    Version      string
    ResponseTime time.Duration
    Timestamp    time.Time
    OSGuess      string
}

var (
    config = Config{
        PortRange:      "1-1000",
        ScanTimeout:    500,
        MaxConcurrency: 100,
    }
    results      []EnhancedScanResult
    mutex        sync.Mutex
    wg           sync.WaitGroup
    sem          chan struct{}
    scannedPorts int64
)

func main() {
    if validateConfig() {
        results = runUltraFastScan()
        displayResults()
    } else {
        fmt.Println("❌ Scan aborted due to invalid configuration.")
    }
}

func parsePortRange(portRange string) []int {
    var ports []int
    ranges := strings.Split(portRange, ",")
    for _, r := range ranges {
        r = strings.TrimSpace(r)
        if strings.Contains(r, "-") {
            parts := strings.Split(r, "-")
            start, _ := strconv.Atoi(parts[0])
            end, _ := strconv.Atoi(parts[1])
            for i := start; i <= end; i++ {
                ports = append(ports, i)
            }
        } else {
            port, _ := strconv.Atoi(r)
            ports = append(ports, port)
        }
    }
    return ports
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
    return service, "unknown" // Simplified; assumes portProbes not provided
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

func runUltraFastScan() []EnhancedScanResult {
    fmt.Println("🚀 Starting ultra-fast scan...")
    hosts := parseTargets(config.TargetHost, config.TargetFile)
    if len(hosts) == 0 {
        fmt.Println("❌ No valid targets found.")
        return nil
    }
    ports := parsePortRange(config.PortRange)
    if len(ports) == 0 {
        fmt.Println("❌ No valid ports found.")
        return nil
    }
    totalScans := int64(len(hosts) * len(ports))
    if config.UDPScan {
        totalScans *= 2
    }
    fmt.Printf("📊 Scanning %d hosts across %d ports (%d total scans)\n", len(hosts), len(ports), totalScans)
    if totalScans > 100000 {
        fmt.Printf("⚠️  Warning: Large scan detected (%d operations).\n", totalScans)
        fmt.Print("Continue? (y/N): ")
        var response string
        fmt.Scanln(&response)
        if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
            fmt.Println("❌ Scan cancelled.")
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
                fmt.Printf("\r🔍 Progress: %d/%d (%.1f%%) - Found: %d", current, totalScans, percentage, len(results))
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
                    mutex.Lock()
                    results = append(results, *result)
                    mutex.Unlock()
                    fmt.Printf("\r✅ Found TCP port: %s:%d (%s)", h, p, result.Service)
                }
                if config.UDPScan {
                    if result := scanUDPPort(h, p); result != nil {
                        mutex.Lock()
                        results = append(results, *result)
                        mutex.Unlock()
                        fmt.Printf("\r✅ Found UDP port: %s:%d (%s)", h, p, result.Service)
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
        fmt.Printf("⚡ Scan rate: %.0f ports/second\n", float64(totalScans)/elapsed.Seconds())
    }
    return results
}

func validateConfig() bool {
    fmt.Println("🔧 Validating configuration...")
    if config.TargetHost == "" && config.TargetFile == "" {
        fmt.Println("❌ No target specified.")
        return false
    }
    ports := parsePortRange(config.PortRange)
    if len(ports) == 0 {
        fmt.Println("❌ Invalid port range.")
        return false
    }
    if config.TargetFile != "" {
        if _, err := os.Stat(config.TargetFile); os.IsNotExist(err) {
            fmt.Printf("❌ Target file does not exist: %s\n", config.TargetFile)
            return false
        }
    }
    if config.ScanTimeout < 100 || config.ScanTimeout > 30000 {
        fmt.Println("⚠️  Timeout should be between 100ms and 30000ms.")
    }
    if config.MaxConcurrency < 1 || config.MaxConcurrency > 1000 {
        fmt.Println("⚠️  Concurrency should be between 1 and 1000.")
    }
    fmt.Println("✅ Configuration valid.")
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

func displayResults() {
    if len(results) == 0 {
        fmt.Println("❌ No results to display.")
        return
    }
    fmt.Printf("\n📊 Scan Results (%d ports):\n", len(results))
    for _, r := range results {
        fmt.Printf("Host: %s, Port: %d, Protocol: %s, State: %s, Service: %s\n",
            r.Host, r.Port, r.Protocol, r.State, r.Service)
    }
}

// Stub functions (not in changes.txt, simplified from thinking trace)
func guessOS(result *EnhancedScanResult) string {
    return "unknown" // Placeholder
}

func mapVulnerabilities(result *EnhancedScanResult) {
    // Placeholder for vulnerability mapping
}
