# r3cond0g

![Version](https://img.shields.io/badge/version-0.0.1--beta-orange)
![License](https://img.shields.io/badge/license-MIT-blue)

```
 _____  _____               _  ___       
|  __ \|___ /              | |/ _ \      
| |__) | |_ \  ___ ___   __| | | | | __ _
|  _  /|___) |/ __/ _ \ / _' | | | |/ _' |
| | \ \____/ | (_| (_) | (_| | |_| | (_| |
|_|  \_\_____|\___\___/ \__,_|\___/ \__, |
                                     __/ |
                                    |___/ 
```

**r3cond0g** is an advanced network reconnaissance and sniffing tool designed for security professionals, pentesters, and ethical hackers. Built with Go, it provides a powerful and versatile interface for network scanning and traffic analysis, combining the speed of modern scanning techniques with comprehensive analysis capabilities suitable for CTFs and red team training.

## Features

* **Multiple Nmap Scan Types**: SYN, Connect, TCP, UDP, NULL, FIN, XMAS, AGGRESSIVE, and Comprehensive scans.
* **Service & Version Detection**: Identify running services and their versions on open ports using Nmap.
* **OS Fingerprinting**: Detect operating systems running on target hosts via Nmap.
* **Nmap Script Scanning**: Run Nmap's default vulnerability and discovery scripts.
* **Performance Optimization**:
    * Optional integration with **Rustscan** for significantly faster initial port discovery.
    * Concurrent scanning using Go routines for efficiency.
* **Native Banner Grabbing**: Fast, concurrent banner grabbing for open TCP ports.
* **Vulnerability Insights (BETA)**:
    * Identifies potential vulnerabilities based on discovered service versions.
    * Includes an internal, expandable list of common vulnerabilities.
    * Supports loading custom vulnerability definitions from a user-provided JSON file.
* **Web Directory & File Discovery (BETA)**:
    * Performs basic directory and file brute-forcing on identified HTTP/S services.
    * Uses an internal default wordlist or a custom user-provided wordlist.
* **Live Packet Sniffing (BETA)**:
    * Captures live network traffic on a specified interface using `gopacket`.
    * Supports BPF (Berkeley Packet Filter) syntax for traffic filtering.
    * Provides a real-time summary of captured traffic and common protocols.
    * Option to save captured packets to a `.pcap` file.
* **Flexible Target Specification**: Support for CIDR notation, IP ranges, individual IPs, and loading targets from a file.
* **Interactive Mode**: User-friendly command-line menu for easy configuration.
* **Detailed Output & Reporting**:
    * Comprehensive scan results.
    * Multiple output formats: Text, JSON, and HTML (BETA).
    * Optional file output for all formats.
* **Configuration Management**: Saves and loads scan configurations.
* **Cross-Platform**: Built with Go, aiming for compatibility across Linux, Windows, and macOS (external tools and sniffing libraries have their own dependencies).

## Installation

### Prerequisites

* **Go**: Version 1.18 or higher.
* **Nmap**: Required for core scanning functionality. Ensure it's in your system's PATH.
* **Rustscan**: Optional, for `-rustscan` fast port discovery. Ensure it's in your system's PATH.
* **Packet Capture Libraries (for Sniffing feature)**:
    * **Linux**: `libpcap-dev` (e.g., `sudo apt-get install libpcap-dev`)
    * **macOS**: `libpcap` (usually via Xcode command-line tools or `brew install libpcap`)
    * **Windows**: `Npcap` (from [nmap.org/npcap/](https://nmap.org/npcap/), install with SDK option).
* **C Compiler (for Sniffing feature via Cgo)**:
    * **Linux**: `gcc` (e.g., `sudo apt-get install build-essential`)
    * **macOS**: Xcode Command Line Tools (`xcode-select --install`)
    * **Windows**: MinGW-w64 or similar.

### From Source (Recommended)

```bash
# git clone https://github.com/0xb0rn3/r3cond0g
# cd r3cond0g

# Ensure you have the main.go file in your current directory

# Get gopacket dependency
go get github.com/google/gopacket@latest
go mod init r3cond0g
go mod tidy


# Build the project
go build -o r3cond0g main.go

# Make it executable (Linux/macOS)
chmod +x r3cond0g

# Run
./r3cond0g

Using go install (If the tool is published to a Go module path)

If the authors publish it, for example, at github.com/0xb0rn3/r3cond0g (this is a placeholder URL):
Bash

go install github.com/0xb0rn3/r3cond0g@latest

(This command will only work if the authors set up a proper Go module and repository.)
Usage
Command Line Arguments

Run ./r3cond0g -h to see all available options. Some key flags include:

./r3cond0g [options]

Options:
  -targets string        Target specification (CIDR, IP range, or comma-separated IPs)
  -file string           Path to a file containing a list of targets
  -ports string          Port specification (e.g., 80,443 or 1-1000)
  -common-ports          Scan common ports (overrides -ports)
  -all-ports             Scan all 65535 ports (overrides -ports and -common-ports)
  -scan string           Nmap scan type (SYN, CONNECT, TCP, UDP, NULL, FIN, XMAS, AGGRESSIVE, COMPREHENSIVE) (default "SYN")
  -threads int           Number of concurrent Nmap threads/operations (default 10)
  -timeout int           Timeout in milliseconds for individual probes/operations (default 3000)
  -output string         Output file name (prefix, format will be appended)
  -format string         Output format (text, json, html) (default "text")
  -verbose               Enable verbose output
  -service               Enable Nmap service detection (-sV) (default true)
  -os                    Enable Nmap OS detection (-O) (default true)
  -script                Enable Nmap default script scanning (default false)
  -custom string         Custom nmap arguments
  -rustscan              Use rustscan for initial fast port discovery (default true if available)
  -banners               Attempt to grab banners from open TCP ports (default true)
  -vuln-insights         Enable basic vulnerability insights (default true)
  -custom-vuln-db string Path to custom vulnerability DB JSON file
  -web-discover          Enable basic web directory/file discovery (default false)
  -web-wordlist string   Path to custom wordlist for web discovery
  -sniff-iface string    Network interface for sniffing
  -sniff-duration int    Duration for sniffing in seconds (0 for indefinite) (default 60)
  -sniff-filter string   BPF filter for sniffing
  -sniff-pcap string     File to save sniffed packets (e.g., capture.pcap)
  -save-config           Save current settings to config file on exit from menu (default true)

```

### Interactive Mode

Simply run `r3cond0g` without arguments to enter interactive mode:

```bash
./r3cond0g
```

Follow the prompts to configure your scan.

### Examples

Basic SYN scan of a network:
```bash
./r3cond0g -targets 192.168.1.0/24 -ports 1-1000
```

Comprehensive scan of a single host:
```bash
./r3cond0g -targets 192.168.1.10 -scan COMPREHENSIVE -service -os -script
```

Fast scan using rustscan:
```bash
./r3cond0g -targets 10.0.0.0/24 -rustscan -ports 1-65535
```

## Sample Output

```
=== Scan Results (3 hosts) ===

------------------------------------
Host: 192.168.1.1 (router.local)
OS: Linux 3.x
Open Ports: 5
PORT    STATE   SERVICE
22/tcp  open    ssh
53/tcp  open    domain
80/tcp  open    http
443/tcp open    https
8080/tcp open   http-proxy

------------------------------------
Host: 192.168.1.10 (desktop.local)
OS: Windows 10 21H2
Open Ports: 3
PORT    STATE   SERVICE
135/tcp open    msrpc
445/tcp open    microsoft-ds
3389/tcp open   ms-wbt-server

------------------------------------
Host: 192.168.1.20 (server.local)
OS: Ubuntu Server 20.04
Open Ports: 2
PORT    STATE   SERVICE
22/tcp  open    ssh
3306/tcp open   mysql

=== End of Results ===
```
Interactive Mode

Simply run r3cond0g without arguments to enter the interactive menu:
## Disclaimer

This tool is intended for use by security professionals for legitimate security testing with proper authorization. Unauthorized scanning of networks is illegal and unethical. Always ensure you have explicit permission before scanning any network or system.

Follow the on-screen prompts to configure your scan parameters, sniffing options, analysis features, and output settings.
Examples

    Aggressive Nmap scan on a network, with vulnerability insights and web discovery, saving to JSON:
    ./r3cond0g -targets 192.168.1.0/24 -scan AGGRESSIVE -vuln-insights -web-discover -output results_net1 -format json
    Fast Rustscan discovery on common ports for a single host, followed by detailed Nmap service scan:
    ./r3cond0g -targets 10.10.10.5 -rustscan -common-ports -service
    Sniff HTTP traffic on eth0 indefinitely and save to webapp.pcap:
    sudo ./r3cond0g -sniff-iface eth0 -sniff-duration 0 -sniff-filter "tcp port 80 or tcp port 443" -sniff-pcap webapp.pcap
Sample Output (Text Format - Illustrative)
    === Scan Results (1 host processed) ===

====================================
Host: 192.168.1.10 (example.local)
OS Guess: Linux 5.4
Rustscan Initial Ports: 21, 22, 80, 443, 3306
--- Open Ports & Services ---
PORT     STATE  SERVICE                  VERSION & BANNER
-------- ------ ------------------------ --------------------------------------------------
21/tcp   open   ftp                      vsftpd 3.0.3 | Banner: 220 (vsFTPd 3.0.3)
22/tcp   open   ssh                      OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 | Banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.4
80/tcp   open   http                     Apache httpd 2.4.49 ((Ubuntu)) | Banner: HTTP/1.1 200 OK...
443/tcp  open   ssl/http                 Apache httpd 2.4.49 ((Ubuntu)) | Banner: HTTP/1.1 200 OK...
3306/tcp open   mysql                    MySQL 8.0.28-0ubuntu0.20.04.3 | Banner: Z.....
...

--- Web Discovery ---
  [200] http://192.168.1.10:80/ (Title: Welcome to Apache!, Length: 11321)
  [301] http://192.168.1.10:80/admin (Title: Redirect: /admin/, Length: 312)
  [403] http://192.168.1.10:80/.git/HEAD (Title: Forbidden, Length: 279)

--- Potential Vulnerability Insights ---
  Port 80 (Apache httpd 2.4.49): [Critical] Path Traversal & RCE (CVE-2021-41773, CVE-2021-42013). (Ref: CVE-2021-41773) (Source: internal)
  Port 22 (OpenSSH 8.2p1 Ubuntu 4ubuntu0.4): [Low] Potential regex DoS in ssh-add (CVE-2021-28041), less impactful for server. (Ref: CVE-2021-28041) (Source: internal)
...
====================================

=== End of Scan Results ===


## About

- **Version**: 0.0.2 BETA
- **Designed by**: [0xb0rn3](https://github.com/0xb0rn3)
- **Maintained by**: [SecVulnHub](https://github.com/SecVulnHub)
- **License**: MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
