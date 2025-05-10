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

**r3cond0g** is an advanced network reconnaissance tool designed for security professionals and ethical hackers. Built with Go, it provides a powerful interface for network scanning, combining the speed of modern scanning techniques with comprehensive analysis capabilities.

## Features

- **Multiple Scan Types**: SYN, Connect, UDP, and Comprehensive scans
- **Service Detection**: Identify running services on open ports
- **OS Fingerprinting**: Detect operating systems running on target hosts
- **Script Scanning**: Run vulnerability assessment scripts
- **Performance Optimization**: Optional integration with rustscan for faster port discovery
- **Concurrent Scanning**: Multi-threaded scanning for efficiency
- **Flexible Target Specification**: Support for CIDR notation, IP ranges, and individual IPs
- **Interactive Mode**: User-friendly command-line interface
- **Detailed Output**: Comprehensive scan results with optional file output
- **Cross-Platform**: Works on both Linux and Windows systems

## Installation

### Prerequisites

- Go 1.16 or higher
- Nmap (required)
- Rustscan (optional, for faster scanning)

### From Source

```bash
# Clone the repository
git clone https://github.com/SecVulnHub/r3cond0g.git

# Navigate to the project directory
cd r3cond0g

# Build the project
go build -o r3cond0g

# Make it executable (Linux/macOS)
chmod +x r3cond0g
```

### Using Go Install

```bash
go install github.com/SecVulnHub/r3cond0g@latest
```

### Windows PowerShell Quick Deployment

```powershell
# Download and execute directly (for trusted environments only)
iex (irm https://raw.githubusercontent.com/SecVulnHub/r3cond0g/main/install.ps1)
```

## Usage

### Command Line Arguments

```
./r3cond0g [options]

Options:
  -targets string    Target specification (CIDR, IP range, or comma-separated IPs)
  -ports string      Port specification (e.g., 80,443,8080 or 1-1000) (default "1-1000")
  -scan string       Scan type (SYN, CONNECT, UDP, COMPREHENSIVE) (default "SYN")
  -threads int       Number of concurrent threads (default 100)
  -timeout int       Timeout in milliseconds (default 2000)
  -output string     Output file name
  -verbose           Enable verbose output
  -fast              Enable fast mode (uses rustscan if available)
  -service           Enable service detection
  -os                Enable OS detection
  -script            Enable script scanning
  -custom string     Custom nmap arguments
  -rustscan          Use rustscan for port discovery
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

## Disclaimer

This tool is intended for use by security professionals for legitimate security testing with proper authorization. Unauthorized scanning of networks is illegal and unethical. Always ensure you have explicit permission before scanning any network or system.

## About

- **Version**: 0.0.1 BETA
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
