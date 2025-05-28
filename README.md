# r3cond0g Network Reconnaissance Tool

**Authors:** 0xbv1 | 0xn0rn3

A powerful, multi-threaded network reconnaissance tool written in Go with advanced features including vulnerability mapping, topology generation, and Nmap integration.

## 🚀 Quick Start
Clone repo 
```bash
git clone https://github.com/0xb0rn3/r3cond0g
```
Change directory
```bash
cd r3cond0g
```
Make the runner executable and run
```bash
chmod +x run && ./run
```

The runner script will automatically:
- Detect your operating system
- Install Go if not present
- Install required dependencies
- Compile the tool
- Execute r3cond0g

## ✨ Features

### Core Scanning
- **Ultra-Fast TCP/UDP Scanning** - Multi-threaded port scanning with configurable concurrency
- **Service Detection** - Automatic service fingerprinting for discovered ports
- **Flexible Target Support** - Single hosts, ranges, and comma-separated lists

### Advanced Analysis
- **Nmap Integration** - Parse and analyze existing Nmap XML results
- **Vulnerability Mapping** - Automatic CVE lookup using NVD API
- **Network Topology** - Generate DOT format network graphs for visualization

### Export & Reporting
- **Multiple Formats** - Export results in JSON, CSV, or XML
- **Filtered Results** - Option to show only open ports
- **Real-time Progress** - Live scanning progress with performance metrics

## 🛠️ Manual Installation

If you prefer manual setup:

```bash
# Install Go (if not installed)
# Ubuntu/Debian: sudo apt-get install golang-go
# CentOS/RHEL: sudo yum install golang
# macOS: brew install go

# Clone and build
git clone https://github.com/0xb0rn3/r3cond0g
cd r3cond0g
go mod init r3cond0g
go mod tidy
go build -o r3cond0g main.go
./r3cond0g
```

## 📋 Usage Examples

### Basic Port Scan
1. Run the tool: `./r3cond0g`
2. Select "🚀 Run Ultra-Fast Scan"
3. Configure target via "🛠️ Configure Settings"

### Parse Nmap Results
1. Run: `./r3cond0g`
2. Select "📄 Parse Nmap Results"
3. Provide path to Nmap XML file

### Vulnerability Assessment
1. Configure NVD API key in settings
2. Enable vulnerability mapping
3. Run scan or parse existing results
4. View CVE information in results

## ⚙️ Configuration Options

- **Target Host(s)** - IP addresses or hostnames (comma-separated)
- **Port Range** - Port ranges (e.g., "1-1000", "80,443,8080")
- **Scan Timeout** - Connection timeout in milliseconds
- **Max Concurrency** - Number of simultaneous connections
- **UDP Scanning** - Enable UDP port scanning
- **Vulnerability Mapping** - CVE lookup via NVD API
- **Topology Mapping** - Network graph generation
- **Results Filtering** - Show only open ports

## 🔧 Dependencies
```bash
- Go 1.16+ (automatically installed by runner script)
- Network access for target scanning
- NVD API key for vulnerability mapping (optional)
- Graphviz for topology visualization (optional)
```
## 📊 Output Formats

### Console Display
Formatted table with host, port, protocol, state, service, and vulnerability information.

### Export Options
- **JSON** - Structured data for programmatic analysis
- **CSV** - Spreadsheet-compatible format
- **XML** - Structured markup for integration
- **DOT** - Network topology graphs (use with Graphviz)

## 🛡️ Security Features

- **CVE Integration** - Automatic vulnerability database lookup
- **Service Fingerprinting** - Identify services and versions
- **Secure Configuration** - API key masking and secure storage

## 🎯 Advanced Usage

### Network Topology Visualization
```bash
# Generate topology file
./r3cond0g
# Select "🌐 Generate Network Topology"
# Visualize with Graphviz
dot -Tpng scan_results-topology.dot -o network.png
```

### Automation Integration
```bash
# Use with existing Nmap scans
nmap -sS -O -sV -oX scan.xml target_network
./r3cond0g
# Select "📄 Parse Nmap Results" and provide scan.xml
```

## 📝 License
```bash
This tool is for educational and authorized security testing purposes only. Users are responsible for compliance with applicable laws and regulations.
```
## 🐛 Troubleshooting

### Common Issues

- **Permission Denied**: Ensure script is executable (`chmod +x run`)
- **Go Not Found**: Runner script will auto-install Go
- **Compilation Errors**: Check Go version (requires 1.16+)
- **Network Timeouts**: Adjust scan timeout in configuration

### Performance Tuning
```bash
- Reduce concurrency for unstable networks
- Increase timeout for slow targets
- Use TCP-only scanning for faster results
- Filter to open ports only for cleaner output
```
---
```bash
Version: 0.2.0  
Platform: Cross-platform (Linux, macOS, Windows)
```
