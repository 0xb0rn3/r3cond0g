# r3cond0g (RECONRAPTOR) 🦅
### *Hunt. Scan. Conquer.*

<div align="center">
  
[![Version](https://img.shields.io/badge/Version-0.2.2-red.svg?style=for-the-badge&logo=github)](https://github.com/0xb0rn3/r3cond0g)
[![Go Version](https://img.shields.io/badge/Go-1.18+-00ADD8.svg?style=for-the-badge&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)
[![Build Status](https://img.shields.io/github/actions/workflow/status/0xb0rn3/r3cond0g/go.yml?branch=main&style=for-the-badge&logo=github-actions)](https://github.com/0xb0rn3/r3cond0g/actions)

**Developed by:** [0xb0rn3](https://github.com/0xb0rn3) & [0xbv1](https://instagram.com/theehiv3) 

*A lightning-fast, multi-threaded network reconnaissance tool engineered for modern penetration testing and security assessments.*

[🚀 Quick Start](#-quick-start) • [📖 Documentation](#-usage) • [🛠️ Installation](#-installation) • [🤝 Contributing](#-contributing)

</div>

---

## 🎯 **What is RECONRAPTOR?**

RECONRAPTOR is a cutting-edge network reconnaissance framework built in Go that combines speed, precision, and intelligence. Unlike traditional scanning tools, RECONRAPTOR integrates advanced vulnerability mapping, network topology generation, and multi-format reporting into a single, powerful platform designed for security professionals who demand both performance and comprehensive results.

### 🔥 **Why Choose RECONRAPTOR?**

Modern networks require modern tools. RECONRAPTOR addresses the limitations of legacy scanners by providing a unified platform that not only discovers services but intelligently maps vulnerabilities and generates actionable intelligence for security assessments.

---

## ⚡ **Core Capabilities**

<table>
<tr>
<td width="50%">

### 🚀 **Ultra-Performance Scanning**
- **Multi-threaded Architecture**: Concurrent TCP/UDP port scanning
- **Intelligent Optimization**: Prioritizes common ports for faster results  
- **Configurable Concurrency**: Customize thread count for optimal performance
- **Smart Timeouts**: Adaptive timeout handling for various network conditions

### 🔬 **Advanced Intelligence Gathering**
- **Service Fingerprinting**: Deep service detection and version identification
- **OS Detection**: Intelligent operating system identification
- **Banner Grabbing**: Comprehensive service banner analysis
- **Protocol Analysis**: Multi-protocol support and analysis

</td>
<td width="50%">

### 🛡️ **Vulnerability Intelligence**
- **NVD Integration**: Real-time CVE lookup using NVD API 2.0
- **Custom CVE Plugins**: Support for private vulnerability databases
- **Automated Mapping**: Links discovered services to known vulnerabilities
- **Risk Assessment**: Contextual vulnerability scoring and prioritization

### 🗺️ **Network Topology & Visualization**
- **Topology Generation**: Creates network maps in DOT format
- **Graphviz Compatibility**: Professional network diagrams
- **Relationship Mapping**: Visualizes network interconnections
- **Export Flexibility**: Multiple visualization output formats

</td>
</tr>
</table>

---

## 🎯 **Target Flexibility**

RECONRAPTOR adapts to your reconnaissance needs with comprehensive targeting options:

**Single Host Scanning**: `./r3cond0g -target 192.168.1.1`
**CIDR Range Scanning**: `./r3cond0g -target 192.168.1.0/24`  
**Multiple Targets**: `./r3cond0g -target 10.0.0.1,172.16.0.1,192.168.1.1`
**File-Based Targeting**: `./r3cond0g -target-file targets.txt`
**Nmap Integration**: `./r3cond0g -nmap-file scan_results.xml`

---

## 🚀 **Quick Start**

### **Automated Setup (Recommended)**

The intelligent runner script handles everything from dependency checks to compilation:

```bash
# Clone the repository
git clone https://github.com/0xb0rn3/r3cond0g.git
cd r3cond0g

# Execute the automated setup
chmod +x run && ./run
```

The runner automatically detects your system, verifies dependencies (Git, Go), checks for updates, compiles the binary, and launches RECONRAPTOR with an intuitive interface.

### **Manual Installation**

For users who prefer granular control over the installation process:

```bash
# Ensure Go 1.18+ is installed
go version

# Clone and initialize
git clone https://github.com/0xb0rn3/r3cond0g.git
cd r3cond0g
go mod init r3cond0g
go mod tidy

# Build with optimization flags
go build -ldflags="-s -w" -o r3cond0g main.go

# Launch RECONRAPTOR
./r3cond0g
```

---

## 📖 **Usage**

### **Interactive Mode**

RECONRAPTOR features an intuitive menu-driven interface perfect for both beginners and experts:

```
🦅 RECONRAPTOR v0.2.2 - Network Reconnaissance Suite

1. 🚀 Execute Ultra-Fast Scan
2. ⚙️  Configure Scan Parameters  
3. 📊 Display Current Results
4. 💾 Save Results (JSON Format)
5. 📄 Import Nmap XML Results
6. 🔍 Perform Vulnerability Analysis
7. 🗺️  Generate Network Topology
8. 📤 Export Multi-Format Reports
9. ❌ Exit Application
```

### **Command Line Interface**

For automation and integration into security workflows:

```bash
# Comprehensive scan with vulnerability mapping
./r3cond0g -target 192.168.1.0/24 -ports 1-65535 -vuln -nvd-key YOUR_API_KEY

# Fast common ports scan
./r3cond0g -target example.com -ports 80,443,22,21,25,53,110,995 -timeout 5000

# UDP service discovery
./r3cond0g -target 10.0.0.1 -udp -ports 53,67,68,69,123,161,162

# Import and analyze existing Nmap results
./r3cond0g -nmap-file previous_scan.xml -vuln -output analysis_report
```

### **Advanced Configuration Options**

| Parameter | Description | Example |
|-----------|-------------|---------|
| `-target` | Target specification (IP, CIDR, hostname) | `192.168.1.0/24` |
| `-target-file` | File containing target list | `targets.txt` |
| `-ports` | Port range or specific ports | `1-1000` or `80,443,22` |
| `-timeout` | Connection timeout (milliseconds) | `5000` |
| `-concurrency` | Maximum concurrent connections | `100` |
| `-udp` | Enable UDP scanning | Boolean flag |
| `-vuln` | Enable vulnerability mapping | Boolean flag |
| `-nvd-key` | NVD API key for CVE lookup | `your-api-key-here` |
| `-output` | Output file basename | `security_assessment` |

---

## 🔧 **Configuration & Setup**

### **NVD API Integration**

For comprehensive vulnerability analysis, obtain a free API key from the [National Vulnerability Database](https://nvd.nist.gov/developers/request-an-api-key):

```bash
# Environment variable (recommended)
export NVD_API_KEY="your-nvd-api-key"

# Command line parameter
./r3cond0g -nvd-key "your-nvd-api-key" -vuln

# Interactive configuration
./r3cond0g
# Select option 2 (Configure Settings)
```

### **Custom CVE Database**

Integrate private vulnerability data using JSON format:

```json
{
  "Apache httpd 2.4.50": ["CVE-2021-41773", "CVE-2021-42013"],
  "OpenSSH 8.2p1": ["CVE-2020-15778"],
  "nginx 1.18.0": ["CVE-2021-23017"]
}
```

Load custom CVE data: `./r3cond0g -cve-plugin custom_vulnerabilities.json`

---

## 📊 **Output & Reporting**

RECONRAPTOR generates comprehensive reports in multiple formats to support various workflows:

### **Real-time Console Output**
- Live progress indicators with ETA calculations
- Formatted result tables with color-coded status
- Scan statistics and performance metrics

### **Structured Data Formats**
- **JSON**: Complete scan data for programmatic analysis
- **CSV**: Spreadsheet-compatible format for data manipulation  
- **XML**: Structured markup for tool integration
- **HTML**: Professional reports with embedded styling

### **Network Visualization**
- **DOT Files**: Graphviz-compatible topology maps
- **PNG/SVG**: Rendered network diagrams (`dot -Tpng topology.dot -o network_map.png`)

---

## 🛡️ **Security & Compliance**

### **Ethical Usage Guidelines**

RECONRAPTOR is designed exclusively for authorized security testing and educational purposes. Users must understand and accept the following responsibilities:

**Legal Authorization**: Always obtain explicit written permission before scanning networks or systems you do not own. Unauthorized network scanning may violate local, national, or international laws.

**Professional Standards**: Use RECONRAPTOR only within the scope of authorized penetration testing engagements, security assessments, or educational environments.

**Responsible Disclosure**: When vulnerabilities are discovered during authorized testing, follow responsible disclosure practices and coordinate with system owners.

### **Compliance Considerations**

Organizations using RECONRAPTOR should ensure alignment with relevant frameworks such as NIST Cybersecurity Framework, ISO 27001, and industry-specific regulations. Maintain proper documentation of authorized testing activities and results.

---

## 🔧 **Troubleshooting**

### **Common Issues & Solutions**

**Installation Problems**:
- Verify Go version compatibility (1.18+ required): `go version`
- Ensure Git is installed and accessible: `git --version`
- Check network connectivity for dependency downloads

**Performance Optimization**:
- Reduce concurrency for unstable networks: `-concurrency 50`
- Increase timeout for slow targets: `-timeout 10000`
- Focus on specific port ranges rather than full scans for initial reconnaissance

**API Integration Issues**:
- Verify NVD API key validity and quota limits
- Check internet connectivity for NVD API access
- Monitor rate limiting messages and adjust scan timing accordingly

---

## 🛠️ **Technical Architecture**

RECONRAPTOR is built on a modern, modular architecture that prioritizes performance, maintainability, and extensibility:

### **Core Components**
- **Scan Engine**: Multi-threaded Go routines for concurrent network operations
- **Service Detection**: Pattern matching and banner analysis for service identification
- **Vulnerability Engine**: NVD API integration with local caching and rate limiting
- **Export Framework**: Pluggable output modules supporting multiple formats
- **CLI Interface**: Comprehensive command-line parser with validation

### **Dependencies & Requirements**
- **Go Runtime**: Version 1.18 or higher for optimal performance
- **Network Access**: Internet connectivity for vulnerability database queries
- **System Resources**: Sufficient memory and file descriptors for concurrent operations
- **Optional Tools**: Graphviz for network topology visualization

---

## 🤝 **Contributing**

RECONRAPTOR thrives through community collaboration. We welcome contributions from security professionals, developers, and researchers who share our vision of advancing open-source security tooling.

### **How to Contribute**

**Bug Reports**: Submit detailed issue reports with reproduction steps and system information through GitHub Issues.

**Feature Requests**: Propose new capabilities with clear use cases and implementation considerations.

**Code Contributions**: Fork the repository, create feature branches, and submit pull requests with comprehensive testing.

**Documentation**: Improve user guides, technical documentation, and code comments to enhance project accessibility.

### **Development Standards**

Contributors should follow Go best practices, maintain backward compatibility where possible, and include appropriate test coverage for new features. All submissions undergo code review to ensure quality and security standards.

---

## 📄 **License & Acknowledgments**

RECONRAPTOR is released under the MIT License, promoting open-source collaboration while maintaining flexibility for both personal and commercial use. See the [LICENSE](LICENSE) file for complete terms and conditions.

### **Credits**
- Core development by [0xb0rn3](https://github.com/0xb0rn3) and [0xbv1](https://instagram.com/theehiv3)
- Built with the Go programming language and ecosystem
- Vulnerability data provided by the National Vulnerability Database (NVD)
- Community contributions and feedback from security professionals worldwide

---

<div align="center">

**🦅 RECONRAPTOR - Hunt. Scan. Conquer. 🦅**

*Empowering security professionals with next-generation reconnaissance capabilities*

[![GitHub](https://img.shields.io/badge/GitHub-r3cond0g-black?style=for-the-badge&logo=github)](https://github.com/0xb0rn3/r3cond0g)
[![Follow](https://img.shields.io/badge/Follow-@theehiv3-E4405F?style=for-the-badge&logo=instagram)](https://instagram.com/theehiv3)

**Remember: With great power comes great responsibility. Scan ethically.**

</div>
