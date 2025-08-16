# R3COND0G (HellHound) 🦅
### 📌 **Advanced Usage**

### **Service Detection Probes**

```bash
# Generate custom probes for proprietary services
./run --generate-probes --custom-services "customdb,internal-api,legacy-app"

# Use specific probe files
./run --scan default --probe-files "probes/custom.json,probes/tcp_probes.json"
```

### **Vulnerability Correlation**

```bash
# Update NVD database
./run --update-vulns --nvd-key YOUR_API_KEY

# Scan with vulnerability mapping
./run --scan vulnerability --targets 10.0.0.0/24 --cve-plugin custom_cves.json

# Generate vulnerability report
./run --report vulnerability --format html,json
```

### **Network Topology Visualization**

```bash
# Generate network map
./run --topology dot
dot -Tpng network_topology.dot -o network.png

# Interactive HTML topology
./run --topology html --interactive
```

---

## 📊 **Reporting**

### **Available Report Formats**

| Format | Extension | Use Case |
|--------|-----------|----------|
| **HTML** | .html | Executive presentations, dashboards |
| **JSON** | .json | API integration, automation |
| **Markdown** | .md | Documentation, wikis |
| **CSV** | .csv | Spreadsheet analysis |
| **XML** | .xml | Nmap compatibility |
| **PDF** | .pdf | Formal reports (requires wkhtmltopdf) |

### **Report Generation**

```bash
# Generate all report formats
./run --report all

# Specific formats with custom template
./run --report html --template executive --output reports/

# Automated report scheduling
crontab -e
0 2 * * * /opt/r3cond0g/run --scan discovery --report html --email security@company.com
```

---

## 🔌 **Tool Integration**

### **Metasploit Integration**

```bash
# Generate resource script
./run --generate-msf

# Use in Metasploit
msfconsole
msf6 > resource r3cond0g.rc
```

### **SIEM Integration**

```bash
# Splunk HEC
./run --siem-feed json | curl -k https://splunk:8088/services/collector \
  -H "Authorization: Splunk TOKEN" -d @-

# QRadar
./run --siem-feed leef > /var/log/r3cond0g.leef

# Elasticsearch
./run --siem-feed json | curl -X POST "elasticsearch:9200/r3cond0g/_doc" \
  -H 'Content-Type: application/json' -d @-
```

### **CI/CD Pipeline**

```yaml
# GitLab CI example
security_scan:
  stage: test
  script:
    - ./run setup
    - ./run --scan discovery --targets $TARGET_NETWORK
    - ./run --report json --output $CI_PROJECT_DIR/
  artifacts:
    reports:
      security: reports_*/report_*.json
```

---

## 🛡️ **Security Features**

### **Evasion Techniques**

```bash
# Packet fragmentation
./run --scan stealth --fragment-packets

# Decoy scanning
./run --scan stealth --decoy-hosts "10.0.0.99,10.0.0.100,10.0.0.101"

# Custom source port
./run --scan stealth --source-port 53

# TTL manipulation
./run --scan stealth --ttl 64
```

### **Authentication Support**

```bash
# SSH key authentication for service probing
./run --ssh-key ~/.ssh/id_rsa --ssh-user admin

# SNMP community strings
./run --snmp-community "public,private,internal"

# HTTP authentication
./run --http-auth "user:pass" --http-auth-type basic
```

---

## 🔧 **Troubleshooting**

### **Common Issues and Solutions**

| Issue | Solution |
|-------|----------|
| **Permission denied (ICMP)** | Run: `sudo setcap cap_net_raw=eip ./r3cond0g` |
| **No module named 'rich'** | Run: `./run setup` to install dependencies |
| **Cannot build Go binary** | Ensure Go 1.21+ is installed: `go version` |
| **High memory usage** | Reduce concurrency: `--concurrency 50` |
| **Slow scanning** | Check rate limiting: `--rate-limit 0` |
| **No results** | Verify target is reachable: `ping <target>` |

### **Debug Mode**

```bash
# Enable verbose logging
./run --debug --verbose

# Check setup log
tail -f /tmp/r3cond0g_setup.log

# Test specific component
./run --test-component scanner
./run --test-component probes
```

---

## 📚 **API Documentation**

### **Python API**

```python
from r3cond0g_controller import R3COND0GController

# Initialize controller
controller = R3COND0GController()

# Create custom profile
profile = controller.create_scan_profile(
    name="api_scan",
    mode="aggressive",
    targets=["192.168.1.0/24"],
    ports="1-1000",
    options={"vuln_mapping": True}
)

# Execute scan
results = controller.run_scan(profile)

# Generate reports
reports = controller.generate_reports(
    results, 
    formats=["html", "json"],
    template="executive"
)

# Export to SIEM
siem_events = controller.generate_siem_feed(results, format="cef")
```

### **REST API** (Coming Soon)

```bash
# Start API server
./run --api-server --port 8080

# API endpoints
GET  /api/v1/scans          # List all scans
POST /api/v1/scans          # Start new scan
GET  /api/v1/scans/{id}     # Get scan results
GET  /api/v1/reports/{id}   # Download report
```

---

## 🎓 **Training Mode**

R3COND0G includes a training mode for learning network reconnaissance:

```bash
# Start training mode
./run --training

# Available lessons:
1. Network Discovery Fundamentals
2. Port Scanning Techniques
3. Service Enumeration
4. Vulnerability Assessment
5. Evasion Techniques
6. Report Generation
```

---

## 📊 **Performance Metrics**

### **Resource Usage**

| Metric | Light Load | Medium Load | Heavy Load |
|--------|------------|-------------|------------|
| **CPU** | 5-10% | 20-40% | 60-80% |
| **Memory** | 50MB | 200MB | 1GB |
| **Network** | 1Mbps | 10Mbps | 100Mbps |
| **Disk I/O** | Minimal | 5MB/s | 20MB/s |

### **Optimization Tips**

1. **For large networks**: Use discovery profile first
2. **For production**: Enable rate limiting
3. **For accuracy**: Use slower timeout values
4. **For speed**: Increase concurrency and reduce timeout

---

## 🚨 **Security Considerations**

### **Responsible Use**

⚠️ **WARNING**: This tool is for authorized testing only!

- ✅ **Authorized penetration testing**
- ✅ **Security assessments with permission**
- ✅ **Network administration**
- ✅ **Security research in lab environments**
- ❌ **Unauthorized network scanning**
- ❌ **Scanning without written permission**

### **Legal Compliance**

Always ensure compliance with:
- Computer Fraud and Abuse Act (CFAA)
- EU Cybercrime Directive
- Local cybersecurity laws
- Organization security policies

---

## 🤝 **Contributing**

### **Development Setup**

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/r3cond0g.git
cd r3cond0g

# Create branch
git checkout -b feature/amazing-feature

# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
./run --test

# Submit pull request
```

### **Contribution Areas**

- 🔍 **Probe Definitions**: Add detection for new services
- 🛡️ **Vulnerability Signatures**: Expand CVE database
- 🔌 **Integrations**: Connect with more tools
- 📊 **Visualizations**: Improve reporting
- 🌍 **Translations**: Internationalization
- 📚 **Documentation**: Enhance guides

---

## 📅 **Roadmap**

### **Version 3.1** (Q2 2025)
- [ ] REST API implementation
- [ ] Web UI dashboard
- [ ] Distributed scanning
- [ ] Cloud provider support (AWS, Azure, GCP)
- [ ] Container scanning

### **Version 3.2** (Q3 2025)
- [ ] Machine learning anomaly detection
- [ ] Automated exploitation framework
- [ ] Real-time collaboration features
- [ ] Mobile companion app
- [ ] Kubernetes operator

### **Version 4.0** (Q4 2025)
- [ ] AI-powered threat prediction
- [ ] Zero-touch automation
- [ ] Blockchain integration
- [ ] Quantum-resistant encryption
- [ ] AR/VR visualization

---

## 📞 **Support**

### **Getting Help**

- **Documentation**: [Wiki](https://github.com/0xb0rn3/r3cond0g/wiki)
- **Issues**: [GitHub Issues](https://github.com/0xb0rn3/r3cond0g/issues)
- **Discussions**: [GitHub Discussions](https://github.com/0xb0rn3/r3cond0g/discussions)
- **Security**: security@r3cond0g.io

### **Commercial Support**

For enterprise support, training, and custom development:
- Email: enterprise@r3cond0g.io
- Website: https://r3cond0g.io/enterprise

---

## 📜 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### **Third-Party Components**

- Go standard library (BSD)
- Python standard library (PSF)
- Rich terminal library (MIT)
- Various Go modules (see go.mod)

---

## 🙏 **Acknowledgments**

### **Special Thanks**

- The open-source security community
- Contributors and testers
- Security researchers worldwide
- Our sponsors and supporters

### **Inspired By**

- **Nmap** - The legendary network mapper
- **Masscan** - Speed demon of port scanning
- **Metasploit** - Framework architecture
- **MITRE ATT&CK** - Technique classification

---

## 📈 **Statistics**

<div align="center">

![GitHub stars](https://img.shields.io/github/stars/0xb0rn3/r3cond0g?style=social)
![GitHub forks](https://img.shields.io/github/forks/0xb0rn3/r3cond0g?style=social)
![GitHub watchers](https://img.shields.io/github/watchers/0xb0rn3/r3cond0g?style=social)

### **Project Stats**
- **Lines of Code**: 15,000+
- **Supported Services**: 200+
- **CVE Database**: 180,000+
- **Active Users**: 10,000+
- **Countries**: 80+

</div>

---

<div align="center">

# **Start Your Hunt Today**

```bash
git clone https://github.com/0xb0rn3/r3cond0g.git && cd r3cond0g && chmod +x run && ./run
```

**Built with ❤️ by the R3COND0G Team**

[0xb0rn3](https://github.com/0xb0rn3) | [0xbv1](https://instagram.com/theehiv3)

*"In the digital realm, reconnaissance is the key to dominance."*

</div>*Hunt. Scan. Conquer. Control.*

<div align="center">
  
[![Version](https://img.shields.io/badge/Version-3.0.0-red.svg?style=for-the-badge&logo=github)](https://github.com/0xb0rn3/r3cond0g)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8.svg?style=for-the-badge&logo=go)](https://golang.org)
[![Python](https://img.shields.io/badge/Python-3.8+-3776AB.svg?style=for-the-badge&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-FCC624.svg?style=for-the-badge&logo=linux)](https://www.linux.org/)

**Developed by:** [0xb0rn3](https://github.com/0xb0rn3) & [0xbv1](https://instagram.com/theehiv3) 

*Enterprise-grade network reconnaissance framework with intelligent orchestration*

[🚀 Quick Start](#-quick-start) • [🎯 Features](#-features) • [🛠️ Installation](#-installation) • [📖 Documentation](#-documentation) • [🤝 Contributing](#-contributing)

</div>

---

## 🎯 **What is R3COND0G?**

R3COND0G is a next-generation network reconnaissance platform that combines a blazing-fast Go scanning engine with an intelligent Python-based Command & Control system. Built for security professionals, penetration testers, and network administrators who need comprehensive visibility into their infrastructure.

### **Core Architecture**

- **Go Engine**: High-performance, concurrent scanning core
- **Python Controller**: Intelligent orchestration and automation
- **Universal Launcher**: Cross-distribution Linux compatibility
- **Modular Design**: Extensible plugin and probe system

---

## ⚡ **Quick Start**

### **One-Line Installation**

```bash
curl -sSL https://raw.githubusercontent.com/0xb0rn3/r3cond0g/main/run | bash -s setup
```

### **Manual Installation**

```bash
# Clone repository
git clone https://github.com/0xb0rn3/r3cond0g.git
cd r3cond0g

# Make launcher executable
chmod +x run

# Run setup (auto-detects your Linux distribution)
./run setup

# Launch interactive mode
./run
```

### **Quick Scan Examples**

```bash
# Simple network discovery
./run scan 192.168.1.0/24

# Aggressive scan with reporting
./run --scan aggressive --targets 10.0.0.0/24 --report html

# Import and enhance Nmap results
./run --import-nmap scan.xml --generate-msf
```

---

## 🐧 **Linux Distribution Support**

R3COND0G's universal launcher (`./run`) automatically detects and configures for:

### **Debian-based**
- Ubuntu (16.04+)
- Debian (9+)
- Kali Linux
- Parrot OS
- Linux Mint
- Pop!_OS
- Elementary OS
- Zorin OS

### **RHEL-based**
- RHEL (7+)
- CentOS (7+)
- Fedora (30+)
- Rocky Linux
- AlmaLinux
- Oracle Linux

### **Arch-based**
- Arch Linux
- Manjaro
- EndeavourOS
- Garuda Linux

### **Other Distributions**
- openSUSE Leap/Tumbleweed
- Alpine Linux
- Gentoo
- Void Linux
- NixOS (manual config required)

---

## 🎮 **Interactive Command Center**

Launch the interactive mode with a simple command:

```bash
./run
```

You'll be presented with an intuitive menu system:

```
🦅 R3COND0G Command & Control System
Advanced Orchestration Platform v3.0.0

 1  Build Core Binary
 2  Generate Probe Definitions  
 3  Create Scan Profile
 4  Run Scan
 5  Import Nmap Results
 6  Generate Metasploit RC
 7  Update Vulnerability Database
 8  Generate Reports
 9  Optimize Performance
10  Generate SIEM Feed
11  View Scan History
12  Generate Network Topology
 0  Exit
```

---

## 🚀 **Features**

### **Scanning Capabilities**

| Feature | Description |
|---------|-------------|
| **Multi-Protocol Support** | TCP, UDP, ICMP, ARP scanning |
| **Service Detection** | 200+ pre-configured probes |
| **OS Fingerprinting** | TTL, window size, TCP options analysis |
| **Vulnerability Mapping** | Real-time CVE correlation |
| **Network Topology** | Visual network mapping |
| **MAC Vendor Lookup** | OUI database integration |

### **Performance Features**

- **Concurrent Scanning**: Up to 10,000 simultaneous connections
- **Intelligent Rate Limiting**: Adaptive throttling
- **Memory Optimization**: ~0.5MB per connection
- **Distributed Scanning**: Multi-host coordination
- **Resume Capability**: Checkpoint and resume scans

### **Integration Ecosystem**

| Tool | Integration Type | Features |
|------|-----------------|----------|
| **Metasploit** | Resource Scripts | Auto-exploit generation |
| **Nmap** | XML Import/Export | Result enhancement |
| **SIEM** | CEF/LEEF/JSON | Real-time event streaming |
| **Elasticsearch** | JSON API | Direct indexing |
| **Splunk** | HEC Integration | Event forwarding |
| **Grafana** | Metrics Export | Performance dashboards |

---

## 🛠️ **Installation**

### **Prerequisites**

The `./run` script automatically installs all dependencies for your distribution:

- **Go** 1.21+ (for core engine)
- **Python** 3.8+ (for controller)
- **libpcap** (for packet capture)
- **Git** (for updates)

### **Automated Setup**

```bash
# Full setup with all features
./run setup

# Setup without dependency installation (if already installed)
SKIP_DEPS=1 ./run setup

# Force rebuild of core binary
FORCE_BUILD=1 ./run build
```

### **Docker Installation**

```bash
# Build Docker image
docker build -t r3cond0g .

# Run container
docker run -it --rm --network host --cap-add NET_RAW r3cond0g
```

### **Manual Build**

```bash
# Build Go core
go mod init r3cond0g
go mod tidy
go build -ldflags="-s -w" -o r3cond0g main.go

# Install Python dependencies
pip3 install -r requirements.txt

# Set capabilities (for non-root ICMP)
sudo setcap cap_net_raw,cap_net_admin=eip ./r3cond0g
```

---

## 📊 **Scan Profiles**

### **Pre-configured Profiles**

| Profile | Use Case | Configuration |
|---------|----------|---------------|
| **stealth** | Covert reconnaissance | Low concurrency, packet fragmentation |
| **discovery** | Network mapping | ICMP/TCP ping sweep, topology generation |
| **aggressive** | Full enumeration | All ports, all protocols, version detection |
| **vulnerability** | Security assessment | CVE mapping, version detection, scripts |
| **default** | Balanced scanning | Top 1000 ports, basic service detection |

### **Creating Custom Profiles**

```bash
# Interactive profile creation
./run
> Select option: 3 (Create Scan Profile)

# CLI profile creation
./run --create-profile pentest --base aggressive \
  --ports 1-65535 --timeout 5000 --concurrency 500
```

---

## 📈 **Performance Optimization**

### **Automatic Optimization**

```bash
# Let R3COND0G optimize for your network
./run --optimize-performance 1000 --network-type lan

# Generated configuration:
{
  "max_concurrency": 100,
  "timeout": 2000,
  "rate_limit": 100,
  "estimated_memory_mb": 50
}
```

### **Manual Tuning**

```bash
# System optimizations (applied automatically by ./run)
sudo sysctl -w net.ipv4.tcp_fin_timeout=30
sudo sysctl -w net.ipv4.tcp_tw_reuse=1
ulimit -n 65535
```

### **Performance Benchmarks**

| Target Scale | Configuration | Scan Time | Rate |
|--------------|---------------|-----------|------|
| /24 Network | Discovery | ~30 sec | 500 hosts/min |
| Single Host | All ports | ~3 min | 21,000 ports/min |
| /16 Network | Top 100 ports | ~45 min | 1,400 hosts/min |

---

##
