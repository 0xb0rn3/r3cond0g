# R3COND0G (HellHound) 🦅
### *Hunt. Scan. Conquer. Control.*

<div align="center">
  
[![Version](https://img.shields.io/badge/Version-3.0.0-red.svg?style=for-the-badge&logo=github)](https://github.com/0xb0rn3/r3cond0g)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8.svg?style=for-the-badge&logo=go)](https://golang.org)
[![Python](https://img.shields.io/badge/Python-3.8+-3776AB.svg?style=for-the-badge&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)
[![Build Status](https://img.shields.io/github/actions/workflow/status/0xb0rn3/r3cond0g/go.yml?branch=main&style=for-the-badge&logo=github-actions)](https://github.com/0xb0rn3/r3cond0g/actions)

**Developed by:** [0xb0rn3](https://github.com/0xb0rn3) & [0xbv1](https://instagram.com/theehiv3) 

*Next-generation network reconnaissance platform with advanced Command & Control orchestration*

[🚀 Quick Start](#-quick-start) • [🎯 Features](#-core-capabilities) • [🛠️ Installation](#-installation) • [📖 Documentation](#-documentation) • [🤝 Contributing](#-contributing)

</div>

---

## 🎯 **What is R3COND0G?**

R3COND0G is a comprehensive network reconnaissance ecosystem combining a high-performance Go scanning engine with an intelligent Python-based Command & Control system. This dual-architecture design provides unprecedented flexibility, automation, and integration capabilities for security professionals conducting authorized penetration testing and vulnerability assessments.

### 🔥 **Why R3COND0G?**

Traditional network scanners operate in isolation, requiring manual coordination and result correlation. R3COND0G revolutionizes reconnaissance by providing:

- **Unified Control System**: Single interface for all reconnaissance operations
- **Intelligent Orchestration**: Automated workflow management and optimization
- **Multi-Layer Discovery**: L2-L7 network analysis in a single platform
- **Advanced Integration**: Seamless interoperability with existing security tools
- **Real-time Intelligence**: Dynamic vulnerability correlation and threat assessment

---

## ⚡ **Architecture Overview**

```
┌─────────────────────────────────────────────────────────────┐
│          R3COND0G Command & Control System (Python)         │
│  ┌─────────────┬──────────────┬───────────┬─────────────┐  │
│  │   Profile   │   Automation  │  Reports  │ Integration │  │
│  │  Management │    Engine     │ Generator │   Modules   │  │
│  └─────────────┴──────────────┴───────────┴─────────────┘  │
│                            ▼                                │
│  ┌────────────────────────────────────────────────────────┐ │
│  │            Orchestration & Control Layer               │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────┬───────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────┐
│            R3COND0G Core Scanning Engine (Go)               │
│  ┌──────────┬──────────┬──────────┬──────────┬──────────┐  │
│  │   ICMP   │   TCP    │   UDP    │  Service │   Vuln   │  │
│  │Discovery │ Scanner  │ Scanner  │ Detection│  Mapping │  │
│  └──────────┴──────────┴──────────┴──────────┴──────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │         Multi-threaded Concurrent Engine             │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 **Quick Start**

### **One-Command Setup**

```bash
# Clone and auto-setup with controller
git clone https://github.com/0xb0rn3/r3cond0g.git
cd r3cond0g
python3 r3cond0g_controller.py --interactive
```

The controller will automatically:
- ✅ Check and install dependencies
- ✅ Build optimized Go binary
- ✅ Generate probe definitions
- ✅ Create default configurations
- ✅ Initialize vulnerability database

### **Quick Scan Examples**

```bash
# Using the controller for automated scanning
python3 r3cond0g_controller.py --scan aggressive --targets 192.168.1.0/24

# Direct core usage for speed
./r3cond0g -target 192.168.1.0/24 -ports 1-1000 -tcp-ping -icmp-ping

# Import and enhance existing Nmap scans
python3 r3cond0g_controller.py --import-nmap scan.xml --report all
```

---

## 🎮 **Command & Control System**

### **Interactive Mode**

The controller provides a rich interactive interface for comprehensive reconnaissance operations:

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

### **Automation Capabilities**

```python
# Example: Automated reconnaissance workflow
from r3cond0g_controller import R3COND0GController

controller = R3COND0GController()

# Create optimized profile
controller.create_scan_profile("pentest", base="aggressive")

# Run discovery
results = controller.run_scan("pentest", ["192.168.1.0/24"])

# Enhance with vulnerability data
controller.nvd_integration(bulk_update=True)

# Generate comprehensive reports
controller.generate_reports(results, ["html", "json", "markdown"])

# Export to other tools
controller.generate_metasploit_rc(results)
controller.generate_siem_feed(results, "cef")
```

---

## 🛡️ **Core Capabilities**

### **Multi-Layer Network Discovery**

| Layer | Protocol | Capabilities |
|-------|----------|-------------|
| **L2 - Data Link** | ARP | MAC address resolution, vendor identification |
| **L3 - Network** | ICMP | Host discovery, OS fingerprinting via TTL |
| **L4 - Transport** | TCP/UDP | Port scanning, service detection |
| **L5-7 - Application** | Various | Banner grabbing, version detection, vulnerability mapping |

### **Scan Profiles**

| Profile | Purpose | Configuration |
|---------|---------|---------------|
| **Stealth** | Covert reconnaissance | Low concurrency, fragmented packets, decoy sources |
| **Default** | Balanced scanning | Moderate speed, basic service detection |
| **Aggressive** | Complete enumeration | High concurrency, all protocols, full detection |
| **Discovery** | Network mapping | Ping sweep, topology generation, MAC lookup |
| **Vulnerability** | Security assessment | Version detection, CVE correlation, exploit mapping |

### **Service Detection Engine**

Advanced probe-based service identification with:
- **200+ Pre-configured Probes**: Coverage for common services
- **Custom Probe Support**: Define detection for proprietary services
- **TLS/SSL Analysis**: Certificate extraction and cipher enumeration
- **Protocol Negotiation**: ALPN/NPN detection for modern services
- **Confidence Scoring**: Accuracy metrics for detection results

---

## 📊 **Reporting & Output**

### **Multi-Format Reports**

| Format | Use Case | Features |
|--------|----------|----------|
| **HTML** | Executive presentations | Interactive charts, vulnerability heat maps |
| **JSON** | Tool integration | Structured data, API-ready format |
| **Markdown** | Documentation | GitHub-compatible, human-readable |
| **CSV** | Data analysis | Excel-compatible, statistical processing |
| **XML** | Legacy tools | Nmap-compatible format |

### **Real-time Visualizations**

```bash
# Generate network topology
python3 r3cond0g_controller.py --topology dot
dot -Tpng network_topology.dot -o network.png

# Create interactive HTML dashboard
python3 r3cond0g_controller.py --report html --format interactive
```

---

## 🔌 **Tool Integration**

### **Metasploit Integration**

```bash
# Generate resource script
python3 r3cond0g_controller.py --generate-msf

# In Metasploit
msf6> resource r3cond0g.rc
```

### **SIEM Integration**

```bash
# Generate CEF events (ArcSight, Splunk)
python3 r3cond0g_controller.py --siem-feed cef > siem_events.log

# Generate LEEF events (QRadar)
python3 r3cond0g_controller.py --siem-feed leef > qradar_events.log

# JSON for modern SIEMs
python3 r3cond0g_controller.py --siem-feed json | curl -X POST https://siem.company.com/api/import -d @-
```

### **CI/CD Pipeline Integration**

```yaml
# GitHub Actions example
- name: Security Reconnaissance
  run: |
    python3 r3cond0g_controller.py --scan discovery --targets ${{ secrets.TARGET_NETWORK }}
    python3 r3cond0g_controller.py --report json --format api
    
- name: Upload Results
  uses: actions/upload-artifact@v2
  with:
    name: reconnaissance-results
    path: reports_*/
```

---

## 🔧 **Advanced Configuration**

### **Performance Optimization**

The controller automatically optimizes based on your environment:

```bash
# Auto-optimize for large network
python3 r3cond0g_controller.py --optimize-performance 1000 --network-type lan

# Generated optimization:
{
  "performance_profile": "lan_large",
  "max_concurrency": 100,
  "timeout": 2000,
  "rate_limit": 100,
  "estimated_memory_mb": 50,
  "system_optimizations": [
    "ulimit -n 1000",
    "sysctl -w net.ipv4.tcp_fin_timeout=30"
  ]
}
```

### **Custom Probe Development**

Create specialized service detection:

```json
{
  "name": "Custom-Database",
  "protocol": "TCP",
  "ports": [9999],
  "priority": 10,
  "requires_tls": true,
  "send_payload": "HELLO\\x00VERSION\\r\\n",
  "read_pattern": "^WELCOME\\s+v([0-9.]+)",
  "service_override": "customdb",
  "version_template": "{{group_1}}",
  "timeout_ms": 5000
}
```

### **Vulnerability Database Management**

```bash
# Update NVD database
python3 r3cond0g_controller.py --update-vulns --nvd-key YOUR_KEY

# Import custom CVEs
cat > custom_cves.json << EOF
{
  "InternalApp 1.0": ["INTERNAL-001", "CVE-2024-0001"],
  "CustomService 2.5": ["CVE-2024-1234"]
}
EOF
./r3cond0g -cve-plugin custom_cves.json
```

---

## 📈 **Performance Metrics**

### **Scanning Benchmarks**

| Scenario | Targets | Ports | Time | Rate |
|----------|---------|-------|------|------|
| LAN Discovery | /24 (254 hosts) | Top 100 | ~30s | 847 hosts/min |
| Full TCP Scan | Single host | 65,535 | ~3min | 21,845 ports/min |
| Service Detection | 10 hosts | 1,000 | ~2min | 5,000 ports/min |
| Vulnerability Scan | /28 (14 hosts) | Top 1000 | ~5min | 2,800 checks/min |

### **Resource Usage**

- **Memory**: ~0.5MB per concurrent connection
- **CPU**: Scales linearly with concurrency
- **Network**: Configurable rate limiting
- **Disk**: Minimal (cache and results only)

---

## 🛠️ **Installation**

### **Requirements**

- **Go**: 1.21 or higher
- **Python**: 3.8 or higher
- **Git**: For repository management
- **Optional**: Graphviz (topology visualization), nmap (import functionality)

### **Automated Installation**

```bash
# The controller handles everything
git clone https://github.com/0xb0rn3/r3cond0g.git
cd r3cond0g

# Install Python dependencies
pip3 install -r requirements.txt

# Run controller setup
python3 r3cond0g_controller.py --build --optimize --generate-probes
```

### **Manual Installation**

```bash
# Build Go core
go mod init r3cond0g
go mod tidy
go build -ldflags="-s -w" -o r3cond0g main.go

# Set capabilities (Linux)
sudo setcap cap_net_raw,cap_net_admin=eip ./r3cond0g

# Generate configurations
python3 r3cond0g_controller.py --generate-probes
python3 r3cond0g_controller.py --config default
```

---

## 📖 **Documentation**

### **Command Reference**

```bash
# Controller Commands
python3 r3cond0g_controller.py --help

# Core Scanner Commands  
./r3cond0g --help

# Common Workflows
python3 r3cond0g_controller.py --scan discovery --targets 192.168.1.0/24
python3 r3cond0g_controller.py --import-nmap results.xml --report all
python3 r3cond0g_controller.py --generate-msf --siem-feed cef
```

### **API Usage**

```python
# Programmatic control
from r3cond0g_controller import R3COND0GController

controller = R3COND0GController()
results = controller.run_scan("aggressive", ["192.168.1.1"])
vulnerabilities = controller.nvd_integration(results.get("cves", []))
reports = controller.generate_reports(results, ["html", "json"])
```

---

## 🚨 **Security & Ethics**

### **Responsible Usage**

R3COND0G is a powerful reconnaissance tool designed for:
- ✅ Authorized penetration testing
- ✅ Security assessments with written permission
- ✅ Network administration and monitoring
- ✅ Security research and education

### **Legal Compliance**

⚠️ **WARNING**: Unauthorized network scanning may violate:
- Computer Fraud and Abuse Act (CFAA)
- EU Cybercrime Directive
- Local cybercrime laws
- Terms of service agreements

**Always obtain explicit written authorization before scanning any network or system you do not own.**

---

## 🤝 **Contributing**

We welcome contributions from the security community! 

### **How to Contribute**

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Commit your changes** (`git commit -m 'Add amazing feature'`)
4. **Push to branch** (`git push origin feature/amazing-feature`)
5. **Open a Pull Request**

### **Contribution Areas**

- 🔍 **New Probe Definitions**: Expand service detection capabilities
- 🛡️ **Vulnerability Signatures**: Add CVE mappings and checks
- 🔌 **Tool Integrations**: Connect with additional security platforms
- 📊 **Report Templates**: Create new visualization formats
- 🌍 **Translations**: Internationalize the interface
- 📖 **Documentation**: Improve guides and examples

---

## 🏆 **Comparison with Other Tools**

| Feature | R3COND0G | Nmap | Masscan | Zmap |
|---------|----------|------|---------|------|
| **Speed** | ⚡ Very Fast | 🚀 Fast | ⚡⚡ Fastest | ⚡ Very Fast |
| **Service Detection** | ✅ Advanced | ✅ Excellent | ❌ Basic | ❌ None |
| **Vulnerability Mapping** | ✅ Integrated | ⚠️ Scripts | ❌ No | ❌ No |
| **Command & Control** | ✅ Full System | ❌ No | ❌ No | ❌ No |
| **Report Generation** | ✅ Multi-format | ⚠️ Basic | ❌ No | ⚠️ Basic |
| **Tool Integration** | ✅ Extensive | ⚠️ Limited | ❌ No | ⚠️ Limited |
| **Network Topology** | ✅ Visual | ⚠️ Text | ❌ No | ❌ No |
| **SIEM Integration** | ✅ Native | ❌ No | ❌ No | ❌ No |
| **Learning Curve** | 📈 Moderate | 📈 Moderate | 📉 Easy | 📉 Easy |

---

## 📊 **Use Cases**

### **Enterprise Security Assessment**

```bash
# Comprehensive network audit
python3 r3cond0g_controller.py --scan discovery --targets corporate.network/16
python3 r3cond0g_controller.py --update-vulns
python3 r3cond0g_controller.py --report all --format html,json,csv
```

### **Penetration Testing**

```bash
# Initial reconnaissance
python3 r3cond0g_controller.py --scan stealth --targets client.com
python3 r3cond0g_controller.py --generate-msf
msfconsole -r r3cond0g.rc
```

### **Continuous Monitoring**

```bash
# Scheduled scanning with SIEM integration
*/6 * * * * python3 /opt/r3cond0g/r3cond0g_controller.py --scan default --targets 10.0.0.0/24 --siem-feed json | curl -X POST https://siem.local/api/import -d @-
```

### **Incident Response**

```bash
# Rapid assessment of compromised network
python3 r3cond0g_controller.py --scan aggressive --targets infected.subnet/24
python3 r3cond0g_controller.py --report html --format forensic
```

---

## 🔮 **Roadmap**

### **Version 3.1 (Q2 2025)**
- [ ] Machine Learning anomaly detection
- [ ] Distributed scanning architecture
- [ ] Cloud provider integrations (AWS, Azure, GCP)
- [ ] GraphQL API endpoint

### **Version 3.2 (Q3 2025)**
- [ ] Container/Kubernetes scanning
- [ ] IoT device fingerprinting
- [ ] Blockchain node detection
- [ ] Advanced evasion techniques

### **Version 4.0 (Q4 2025)**
- [ ] AI-powered vulnerability prediction
- [ ] Automated exploitation framework
- [ ] Real-time threat intelligence feeds
- [ ] Mobile application

---

## 📚 **Resources**

### **Official Documentation**
- [User Guide](docs/user-guide.md)
- [API Reference](docs/api-reference.md)
- [Probe Development](docs/probe-development.md)
- [Integration Guide](docs/integrations.md)

---

## 💻 **System Requirements**

### **Minimum Requirements**
- **CPU**: 2 cores
- **RAM**: 2 GB
- **Storage**: 500 MB
- **Network**: 10 Mbps
- **OS**: Linux/macOS/Windows

### **Recommended Requirements**
- **CPU**: 4+ cores
- **RAM**: 8 GB
- **Storage**: 2 GB (with cache)
- **Network**: 100+ Mbps
- **OS**: Linux (for raw socket support)

### **Performance Scaling**

| Targets | Recommended Specs |
|---------|------------------|
| < 100 | 2 cores, 2GB RAM |
| 100-1000 | 4 cores, 4GB RAM |
| 1000-10000 | 8 cores, 8GB RAM |
| > 10000 | 16+ cores, 16GB+ RAM |

---

## 🐛 **Troubleshooting**

### **Common Issues**

**Permission Denied (ICMP)**
```bash
# Linux: Set capabilities
sudo setcap cap_net_raw,cap_net_admin=eip ./r3cond0g

# Alternative: Run with sudo
sudo python3 r3cond0g_controller.py --scan discovery
```

**High Memory Usage**
```bash
# Reduce concurrency
python3 r3cond0g_controller.py --optimize-performance 100 --network-type wan
```

**Slow Scanning**
```bash
# Optimize for your network
python3 r3cond0g_controller.py --scan custom \
  --config optimized.json \
  --concurrency 500 \
  --timeout 500
```

**Build Failures**
```bash
# Clean and rebuild
go clean -cache
go mod download
python3 r3cond0g_controller.py --build --optimize
```

---

## 📜 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### **Third-Party Licenses**

R3COND0G incorporates the following open-source components:
- Go standard library (BSD License)
- Python standard library (PSF License)
- Various Go modules (see go.mod for details)
- Rich terminal library (MIT License)

---

## 🙏 **Acknowledgments**

### **Special Thanks**

- The Go community for an amazing language and ecosystem
- The Python community for powerful orchestration capabilities
- Security researchers who provided feedback and testing
- Open source contributors who helped improve the platform

### **Inspired By**

- **Nmap** - The network mapper that started it all
- **Masscan** - For showing what's possible with speed
- **Metasploit** - For integration architecture ideas
- **MITRE ATT&CK** - For reconnaissance technique categorization

---

## 🌟 **Star History**

[![Star History Chart](https://api.star-history.com/svg?repos=0xb0rn3/r3cond0g&type=Date)](https://star-history.com/#0xb0rn3/r3cond0g&Date)

---

<div align="center">

**Built with ❤️ by 0xb0rn3 | 0xbv1**

*"In the realm of digital reconnaissance, knowledge is power, and R3COND0G is your weapon."*

</div>
