# r3cond0g(ReconRaptor) - Network Reconnaissance Tool 🦅

**Version:** 0.2.2 ReconRaptor
**Authors:** IG:theehiv3 (0xbv1) & Github:0xb0rn3

[![Go Version](https://img.shields.io/github/go-mod/go-version/0xb0rn3/r3cond0g?style=flat-square)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE) [![Build Status](https://img.shields.io/github/actions/workflow/status/0xb0rn3/r3cond0g/go.yml?branch=main&style=flat-square)](https://github.com/0xb0rn3/r3cond0g/actions) **ReconRaptor (formerly r3cond0g) is a powerful, multi-threaded network reconnaissance tool written in Go. It's designed for security professionals and enthusiasts to perform comprehensive network scans, service detection, vulnerability mapping, and network topology generation.**

---

## 🌟 Key Features

-   🚀 **Ultra-Fast Scanning:**
    -   Multi-threaded TCP and UDP port scanning.
    -   Configurable concurrency and timeouts for optimized performance.
    -   Intelligent scan optimization (prioritizes common ports).
-   🔬 **Advanced Service & OS Detection:**
    -   Fingerprints services and attempts to identify versions.
    -   Basic OS guessing based on service banners and behavior.
-   🎯 **Flexible Targeting:**
    -   Scan single hosts, CIDR notations, comma-separated lists, or targets from a file.
-   🔗 **Nmap Integration:**
    -   Parse and incorporate results from Nmap XML output.
-   🛡️ **Vulnerability Mapping (NVD Integration):**
    -   Automatic CVE lookup for identified services and versions using the NVD API 2.0.
    -   Supports custom CVE plugin files for offline/private vulnerability data.
    -   NVD API rate limiting and retry logic.
-   🗺️ **Network Topology Generation:**
    -   Generates basic network topology maps in DOT format for visualization with Graphviz.
-   📊 **Versatile Export Options:**
    -   Save scan results in JSON, CSV, XML, or a user-friendly HTML report.
-   ⚙️ **User-Friendly Interface:**
    -   Interactive menu-driven operation.
    -   Command-line flags for automation and headless operation.
    -   Real-time progress display with ETA and scan rate.
-   🔄 **Automatic Updates:**
    -   The runner script can check for and apply updates to keep the tool current.

---

## 🚀 Quick Start

The provided `runner.sh` script automates the entire setup and execution process.

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/0xb0rn3/r3cond0g.git](https://github.com/0xb0rn3/r3cond0g.git) # Or your fork's URL
    cd ReconRaptor
    ```

2.  **Make the Runner Executable & Run:**
    ```bash
    chmod +x run
    ./run
    ```

    The `run` script will:
    -   Detect your operating system.
    -   Check for and offer to install Git and Go if they are not present.
    -   Check for updates to ReconRaptor from the repository.
    -   Initialize the Go module and manage dependencies.
    -   Compile the ReconRaptor tool.
    -   Launch ReconRaptor.

---

## 🛠️ Manual Installation & Build

If you prefer to set up and build ReconRaptor manually:

1.  **Install Go:** Ensure Go (version 1.18 or newer recommended) is installed.
    -   Official Go Downloads: [https://golang.org/dl/](https://golang.org/dl/)

2.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/0xb0rn3/r3cond0g.git](https://github.com/0xb0rn3/r3cond0g.git)
    cd r3cond0g
    ```

3.  **Initialize Module & Tidy Dependencies:**
    ```bash
    go mod init r3cond0g # Or your preferred module name
    go mod tidy
    ```

4.  **Build the Tool:**
    ```bash
    go build -ldflags="-s -w" -o r3cond0g main.go
    # For Windows: go build -ldflags="-s -w" -o r3cond0g.exe main.go
    ```

5.  **Run ReconRaptor:**
    ```bash
    ./r3cond0g
    # For Windows: .\r3cond0g.exe
    ```

---

## 📋 Usage

r3cond0g can be run interactively or with command-line flags for automation.


## 📋 Usage

ReconRaptor can be run interactively or with command-line flags for automation.

./r3cond0g [flags]
**Common Flags (see `./r3cond0g --help` for all):**

-   `-target <hosts>`: Target host(s) (comma-separated or CIDR).
-   `-target-file <file>`: File containing a list of targets.
-   `-ports <range>`: Port range (e.g., "1-1000", "80,443").
-   `-timeout <ms>`: Scan timeout in milliseconds.
-   `-concurrency <num>`: Maximum concurrent scans.
-   `-udp`: Enable UDP scanning.
-   `-vuln`: Enable vulnerability mapping (NVD).
-   `-nvd-key <key>`: Your NVD API key.
-   `-nmap-file <xmlfile>`: Import Nmap XML results.
-   `-cve-plugin <jsonfile>`: Path to custom CVE JSON file.
-   `-output <basename>`: Basename for output files (e.g., "scan_results").

**Interactive Menu Options:**

1.  🚀 Run Ultra-Fast Scan
2.  🛠️ Configure Settings (Target, Ports, Timeout, API Keys, etc.)
3.  📋 Display Results
4.  💾 Save Results (JSON)
5.  📄 Parse Nmap Results
6.  🔍 Perform Vulnerability Mapping (on existing results)
7.  🌐 Generate Network Topology (DOT file)
8.  📤 Export Results (JSON, CSV, XML, HTML)
9.  ❌ Exit

---

## ⚙️ Configuration

Most settings are configurable via the interactive menu (Option 2) or command-line flags.

-   **NVD API Key:** For effective vulnerability mapping, obtain an API key from the [NVD](https://nvd.nist.gov/developers/request-an-api-key). You can set it via:
    -   The `NVD_API_KEY` environment variable.
    -   The `--nvd-key` command-line flag.
    -   The interactive settings menu.
-   **Custom CVEs:** Use a JSON file (specified with `--cve-plugin` or in settings) to load your own vulnerability mappings. Format: `{"service version": ["CVE-ID-1", "CVE-ID-2"]}`. Example:
    ```json
    {
      "Apache httpd 2.4.50": ["CVE-XXXX-1000"],
      "OpenSSH 8.2p1": ["CVE-YYYY-2000", "CVE-YYYY-2001"]
    }
    ```

---

## 📦 Dependencies

-   **Go:** Version 1.18+ recommended (the runner script can help install it).
-   **Git:** For cloning and updates (the runner script can help install it).
-   **Network Access:** Required for scanning targets.
-   **(Optional) NVD API Key:** For comprehensive vulnerability mapping.
-   **(Optional) Graphviz:** To convert generated DOT files into visual topology maps (`dot -Tpng topology.dot -o topology.png`).

---

## 📊 Output Formats

ReconRaptor provides results in several formats:

-   **Console:** Real-time updates and a formatted table of results.
-   **JSON (`.json`):** Detailed, structured data ideal for programmatic use or archiving.
-   **CSV (`.csv`):** Comma-separated values, easily imported into spreadsheets.
-   **XML (`.xml`):** Structured markup for integration with other tools.
-   **HTML (`.html`):** A user-friendly, styled report for easy viewing and sharing.
-   **DOT (`_topology.dot`):** For network topology graphs (visualize with Graphviz).

---

## 🛡️ Responsible Usage

This tool is intended for educational purposes and **authorized security testing only**.
-   Always obtain explicit permission before scanning any network or system that you do not own.
-   Users are solely responsible for their actions and must comply with all applicable local, state, national, and international laws and regulations.
-   The authors and contributors are not responsible for any misuse or damage caused by this tool.

---

## 🐛 Troubleshooting & Tips

-   **Permission Denied (Runner):** Ensure `run` is executable (`chmod +x run`).
-   **Compilation Errors:**
    -   Verify your Go installation and version (`go version`).
    -   Ensure Go module dependencies are correctly fetched (`go mod tidy`).
-   **Slow Scans / Timeouts:**
    -   Increase the scan timeout (`-timeout` or via settings).
    -   Reduce concurrency (`-concurrency` or via settings), especially on less stable networks or less powerful machines.
    -   If scanning large ranges, consider breaking them into smaller chunks.
-   **NVD API Issues (403 Forbidden / 429 Rate Limit):**
    -   Ensure your NVD API key is correctly configured.
    -   Be mindful of NVD API rate limits. The tool has built-in limiting, but excessive use can still hit quotas.
-   **UDP Scans:** UDP scanning is inherently less reliable and slower than TCP. Results like "open|filtered" are common.

---

## 🤝 Contributing

Contributions, bug reports, and feature requests are welcome! Please feel free to:
-   Open an issue on GitHub.
-   Submit a pull request with your improvements.

---

**Happy Hacking and Stay Ethical!** 🦅

