elif "mysql" in svc_name:
                        rc_commands.append(f"use auxiliary/scanner/mysql/mysql_version")
                        rc_commands.append(f"set RHOSTS {host}")
                        rc_commands.append("run")
                        rc_commands.append("")
                    
                    elif "rdp" in svc_name or port == "3389":
                        rc_commands.append(f"use auxiliary/scanner/rdp/rdp_scanner")
                        rc_commands.append(f"set RHOSTS {host}")
                        rc_commands.append("run")
                        rc_commands.append("")
        
        # Save resource script
        with open(output_file, 'w') as f:
            f.write("\n".join(rc_commands))
            
        self.logger.info(f"✓ Metasploit resource script saved to {output_file}")
        return output_file
    
    def generate_siem_feed(self, scan_results: Dict, format: str = "cef") -> str:
        """Generate SIEM-compatible event feed"""
        events = []
        
        if format == "cef":
            # Common Event Format
            for host, services in scan_results.get("services", {}).items():
                for service in services:
                    if service.get("state") == "open":
                        event = (
                            f"CEF:0|R3COND0G|NetworkScanner|3.0.0|PORT_OPEN|"
                            f"Open Port Detected|3|src={host} dpt={service.get('port')} "
                            f"proto={service.get('protocol', 'tcp')} app={service.get('service', 'unknown')} "
                            f"msg=Open port detected during reconnaissance scan"
                        )
                        events.append(event)
                        
            # Add vulnerability events
            for vuln in scan_results.get("vulnerabilities", []):
                event = (
                    f"CEF:0|R3COND0G|NetworkScanner|3.0.0|VULN_DETECTED|"
                    f"Vulnerability Detected|7|src={vuln.get('host')} "
                    f"cve={vuln.get('cve_id')} cvss={vuln.get('cvss_score', 0)} "
                    f"msg={vuln.get('description', 'Vulnerability detected')}"
                )
                events.append(event)
                
        elif format == "leef":
            # Log Event Extended Format (IBM QRadar)
            for host, services in scan_results.get("services", {}).items():
                for service in services:
                    if service.get("state") == "open":
                        event = (
                            f"LEEF:1.0|R3COND0G|NetworkScanner|3.0.0|PORT_OPEN|"
                            f"src={host}|dst={host}|dstPort={service.get('port')}|"
                            f"proto={service.get('protocol', 'tcp')}|app={service.get('service', 'unknown')}"
                        )
                        events.append(event)
                        
        elif format == "json":
            # JSON format for modern SIEMs
            for host, services in scan_results.get("services", {}).items():
                for service in services:
                    if service.get("state") == "open":
                        event = {
                            "timestamp": datetime.now().isoformat(),
                            "event_type": "port_scan",
                            "severity": "medium",
                            "source_tool": "R3COND0G",
                            "host": host,
                            "port": service.get("port"),
                            "protocol": service.get("protocol", "tcp"),
                            "service": service.get("service", "unknown"),
                            "state": service.get("state")
                        }
                        events.append(json.dumps(event))
        
        return "\n".join(events) if format != "json" else events
    
    def nvd_integration(self, cve_list: List[str] = None, bulk_update: bool = False):
        """Integrate with NVD API for vulnerability information"""
        if not self.nvd_api_key:
            self.logger.warning("NVD API key not configured")
            return []
        
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {"apiKey": self.nvd_api_key}
        
        vulnerabilities = []
        
        if bulk_update:
            # Update vulnerability database
            self.logger.info("Updating vulnerability database from NVD...")
            
            # Get recent CVEs (last 7 days)
            mod_start = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000")
            mod_end = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.000")
            
            params = {
                "lastModStartDate": mod_start,
                "lastModEndDate": mod_end,
                "resultsPerPage": 100
            }
            
            try:
                response = requests.get(base_url, headers=headers, params=params, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    for vuln in data.get("vulnerabilities", []):
                        cve = vuln.get("cve", {})
                        cve_id = cve.get("id")
                        
                        # Extract CVSS score
                        cvss_score = 0
                        metrics = cve.get("metrics", {})
                        if "cvssMetricV31" in metrics:
                            cvss_score = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", 0)
                        elif "cvssMetricV30" in metrics:
                            cvss_score = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore", 0)
                        
                        vuln_info = {
                            "cve_id": cve_id,
                            "description": cve.get("descriptions", [{}])[0].get("value", ""),
                            "cvss_score": cvss_score,
                            "published_date": cve.get("published", ""),
                            "last_modified": cve.get("lastModified", "")
                        }
                        
                        vulnerabilities.append(vuln_info)
                        self._cache_vulnerability(vuln_info)
                        
                    self.logger.info(f"✓ Updated {len(vulnerabilities)} vulnerabilities")
                    
            except Exception as e:
                self.logger.error(f"NVD API error: {e}")
                
        elif cve_list:
            # Query specific CVEs
            for cve_id in cve_list:
                # Check cache first
                cached = self._get_cached_vulnerability(cve_id)
                if cached:
                    vulnerabilities.append(cached)
                else:
                    # Query NVD
                    try:
                        response = requests.get(f"{base_url}?cveId={cve_id}", 
                                              headers=headers, timeout=30)
                        if response.status_code == 200:
                            data = response.json()
                            if data.get("vulnerabilities"):
                                vuln = data["vulnerabilities"][0]
                                cve = vuln.get("cve", {})
                                
                                # Extract CVSS score
                                cvss_score = 0
                                metrics = cve.get("metrics", {})
                                if "cvssMetricV31" in metrics:
                                    cvss_score = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", 0)
                                
                                vuln_info = {
                                    "cve_id": cve_id,
                                    "description": cve.get("descriptions", [{}])[0].get("value", ""),
                                    "cvss_score": cvss_score,
                                    "published_date": cve.get("published", ""),
                                    "last_modified": cve.get("lastModified", "")
                                }
                                
                                vulnerabilities.append(vuln_info)
                                self._cache_vulnerability(vuln_info)
                                
                    except Exception as e:
                        self.logger.error(f"Error querying CVE {cve_id}: {e}")
        
        return vulnerabilities
    
    def _cache_vulnerability(self, vuln_info: Dict):
        """Cache vulnerability information in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO vuln_cache 
            (cve_id, description, cvss_score, published_date, affected_products)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            vuln_info.get("cve_id"),
            vuln_info.get("description", ""),
            vuln_info.get("cvss_score", 0),
            vuln_info.get("published_date", ""),
            json.dumps(vuln_info.get("affected_products", []))
        ))
        
        conn.commit()
        conn.close()
    
    def _get_cached_vulnerability(self, cve_id: str) -> Optional[Dict]:
        """Retrieve cached vulnerability information"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT description, cvss_score, published_date, affected_products
            FROM vuln_cache
            WHERE cve_id = ?
            AND datetime(last_updated) > datetime('now', '-7 days')
        ''', (cve_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                "cve_id": cve_id,
                "description": row[0],
                "cvss_score": row[1],
                "published_date": row[2],
                "affected_products": json.loads(row[3]) if row[3] else []
            }
        return None
    
    def optimize_performance(self, target_count: int, network_type: str = "lan"):
        """Generate optimized configuration based on target environment"""
        
        optimizations = {
            "lan": {
                "small": {"concurrency": 500, "timeout": 500, "rate_limit": 0},
                "medium": {"concurrency": 300, "timeout": 1000, "rate_limit": 0},
                "large": {"concurrency": 100, "timeout": 2000, "rate_limit": 100}
            },
            "wan": {
                "small": {"concurrency": 50, "timeout": 3000, "rate_limit": 50},
                "medium": {"concurrency": 30, "timeout": 5000, "rate_limit": 30},
                "large": {"concurrency": 10, "timeout": 8000, "rate_limit": 10}
            },
            "internet": {
                "small": {"concurrency": 20, "timeout": 5000, "rate_limit": 20},
                "medium": {"concurrency": 10, "timeout": 8000, "rate_limit": 10},
                "large": {"concurrency": 5, "timeout": 10000, "rate_limit": 5}
            }
        }
        
        # Determine size category
        if target_count <= 10:
            size = "small"
        elif target_count <= 100:
            size = "medium"
        else:
            size = "large"
        
        # Get optimizations
        opt = optimizations.get(network_type, {}).get(size, {})
        
        # Calculate memory requirements
        memory_per_connection = 0.5  # MB
        estimated_memory = opt.get("concurrency", 100) * memory_per_connection
        
        # System optimization commands
        if platform.system() == "Linux":
            system_opts = [
                f"ulimit -n {opt.get('concurrency', 100) * 10}",
                f"sysctl -w net.ipv4.tcp_fin_timeout=30",
                f"sysctl -w net.ipv4.tcp_tw_reuse=1"
            ]
        else:
            system_opts = []
        
        optimization_config = {
            "performance_profile": f"{network_type}_{size}",
            "max_concurrency": opt.get("concurrency", 100),
            "timeout": opt.get("timeout", 5000),
            "rate_limit": opt.get("rate_limit", 0),
            "estimated_memory_mb": estimated_memory,
            "system_optimizations": system_opts,
            "recommendations": [
                f"Use {opt.get('concurrency', 100)} concurrent connections",
                f"Set timeout to {opt.get('timeout', 5000)}ms",
                f"Estimated memory usage: {estimated_memory:.1f}MB",
                f"Network type: {network_type.upper()}"
            ]
        }
        
        # Save optimization config
        with open("optimization_config.json", 'w') as f:
            json.dump(optimization_config, f, indent=2)
        
        self.logger.info(f"✓ Generated optimization config for {target_count} targets on {network_type}")
        return optimization_config
    
    def generate_reports(self, scan_results: Dict, formats: List[str] = ["html", "json", "pdf"]):
        """Generate comprehensive reports in multiple formats"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = Path(f"reports_{timestamp}")
        report_dir.mkdir(exist_ok=True)
        
        reports = {}
        
        for fmt in formats:
            if fmt == "html":
                report_path = report_dir / f"report_{timestamp}.html"
                self._generate_html_report(scan_results, report_path)
                reports["html"] = str(report_path)
                
            elif fmt == "json":
                report_path = report_dir / f"report_{timestamp}.json"
                with open(report_path, 'w') as f:
                    json.dump(scan_results, f, indent=2, default=str)
                reports["json"] = str(report_path)
                
            elif fmt == "markdown":
                report_path = report_dir / f"report_{timestamp}.md"
                self._generate_markdown_report(scan_results, report_path)
                reports["markdown"] = str(report_path)
                
            elif fmt == "csv":
                report_path = report_dir / f"report_{timestamp}.csv"
                self._generate_csv_report(scan_results, report_path)
                reports["csv"] = str(report_path)
        
        self.logger.info(f"✓ Generated {len(reports)} reports in {report_dir}")
        return reports
    
    def _generate_html_report(self, scan_results: Dict, output_path: Path):
        """Generate HTML report with charts and visualizations"""
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>R3COND0G Scan Report</title>
    <meta charset="utf-8">
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        .header h1 { margin: 0; font-size: 2.5em; }
        .header .subtitle { opacity: 0.9; margin-top: 10px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .stat-card .value { font-size: 2em; font-weight: bold; color: #667eea; }
        .stat-card .label { color: #666; margin-top: 5px; }
        .section { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .section h2 { color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background: #667eea; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #eee; }
        tr:hover { background: #f9f9f9; }
        .vulnerability { background: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 10px 0; border-radius: 5px; }
        .critical { border-left-color: #dc3545; background: #f8d7da; }
        .high { border-left-color: #fd7e14; background: #ffe5d0; }
        .medium { border-left-color: #ffc107; background: #fff3cd; }
        .low { border-left-color: #28a745; background: #d4edda; }
        .chart-container { width: 100%; height: 300px; margin: 20px 0; }
        .footer { text-align: center; color: #666; margin-top: 40px; padding: 20px; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="header">
        <h1>🦅 R3COND0G Scan Report</h1>
        <div class="subtitle">Generated: {timestamp}</div>
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <div class="value">{total_hosts}</div>
            <div class="label">Hosts Scanned</div>
        </div>
        <div class="stat-card">
            <div class="value">{open_ports}</div>
            <div class="label">Open Ports</div>
        </div>
        <div class="stat-card">
            <div class="value">{services}</div>
            <div class="label">Services Detected</div>
        </div>
        <div class="stat-card">
            <div class="value">{vulnerabilities}</div>
            <div class="label">Vulnerabilities</div>
        </div>
    </div>
    
    <div class="section">
        <h2>Discovered Services</h2>
        <table>
            <thead>
                <tr>
                    <th>Host</th>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>Service</th>
                    <th>Version</th>
                    <th>State</th>
                </tr>
            </thead>
            <tbody>
                {service_rows}
            </tbody>
        </table>
    </div>
    
    <div class="section">
        <h2>Vulnerability Summary</h2>
        {vulnerability_section}
    </div>
    
    <div class="section">
        <h2>Port Distribution</h2>
        <canvas id="portChart"></canvas>
    </div>
    
    <div class="footer">
        <p>R3COND0G v3.0.0 | Advanced Network Reconnaissance Platform</p>
        <p>Report generated by Command & Control System</p>
    </div>
    
    <script>
        // Port distribution chart
        const ctx = document.getElementById('portChart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: {port_labels},
                datasets: [{
                    label: 'Port Frequency',
                    data: {port_data},
                    backgroundColor: 'rgba(102, 126, 234, 0.5)',
                    borderColor: 'rgba(102, 126, 234, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        });
    </script>
</body>
</html>
        """
        
        # Calculate statistics
        total_hosts = len(scan_results.get("hosts", []))
        
        service_count = 0
        open_port_count = 0
        service_rows = []
        port_distribution = {}
        
        for host, services in scan_results.get("services", {}).items():
            for service in services:
                if service.get("state") == "open":
                    open_port_count += 1
                    service_count += 1
                    
                    port = service.get("port", "unknown")
                    port_distribution[port] = port_distribution.get(port, 0) + 1
                    
                    service_rows.append(f"""
                        <tr>
                            <td>{host}</td>
                            <td>{port}</td>
                            <td>{service.get('protocol', 'tcp')}</td>
                            <td>{service.get('service', 'unknown')}</td>
                            <td>{service.get('version', '-')}</td>
                            <td>{service.get('state', 'unknown')}</td>
                        </tr>
                    """)
        
        # Vulnerability section
        vuln_html = ""
        vuln_count = len(scan_results.get("vulnerabilities", []))
        for vuln in scan_results.get("vulnerabilities", []):
            severity_class = "medium"
            cvss = vuln.get("cvss_score", 0)
            if cvss >= 9.0:
                severity_class = "critical"
            elif cvss >= 7.0:
                severity_class = "high"
            elif cvss >= 4.0:
                severity_class = "medium"
            else:
                severity_class = "low"
                
            vuln_html += f"""
                <div class="vulnerability {severity_class}">
                    <strong>{vuln.get('cve_id', 'Unknown')}</strong> - CVSS: {cvss}<br>
                    {vuln.get('description', 'No description available')}
                </div>
            """
        
        # Prepare chart data
        port_labels = list(port_distribution.keys())[:10]  # Top 10 ports
        port_data = [port_distribution[p] for p in port_labels]
        
        # Fill template
        html_content = html_template.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_hosts=total_hosts,
            open_ports=open_port_count,
            services=service_count,
            vulnerabilities=vuln_count,
            service_rows="\n".join(service_rows) if service_rows else "<tr><td colspan='6'>No services detected</td></tr>",
            vulnerability_section=vuln_html if vuln_html else "<p>No vulnerabilities detected</p>",
            port_labels=json.dumps(port_labels),
            port_data=json.dumps(port_data)
        )
        
        with open(output_path, 'w') as f:
            f.write(html_content)
    
    def _generate_markdown_report(self, scan_results: Dict, output_path: Path):
        """Generate Markdown report"""
        md_content = f"""# R3COND0G Scan Report

Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Executive Summary

- **Hosts Scanned**: {len(scan_results.get('hosts', []))}
- **Open Ports Found**: {sum(len(s) for s in scan_results.get('services', {}).values())}
- **Vulnerabilities Detected**: {len(scan_results.get('vulnerabilities', []))}

## Discovered Services

| Host | Port | Protocol | Service | Version | State |
|------|------|----------|---------|---------|-------|
"""
        
        for host, services in scan_results.get("services", {}).items():
            for service in services:
                md_content += f"| {host} | {service.get('port')} | {service.get('protocol', 'tcp')} | "
                md_content += f"{service.get('service', 'unknown')} | {service.get('version', '-')} | "
                md_content += f"{service.get('state', 'unknown')} |\n"
        
        md_content += "\n## Vulnerability Summary\n\n"
        
        for vuln in scan_results.get("vulnerabilities", []):
            md_content += f"### {vuln.get('cve_id', 'Unknown')}\n"
            md_content += f"- **CVSS Score**: {vuln.get('cvss_score', 'N/A')}\n"
            md_content += f"- **Description**: {vuln.get('description', 'No description')}\n\n"
        
        with open(output_path, 'w') as f:
            f.write(md_content)
    
    def _generate_csv_report(self, scan_results: Dict, output_path: Path):
        """Generate CSV report"""
        import csv
        
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Host", "Port", "Protocol", "Service", "Version", "State", "Vulnerabilities"])
            
            for host, services in scan_results.get("services", {}).items():
                for service in services:
                    vulns = []
                    # Find vulnerabilities for this service
                    for vuln in scan_results.get("vulnerabilities", []):
                        if vuln.get("host") == host and vuln.get("port") == service.get("port"):
                            vulns.append(vuln.get("cve_id", ""))
                    
                    writer.writerow([
                        host,
                        service.get("port"),
                        service.get("protocol", "tcp"),
                        service.get("service", "unknown"),
                        service.get("version", ""),
                        service.get("state", "unknown"),
                        ";".join(vulns)
                    ])
    
    def generate_topology(self, scan_results: Dict, output_format: str = "dot"):
        """Generate network topology visualization"""
        if not NETWORK_VIZ:
            self.logger.warning("NetworkX not installed. Install with: pip install networkx matplotlib")
            return None
        
        G = nx.Graph()
        
        # Add nodes for hosts
        for host in scan_results.get("hosts", []):
            G.add_node(host, node_type="host")
        
        # Add edges based on services
        for host, services in scan_results.get("services", {}).items():
            for service in services:
                if service.get("state") == "open":
                    service_node = f"{service.get('service', 'unknown')}:{service.get('port')}"
                    G.add_node(service_node, node_type="service")
                    G.add_edge(host, service_node)
        
        if output_format == "dot":
            # Generate DOT format
            dot_content = "digraph NetworkTopology {\n"
            dot_content += '  rankdir=LR;\n'
            dot_content += '  node [shape=box, style=filled];\n'
            
            for node in G.nodes():
                if G.nodes[node].get("node_type") == "host":
                    dot_content += f'  "{node}" [fillcolor=lightblue, label="{node}\\nHost"];\n'
                else:
                    dot_content += f'  "{node}" [fillcolor=lightgreen, label="{node}"];\n'
            
            for edge in G.edges():
                dot_content += f'  "{edge[0]}" -> "{edge[1]}";\n'
            
            dot_content += "}\n"
            
            with open("network_topology.dot", 'w') as f:
                f.write(dot_content)
            
            self.logger.info("✓ Network topology saved to network_topology.dot")
            return "network_topology.dot"
            
        elif output_format == "png":
            # Generate PNG visualization
            plt.figure(figsize=(12, 8))
            pos = nx.spring_layout(G)
            
            # Draw nodes
            host_nodes = [n for n in G.nodes() if G.nodes[n].get("node_type") == "host"]
            service_nodes = [n for n in G.nodes() if G.nodes[n].get("node_type") == "service"]
            
            nx.draw_networkx_nodes(G, pos, nodelist=host_nodes, node_color='lightblue', 
                                 node_size=1000, label="Hosts")
            nx.draw_networkx_nodes(G, pos, nodelist=service_nodes, node_color='lightgreen', 
                                 node_size=500, label="Services")
            
            # Draw edges and labels
            nx.draw_networkx_edges(G, pos, alpha=0.5)
            nx.draw_networkx_labels(G, pos)
            
            plt.title("Network Topology")
            plt.legend()
            plt.axis('off')
            plt.savefig("network_topology.png", dpi=150, bbox_inches='tight')
            plt.close()
            
            self.logger.info("✓ Network topology saved to network_topology.png")
            return "network_topology.png"
    
    def interactive_mode(self):
        """Run in interactive mode with menu"""
        if not self.console:
            print("Interactive mode requires 'rich' library. Install with: pip install rich")
            return
        
        while True:
            self.console.clear()
            self.console.print(Panel.fit("""
[bold cyan]🦅 R3COND0G Command & Control System[/bold cyan]
[dim]Advanced Orchestration Platform v3.0.0[/dim]
            """, border_style="bright_blue"))
            
            menu_table = Table(show_header=False, box=None)
            menu_table.add_column("Option", style="cyan", width=3)
            menu_table.add_column("Description", style="white")
            
            menu_items = [
                ("1", "Build Core Binary"),
                ("2", "Generate Probe Definitions"),
                ("3", "Create Scan Profile"),
                ("4", "Run Scan"),
                ("5", "Import Nmap Results"),
                ("6", "Generate Metasploit RC"),
                ("7", "Update Vulnerability Database"),
                ("8", "Generate Reports"),
                ("9", "Optimize Performance"),
                ("10", "Generate SIEM Feed"),
                ("11", "View Scan History"),
                ("12", "Generate Network Topology"),
                ("0", "Exit")
            ]
            
            for option, desc in menu_items:
                menu_table.add_row(f"[bold]{option}[/bold]", desc)
            
            self.console.print(menu_table)
            
            choice = Prompt.ask("\n[bold yellow]Select option[/bold yellow]")
            
            if choice == "1":
                self.console.print("\n[cyan]Building Core Binary...[/cyan]")
                optimize = Confirm.ask("Enable optimizations?", default=True)
                cross = Confirm.ask("Cross-compile for other platforms?", default=False)
                platforms = []
                if cross:
                    platforms = Prompt.ask("Enter platforms (e.g., linux/amd64,windows/amd64)").split(",")
                self.build_core(optimize, platforms if platforms else None)
                
            elif choice == "2":
                self.console.print("\n[cyan]Generating Probe Definitions...[/cyan]")
                custom = Confirm.ask("Add custom services?", default=False)
                services = []
                if custom:
                    services = Prompt.ask("Enter service names (comma-separated)").split(",")
                self.generate_probes(services if services else None)
                
            elif choice == "3":
                self.console.print("\n[cyan]Creating Scan Profile...[/cyan]")
                name = Prompt.ask("Profile name")
                base = Prompt.ask("Base profile", default="default", 
                                choices=["default", "stealth", "aggressive", "discovery"])
                self.create_scan_profile(name, base)
                
            elif choice == "4":
                self.console.print("\n[cyan]Running Scan...[/cyan]")
                profile = Prompt.ask("Select profile", default="default")
                targets = Prompt.ask("Enter targets (comma-separated)")
                results = self.run_scan(profile, targets.split(",") if targets else None)
                if results:
                    self.console.print(Panel(f"Scan completed. Found {len(results.get('services', {}))} services", 
                                           style="green"))
                
            elif choice == "5":
                self.console.print("\n[cyan]Importing Nmap Results...[/cyan]")
                nmap_file = Prompt.ask("Enter Nmap XML file path")
                if os.path.exists(nmap_file):
                    results = self.integrate_nmap(nmap_file)
                    self.console.print(f"[green]✓ Imported {len(results.get('hosts', []))} hosts[/green]")
                else:
                    self.console.print("[red]File not found[/red]")
                
            elif choice == "6":
                self.console.print("\n[cyan]Generating Metasploit RC...[/cyan]")
                # Load last scan results
                results = self._load_last_scan_results()
                if results:
                    output = self.generate_metasploit_rc(results)
                    self.console.print(f"[green]✓ Generated {output}[/green]")
                else:
                    self.console.print("[yellow]No scan results available[/yellow]")
                
            elif choice == "7":
                self.console.print("\n[cyan]Updating Vulnerability Database...[/cyan]")
                if not self.nvd_api_key:
                    self.nvd_api_key = Prompt.ask("Enter NVD API key")
                self.nvd_integration(bulk_update=True)
                
            elif choice == "8":
                self.console.print("\n[cyan]Generating Reports...[/cyan]")
                results = self._load_last_scan_results()
                if results:
                    formats = Prompt.ask("Select formats (comma-separated)", 
                                       default="html,json,markdown").split(",")
                    reports = self.generate_reports(results, formats)
                    for fmt, path in reports.items():
                        self.console.print(f"[green]✓ {fmt.upper()}: {path}[/green]")
                else:
                    self.console.print("[yellow]No scan results available[/yellow]")
                
            elif choice == "9":
                self.console.print("\n[cyan]Optimizing Performance...[/cyan]")
                targets = int(Prompt.ask("Number of targets", default="10"))
                network = Prompt.ask("Network type", default="lan", 
                                   choices=["lan", "wan", "internet"])
                config = self.optimize_performance(targets, network)
                self.console.print(Panel(f"Recommended: {config['max_concurrency']} concurrent connections\n"
                                       f"Timeout: {config['timeout']}ms", style="green"))
                
            elif choice == "10":
                self.console.print("\n[cyan]Generating SIEM Feed...[/cyan]")
                results = self._load_last_scan_results()
                if results:
                    fmt = Prompt.ask("Format", default="cef", choices=["cef", "leef", "json"])
                    feed = self.generate_siem_feed(results, fmt)
                    output_file = f"siem_feed_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"
                    with open(output_file, 'w') as f:
                        f.write(feed if isinstance(feed, str) else json.dumps(feed))
                    self.console.print(f"[green]✓ SIEM feed saved to {output_file}[/green]")
                else:
                    self.console.print("[yellow]No scan results available[/yellow]")
                
            elif choice == "11":
                self.console.print("\n[cyan]Scan History[/cyan]")
                self._display_scan_history()
                
            elif choice == "12":
                self.console.print("\n[cyan]Generating Network Topology...[/cyan]")
                results = self._load_last_scan_results()
                if results:
                    fmt = Prompt.ask("Format", default="dot", choices=["dot", "png"])
                    topology = self.generate_topology(results, fmt)
                    if topology:
                        self.console.print(f"[green]✓ Topology saved to {topology}[/green]")
                else:
                    self.console.print("[yellow]No scan results available[/yellow]")
                
            elif choice == "0":
                self.console.print("[yellow]Exiting...[/yellow]")
                break
            
            else:
                self.console.print("[red]Invalid option[/red]")
            
            if choice != "0":
                Prompt.ask("\n[dim]Press Enter to continue[/dim]")
    
    def _load_last_scan_results(self) -> Optional[Dict]:
        """Load the most recent scan results from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT results FROM scan_history 
            WHERE status = 'completed'
            ORDER BY timestamp DESC 
            LIMIT 1
        ''')
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return json.loads(row[0])
        return None
    
    def _display_scan_history(self):
        """Display scan history from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT timestamp, profile, targets, duration, status
            FROM scan_history
            ORDER BY timestamp DESC
            LIMIT 10
        ''')
        
        rows = cursor.fetchall()
        conn.close()
        
        if rows and self.console:
            table = Table(title="Recent Scans")
            table.add_column("Timestamp", style="cyan")
            table.add_column("Profile", style="green")
            table.add_column("Targets", style="yellow")
            table.add_column("Duration", style="magenta")
            table.add_column("Status", style="white")
            
            for row in rows:
                targets = json.loads(row[2]) if row[2] else []
                target_str = ", ".join(targets[:3])
                if len(targets) > 3:
                    target_str += f" (+{len(targets)-3} more)"
                
                table.add_row(
                    row[0],
                    row[1],
                    target_str,
                    f"{row[3]:.2f}s" if row[3] else "N/A",
                    row[4]
                )
            
            self.console.print(table)
        else:
            print("No scan history available")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="R3COND0G Command & Control System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Build and optimize core
  python r3cond0g_controller.py --build --optimize
  
  # Run scan with specific profile
  python r3cond0g_controller.py --scan aggressive --targets 192.168.1.0/24
  
  # Generate all reports
  python r3cond0g_controller.py --report all --format html,json,markdown
  
  # Update vulnerability database
  python r3cond0g_controller.py --update-vulns --nvd-key YOUR_KEY
  
  # Interactive mode
  python r3cond0g_controller.py --interactive
        """
    )
    
    parser.add_argument("--build", action="store_true", help="Build core binary")
    parser.add_argument("--optimize", action="store_true", help="Enable build optimizations")
    parser.add_argument("--cross-compile", nargs="+", help="Cross-compile targets (e.g., linux/amd64 windows/amd64)")
    
    parser.add_argument("--generate-probes", action="store_true", help="Generate probe definitions")
    parser.add_argument("--custom-services", nargs="+", help="Add custom service probes")
    
    parser.add_argument("--scan", metavar="PROFILE", help="Run scan with profile")
    parser.add_argument("--targets", help="Scan targets (comma-separated)")
    parser.add_argument("--config", help="Use specific configuration file")
    
    parser.add_argument("--import-nmap", metavar="FILE", help="Import Nmap XML results")
    parser.add_argument("--generate-msf", action="store_true", help="Generate Metasploit RC file")
    
    parser.add_argument("--update-vulns", action="store_true", help="Update vulnerability database")
    parser.add_argument("--nvd-key", help="NVD API key")
    
    parser.add_argument("--report", choices=["all", "html", "json", "markdown", "csv"], 
                       help="Generate reports")
    parser.add_argument("--format", help="Report formats (comma-separated)")
    
    parser.add_argument("--optimize-performance", metavar="TARGETS", type=int, 
                       help="Generate optimized config for N targets")
    parser.add_argument("--network-type", choices=["lan", "wan", "internet"], 
                       default="lan", help="Network type for optimization")
    
    parser.add_argument("--siem-feed", choices=["cef", "leef", "json"], 
                       help="Generate SIEM feed")
    
    parser.add_argument("--topology", choices=["dot", "png"], help="Generate network topology")
    
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    
    args = parser.parse_args()
    
    # Initialize controller
    controller = R3COND0GController()
    
    # Handle command-line arguments
    if args.build:
        controller.build_core(args.optimize, args.cross_compile)
    
    elif args.generate_probes:
        controller.generate_probes(args.custom_services)
    
    elif args.scan:
        targets = args.targets.split(",") if args.targets else None
        results = controller.run_scan(args.scan, targets)
        if results:
            print(f"Scan completed. Found {len(results.get('services', {}))} services")
    
    elif args.import_nmap:
        results = controller.integrate_nmap(args.import_nmap)
        print(f"Imported {len(results.get('hosts', []))} hosts")
    
    elif args.generate_msf:
        results = controller._load_last_scan_results()
        if results:
            output = controller.generate_metasploit_rc(results)
            print(f"Generated Metasploit RC: {output}")
    
    elif args.update_vulns:
        if args.nvd_key:
            controller.nvd_api_key = args.nvd_key
        controller.nvd_integration(bulk_update=True)
    
    elif args.report:
        results = controller._load_last_scan_results()
        if results:
            formats = args.format.split(",") if args.format else ["html", "json"]
            reports = controller.generate_reports(results, formats)
            for fmt, path in reports.items():
                print(f"Generated {fmt.upper()} report: {path}")
    
    elif args.optimize_performance:
        config = controller.optimize_performance(args.optimize_performance, args.network_type)
        print(f"Optimization config generated: {config['performance_profile']}")
    
    elif args.siem_feed:
        results = controller._load_last_scan_results()
        if results:
            feed = controller.generate_siem_feed(results, args.siem_feed)
            output_file = f"siem_feed.{args.siem_feed}"
            with open(output_file, 'w') as f:
                f.write(feed if isinstance(feed, str) else json.dumps(feed))
            print(f"SIEM feed saved to {output_file}")
    
    elif args.topology:
        results = controller._load_last_scan_results()
        if results:
            output = controller.generate_topology(results, args.topology)
            if output:
                print(f"Topology saved to {output}")
    
    elif args.interactive:
        controller.interactive_mode()
    
    else:
        # Default: show interactive mode if available
        if RICH_AVAILABLE:
            controller.interactive_mode()
        else:
            parser.print_help()

if __name__ == "__main__":
    main()#!/usr/bin/env python3
"""
R3COND0G Command & Control System
Advanced Orchestration and Management Platform
Version: 3.0.0
Author: 0xb0rn3 & 0xbv1
"""

import os
import sys
import json
import yaml
import time
import subprocess
import argparse
import logging
import hashlib
import sqlite3
import requests
import threading
import shutil
import platform
import tempfile
import concurrent.futures
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import xml.etree.ElementTree as ET

# Rich console output (install with: pip install rich)
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.prompt import Prompt, Confirm
    from rich import print as rprint
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Warning: 'rich' library not installed. Install with: pip install rich")

# Advanced features
try:
    import networkx as nx
    import matplotlib.pyplot as plt
    NETWORK_VIZ = True
except ImportError:
    NETWORK_VIZ = False

class ScanMode(Enum):
    """Scan operation modes"""
    STEALTH = "stealth"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"
    CUSTOM = "custom"
    DISCOVERY = "discovery"
    VULNERABILITY = "vulnerability"

class OutputFormat(Enum):
    """Output format types"""
    JSON = "json"
    XML = "xml"
    CSV = "csv"
    HTML = "html"
    MARKDOWN = "markdown"
    NMAP = "nmap"
    METASPLOIT = "metasploit"
    SIEM = "siem"

@dataclass
class ScanProfile:
    """Scan profile configuration"""
    name: str
    mode: ScanMode
    targets: List[str]
    ports: str
    timeout: int
    concurrency: int
    options: Dict[str, Any]

class R3COND0GController:
    """Main controller for R3COND0G orchestration"""
    
    def __init__(self):
        self.console = Console() if RICH_AVAILABLE else None
        self.logger = self._setup_logging()
        self.config = self._load_config()
        self.cache_dir = Path.home() / ".r3cond0g_cache"
        self.cache_dir.mkdir(exist_ok=True)
        self.db_path = self.cache_dir / "r3cond0g.db"
        self.probe_dir = Path("probes")
        self.probe_dir.mkdir(exist_ok=True)
        self.nvd_api_key = os.environ.get("NVD_API_KEY", "")
        self.profiles = {}
        self.init_database()
        
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler("r3cond0g_controller.log"),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger("R3COND0G_Controller")
    
    def _load_config(self) -> Dict:
        """Load or create default configuration"""
        config_path = Path("controller_config.json")
        if config_path.exists():
            with open(config_path, 'r') as f:
                return json.load(f)
        else:
            default_config = {
                "version": "3.0.0",
                "core_binary": "./r3cond0g",
                "max_concurrency": 1000,
                "default_timeout": 5000,
                "cache_ttl": 86400,
                "auto_update": True,
                "performance_mode": "balanced",
                "integrations": {
                    "nmap": {"enabled": True, "path": "nmap"},
                    "metasploit": {"enabled": False, "path": "msfconsole"},
                    "siem": {"enabled": False, "endpoint": ""}
                }
            }
            with open(config_path, 'w') as f:
                json.dump(default_config, f, indent=2)
            return default_config
    
    def init_database(self):
        """Initialize SQLite database for caching and history"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Scan history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                profile TEXT,
                targets TEXT,
                ports TEXT,
                results TEXT,
                duration REAL,
                status TEXT
            )
        ''')
        
        # Vulnerability cache table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vuln_cache (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                cvss_score REAL,
                published_date DATE,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                affected_products TEXT
            )
        ''')
        
        # Performance metrics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                scan_rate REAL,
                memory_usage REAL,
                cpu_usage REAL,
                network_throughput REAL
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def build_core(self, optimize: bool = True, cross_compile: List[str] = None):
        """Build the Go core binary with optimizations"""
        self.logger.info("Building R3COND0G core...")
        
        build_cmd = ["go", "build"]
        
        if optimize:
            build_cmd.extend(["-ldflags", "-s -w"])
            
        build_cmd.extend(["-o", "r3cond0g", "main.go"])
        
        try:
            # Build for current platform
            result = subprocess.run(build_cmd, capture_output=True, text=True)
            if result.returncode == 0:
                self.logger.info("✓ Core binary built successfully")
                
                # Set executable permissions on Unix
                if platform.system() != "Windows":
                    os.chmod("r3cond0g", 0o755)
            else:
                self.logger.error(f"Build failed: {result.stderr}")
                return False
                
            # Cross-compile if requested
            if cross_compile:
                for target in cross_compile:
                    os_name, arch = target.split("/")
                    env = os.environ.copy()
                    env["GOOS"] = os_name
                    env["GOARCH"] = arch
                    
                    output_name = f"r3cond0g_{os_name}_{arch}"
                    if os_name == "windows":
                        output_name += ".exe"
                    
                    build_cmd[-1] = "main.go"
                    build_cmd[-2] = output_name
                    
                    result = subprocess.run(build_cmd, capture_output=True, text=True, env=env)
                    if result.returncode == 0:
                        self.logger.info(f"✓ Built for {target}")
                    else:
                        self.logger.error(f"Failed to build for {target}")
                        
            return True
            
        except Exception as e:
            self.logger.error(f"Build error: {e}")
            return False
    
    def generate_probes(self, custom_services: List[str] = None):
        """Generate probe definitions for service detection"""
        
        # Default TCP probes
        tcp_probes = [
            {
                "name": "SSH-Banner",
                "protocol": "TCP",
                "ports": [22, 2222],
                "priority": 10,
                "requires_tls": False,
                "send_payload": "",
                "read_pattern": "^SSH-([0-9.]+)-([^\\s\\r\\n]+)",
                "service_override": "ssh",
                "version_template": "{{group_2}} (protocol {{group_1}})",
                "timeout_ms": 3000
            },
            {
                "name": "HTTP-Server",
                "protocol": "TCP",
                "ports": [80, 8080, 8000, 3000],
                "priority": 15,
                "requires_tls": False,
                "send_payload": "GET / HTTP/1.1\\r\\nHost: {{TARGET_HOST}}\\r\\n\\r\\n",
                "read_pattern": "(?i)Server:\\s*([^\\r\\n]+)",
                "service_override": "http",
                "version_template": "{{group_1}}",
                "timeout_ms": 5000
            },
            {
                "name": "HTTPS-Server",
                "protocol": "TCP",
                "ports": [443, 8443],
                "priority": 15,
                "requires_tls": True,
                "tls_alpn_protocols": ["http/1.1", "h2"],
                "send_payload": "GET / HTTP/1.1\\r\\nHost: {{TARGET_HOST}}\\r\\n\\r\\n",
                "read_pattern": "(?i)Server:\\s*([^\\r\\n]+)",
                "service_override": "https",
                "version_template": "{{group_1}}",
                "timeout_ms": 8000
            },
            {
                "name": "MySQL-Version",
                "protocol": "TCP",
                "ports": [3306],
                "priority": 10,
                "requires_tls": False,
                "send_payload": "",
                "read_pattern": "\\x0a([0-9.]+[^\\x00]*)",
                "service_override": "mysql",
                "version_template": "{{group_1}}",
                "timeout_ms": 3000
            },
            {
                "name": "PostgreSQL",
                "protocol": "TCP",
                "ports": [5432],
                "priority": 10,
                "requires_tls": False,
                "send_payload": "\\x00\\x00\\x00\\x08\\x04\\xd2\\x16\\x2f",
                "read_pattern": "FATAL.*?version \"([^\"]+)\"",
                "service_override": "postgresql",
                "version_template": "{{group_1}}",
                "timeout_ms": 4000
            },
            {
                "name": "Redis-Info",
                "protocol": "TCP",
                "ports": [6379],
                "priority": 15,
                "requires_tls": False,
                "send_payload": "INFO\\r\\n",
                "read_pattern": "redis_version:([^\\r\\n]+)",
                "service_override": "redis",
                "version_template": "{{group_1}}",
                "timeout_ms": 3000
            },
            {
                "name": "MongoDB",
                "protocol": "TCP",
                "ports": [27017, 27018, 27019],
                "priority": 15,
                "requires_tls": False,
                "send_payload": "",
                "read_pattern": "version.*?([0-9.]+)",
                "service_override": "mongodb",
                "version_template": "{{group_1}}",
                "timeout_ms": 4000
            },
            {
                "name": "RDP",
                "protocol": "TCP",
                "ports": [3389],
                "priority": 10,
                "requires_tls": False,
                "send_payload": "\\x03\\x00\\x00\\x13\\x0e\\xe0\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x08\\x00\\x03\\x00\\x00\\x00",
                "read_pattern": "\\x03\\x00\\x00\\x13\\x0e\\xd0",
                "service_override": "rdp",
                "version_template": "RDP Service",
                "timeout_ms": 3000
            }
        ]
        
        # Default UDP probes
        udp_probes = [
            {
                "name": "DNS-Version",
                "protocol": "UDP",
                "ports": [53],
                "priority": 10,
                "requires_tls": False,
                "send_payload": "\\x00\\x1e\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07version\\x04bind\\x00\\x00\\x10\\x00\\x03",
                "read_pattern": "([0-9]+\\.[0-9]+)",
                "service_override": "dns",
                "version_template": "BIND {{group_1}}",
                "timeout_ms": 3000
            },
            {
                "name": "SNMP",
                "protocol": "UDP",
                "ports": [161],
                "priority": 10,
                "requires_tls": False,
                "send_payload": "\\x30\\x26\\x02\\x01\\x00\\x04\\x06\\x70\\x75\\x62\\x6c\\x69\\x63\\xa0\\x19",
                "read_pattern": ".",
                "service_override": "snmp",
                "version_template": "SNMPv1/v2c",
                "timeout_ms": 3000
            },
            {
                "name": "NTP",
                "protocol": "UDP",
                "ports": [123],
                "priority": 10,
                "requires_tls": False,
                "send_payload": "\\x16\\x02\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00",
                "read_pattern": ".",
                "service_override": "ntp",
                "version_template": "NTP Service",
                "timeout_ms": 2000
            }
        ]
        
        # Add custom service probes if specified
        if custom_services:
            for service in custom_services:
                tcp_probes.append(self._generate_custom_probe(service))
        
        # Save probe files
        with open(self.probe_dir / "tcp_probes.json", 'w') as f:
            json.dump(tcp_probes, f, indent=2)
            
        with open(self.probe_dir / "udp_probes.json", 'w') as f:
            json.dump(udp_probes, f, indent=2)
            
        self.logger.info(f"✓ Generated {len(tcp_probes)} TCP and {len(udp_probes)} UDP probes")
        return True
    
    def _generate_custom_probe(self, service: str) -> Dict:
        """Generate a custom probe definition"""
        return {
            "name": f"Custom-{service}",
            "protocol": "TCP",
            "ports": [],  # Will be determined dynamically
            "priority": 50,
            "requires_tls": False,
            "send_payload": f"{service.upper()}\\r\\n",
            "read_pattern": f".*{service}.*",
            "service_override": service.lower(),
            "version_template": "{{group_0}}",
            "timeout_ms": 5000
        }
    
    def generate_config(self, profile: str = "default") -> Dict:
        """Generate configuration for different scan profiles"""
        
        configs = {
            "default": {
                "target_host": "",
                "port_range": "1-1000",
                "scan_timeout": 1000,
                "service_detect_timeout": 5000,
                "max_concurrency": 100,
                "udp_scan": False,
                "vuln_mapping": False,
                "topology_mapping": False,
                "ping_sweep_tcp": True,
                "ping_sweep_icmp": False,
                "enable_mac_lookup": False,
                "probe_files": "probes/tcp_probes.json,probes/udp_probes.json"
            },
            "stealth": {
                "target_host": "",
                "port_range": "22,80,443,3389",
                "scan_timeout": 3000,
                "service_detect_timeout": 8000,
                "max_concurrency": 10,
                "udp_scan": False,
                "vuln_mapping": False,
                "topology_mapping": False,
                "ping_sweep_tcp": False,
                "ping_sweep_icmp": False,
                "enable_mac_lookup": False,
                "fragment_packets": True,
                "decoy_hosts": ["10.0.0.99", "10.0.0.100"],
                "probe_files": "probes/tcp_probes.json"
            },
            "aggressive": {
                "target_host": "",
                "port_range": "1-65535",
                "scan_timeout": 500,
                "service_detect_timeout": 3000,
                "max_concurrency": 1000,
                "udp_scan": True,
                "vuln_mapping": True,
                "topology_mapping": True,
                "ping_sweep_tcp": True,
                "ping_sweep_icmp": True,
                "enable_mac_lookup": True,
                "os_detect": True,
                "version_detect": True,
                "script_scan": True,
                "probe_files": "probes/tcp_probes.json,probes/udp_probes.json"
            },
            "vulnerability": {
                "target_host": "",
                "port_range": "1-10000",
                "scan_timeout": 2000,
                "service_detect_timeout": 10000,
                "max_concurrency": 50,
                "udp_scan": False,
                "vuln_mapping": True,
                "topology_mapping": False,
                "ping_sweep_tcp": True,
                "ping_sweep_icmp": False,
                "enable_mac_lookup": False,
                "service_detect": True,
                "version_detect": True,
                "nvd_api_key": self.nvd_api_key,
                "cve_plugin_file": "custom_cves.json",
                "probe_files": "probes/tcp_probes.json"
            },
            "discovery": {
                "target_host": "",
                "port_range": "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080",
                "scan_timeout": 1500,
                "service_detect_timeout": 5000,
                "max_concurrency": 200,
                "udp_scan": True,
                "vuln_mapping": False,
                "topology_mapping": True,
                "ping_sweep_tcp": True,
                "ping_sweep_icmp": True,
                "ping_sweep_ports": "80,443,22,3389,445",
                "enable_mac_lookup": True,
                "probe_files": "probes/tcp_probes.json,probes/udp_probes.json"
            }
        }
        
        config = configs.get(profile, configs["default"])
        
        # Save as JSON
        with open(f"config_{profile}.json", 'w') as f:
            json.dump(config, f, indent=2)
            
        # Save as YAML
        with open(f"config_{profile}.yaml", 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
            
        self.logger.info(f"✓ Generated configuration for profile: {profile}")
        return config
    
    def create_scan_profile(self, name: str, base: str = "default") -> ScanProfile:
        """Create a custom scan profile"""
        base_config = self.generate_config(base)
        
        if self.console:
            self.console.print(Panel(f"Creating scan profile: {name}", style="bold blue"))
            
            # Interactive configuration
            targets = Prompt.ask("Enter targets (comma-separated)")
            ports = Prompt.ask("Enter port range", default=base_config["port_range"])
            timeout = int(Prompt.ask("Connection timeout (ms)", default=str(base_config["scan_timeout"])))
            concurrency = int(Prompt.ask("Max concurrency", default=str(base_config["max_concurrency"])))
            
            udp = Confirm.ask("Enable UDP scanning?", default=False)
            vuln = Confirm.ask("Enable vulnerability mapping?", default=False)
            topology = Confirm.ask("Generate network topology?", default=False)
            
            profile = ScanProfile(
                name=name,
                mode=ScanMode.CUSTOM,
                targets=targets.split(","),
                ports=ports,
                timeout=timeout,
                concurrency=concurrency,
                options={
                    "udp_scan": udp,
                    "vuln_mapping": vuln,
                    "topology_mapping": topology
                }
            )
        else:
            # Non-interactive mode
            profile = ScanProfile(
                name=name,
                mode=ScanMode.CUSTOM,
                targets=[],
                ports=base_config["port_range"],
                timeout=base_config["scan_timeout"],
                concurrency=base_config["max_concurrency"],
                options=base_config
            )
        
        self.profiles[name] = profile
        
        # Save profile
        profile_path = self.cache_dir / f"profile_{name}.json"
        with open(profile_path, 'w') as f:
            json.dump(asdict(profile), f, indent=2)
            
        self.logger.info(f"✓ Created scan profile: {name}")
        return profile
    
    def run_scan(self, profile: str = "default", targets: List[str] = None) -> Dict:
        """Execute a scan with specified profile"""
        
        # Load or create configuration
        if profile in self.profiles:
            scan_profile = self.profiles[profile]
            config = scan_profile.options
        else:
            config = self.generate_config(profile)
            
        # Override targets if provided
        if targets:
            config["target_host"] = ",".join(targets)
            
        # Prepare command
        cmd = [self.config["core_binary"]]
        
        # Add configuration parameters
        for key, value in config.items():
            if isinstance(value, bool):
                if value:
                    cmd.append(f"-{key.replace('_', '-')}")
            elif value:
                cmd.append(f"-{key.replace('_', '-')}")
                cmd.append(str(value))
        
        # Execute scan
        self.logger.info(f"Starting scan with profile: {profile}")
        start_time = time.time()
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            duration = time.time() - start_time
            
            # Parse results
            scan_results = self._parse_scan_output(result.stdout)
            
            # Store in database
            self._store_scan_results(profile, targets, config.get("port_range", ""), 
                                   scan_results, duration, "completed")
            
            self.logger.info(f"✓ Scan completed in {duration:.2f} seconds")
            return scan_results
            
        except subprocess.TimeoutExpired:
            self.logger.error("Scan timeout exceeded")
            return {"error": "timeout"}
        except Exception as e:
            self.logger.error(f"Scan error: {e}")
            return {"error": str(e)}
    
    def _parse_scan_output(self, output: str) -> Dict:
        """Parse scan output into structured format"""
        results = {
            "hosts": [],
            "services": {},
            "vulnerabilities": [],
            "statistics": {}
        }
        
        # Basic parsing (would be more sophisticated in production)
        lines = output.split("\n")
        for line in lines:
            if "open" in line.lower():
                # Parse open port information
                parts = line.split()
                if len(parts) >= 3:
                    host = parts[0]
                    port = parts[1]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    
                    if host not in results["services"]:
                        results["services"][host] = []
                    results["services"][host].append({
                        "port": port,
                        "service": service,
                        "state": "open"
                    })
                    
        return results
    
    def _store_scan_results(self, profile: str, targets: List[str], ports: str, 
                           results: Dict, duration: float, status: str):
        """Store scan results in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO scan_history (profile, targets, ports, results, duration, status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (profile, json.dumps(targets), ports, json.dumps(results), duration, status))
        
        conn.commit()
        conn.close()
    
    def integrate_nmap(self, nmap_file: str) -> Dict:
        """Import and process Nmap XML results"""
        self.logger.info(f"Importing Nmap results from {nmap_file}")
        
        try:
            tree = ET.parse(nmap_file)
            root = tree.getroot()
            
            results = {
                "hosts": [],
                "services": {},
                "os_detection": {}
            }
            
            for host in root.findall('.//host'):
                addr = host.find('.//address[@addrtype="ipv4"]')
                if addr is not None:
                    ip = addr.get('addr')
                    results["hosts"].append(ip)
                    results["services"][ip] = []
                    
                    # Parse ports
                    for port in host.findall('.//port'):
                        port_id = port.get('portid')
                        protocol = port.get('protocol')
                        state = port.find('state').get('state')
                        service = port.find('service')
                        
                        service_info = {
                            "port": port_id,
                            "protocol": protocol,
                            "state": state
                        }
                        
                        if service is not None:
                            service_info["service"] = service.get('name', 'unknown')
                            service_info["version"] = service.get('version', '')
                            
                        results["services"][ip].append(service_info)
                    
                    # Parse OS detection
                    os_match = host.find('.//osmatch')
                    if os_match is not None:
                        results["os_detection"][ip] = {
                            "name": os_match.get('name'),
                            "accuracy": os_match.get('accuracy')
                        }
            
            # Convert to R3COND0G format and enhance
            enhanced_results = self._enhance_nmap_results(results)
            
            self.logger.info(f"✓ Imported {len(results['hosts'])} hosts from Nmap")
            return enhanced_results
            
        except Exception as e:
            self.logger.error(f"Failed to parse Nmap file: {e}")
            return {}
    
    def _enhance_nmap_results(self, nmap_results: Dict) -> Dict:
        """Enhance Nmap results with additional scanning"""
        # Run targeted scans on discovered services
        enhanced = nmap_results.copy()
        
        for host, services in nmap_results["services"].items():
            # Run service detection on open ports
            open_ports = [s["port"] for s in services if s["state"] == "open"]
            if open_ports:
                config = {
                    "target_host": host,
                    "port_range": ",".join(open_ports),
                    "service_detect": True,
                    "version_detect": True,
                    "vuln_mapping": True
                }
                
                # Run focused scan
                scan_results = self.run_scan("custom", [host])
                
                # Merge results
                if host in scan_results.get("services", {}):
                    enhanced["services"][host] = scan_results["services"][host]
                    
        return enhanced
    
    def generate_metasploit_rc(self, scan_results: Dict, output_file: str = "r3cond0g.rc"):
        """Generate Metasploit resource script from scan results"""
        self.logger.info("Generating Metasploit resource script")
        
        rc_commands = []
        rc_commands.append("# R3COND0G Metasploit Resource Script")
        rc_commands.append(f"# Generated: {datetime.now()}")
        rc_commands.append("")
        
        # Workspace setup
        rc_commands.append("workspace -a r3cond0g_scan")
        rc_commands.append("")
        
        # Add discovered hosts
        for host in scan_results.get("hosts", []):
            rc_commands.append(f"db_nmap -sV -p- {host}")
            
        # Generate exploit suggestions based on services
        for host, services in scan_results.get("services", {}).items():
            for service in services:
                if service.get("state") == "open":
                    port = service.get("port")
                    svc_name = service.get("service", "").lower()
                    
                    # Common service exploits
                    if "ssh" in svc_name:
                        rc_commands.append(f"use auxiliary/scanner/ssh/ssh_version")
                        rc_commands.append(f"set RHOSTS {host}")
                        rc_commands.append("run")
                        rc_commands.append("")
                        
                    elif "http" in svc_name:
                        rc_commands.append(f"use auxiliary/scanner/http/dir_scanner")
                        rc_commands.append(f"set RHOSTS {host}")
                        rc_commands.append(f"set RPORT {port}")
                        rc_commands.append("run")
                        rc_commands.append("")
                        
                    elif "smb" in svc_name or "microsoft-ds" in svc_name:
                        rc_commands.append(f"use auxiliary/scanner/smb/smb_version")
                        rc_commands.append(f"set RHOSTS {host}")
                        rc_commands.append("run")
                        rc_commands.append("")
                        
                    elif "mysql" in svc_name:
                        rc_commands.append(f"use auxiliary/scanner/mysql/mysql_version")
                        rc_commands.append(f"set RHOSTS {host}")
                        rc_commands.append("run")
                        rc_commands.append("")
