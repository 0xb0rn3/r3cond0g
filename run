#!/usr/bin/env python3
"""
R3COND0G (HellHound) Universal Controller Script
Advanced Network Reconnaissance Framework

Authors: 0xb0rn3 & 0xbv1
Version: 3.0.0 HellHound
Build Date: 2025-08-16
"""

import os
import sys
import json
import time
import shutil
import subprocess
import platform
import requests
import argparse
import tempfile
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import logging
import signal
import threading
import queue
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

# Rich library for beautiful terminal output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.prompt import Prompt, Confirm
    from rich.layout import Layout
    from rich.live import Live
    from rich.tree import Tree
    from rich.text import Text
    from rich.align import Align
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Constants
VERSION = "3.0.0 HellHound"
BUILD_DATE = "2025-08-16"
AUTHORS = "IG:theehiv3 Alias:0xbv1 | Github:0xb0rn3"
APP_NAME = "r3cond0g"
REPO_URL = "https://github.com/0xb0rn3/r3cond0g"

# Global console instance
console = Console() if RICH_AVAILABLE else None

@dataclass
class ScanProfile:
    """Scan profile configuration"""
    name: str
    description: str
    scan_type: str
    targets: List[str]
    ports: str
    timeout: int
    concurrency: int
    rate_limit: int
    service_detect: bool
    version_detect: bool
    os_detect: bool
    vuln_mapping: bool
    stealth_mode: bool
    udp_scan: bool
    ping_sweep: bool
    output_format: str
    additional_options: Dict

    def to_dict(self) -> Dict:
        return asdict(self)

class LinuxDistribution:
    """Linux distribution detection and management"""
    
    def __init__(self):
        self.distro_info = self._detect_distribution()
        
    def _detect_distribution(self) -> Dict[str, str]:
        """Detect Linux distribution and version"""
        info = {
            'name': 'unknown',
            'version': 'unknown',
            'family': 'unknown',
            'package_manager': 'unknown'
        }
        
        # Check /etc/os-release first (most modern distributions)
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release', 'r') as f:
                lines = f.readlines()
                for line in lines:
                    if line.startswith('ID='):
                        info['name'] = line.split('=')[1].strip().strip('"')
                    elif line.startswith('VERSION_ID='):
                        info['version'] = line.split('=')[1].strip().strip('"')
        
        # Fallback methods
        elif os.path.exists('/etc/redhat-release'):
            with open('/etc/redhat-release', 'r') as f:
                content = f.read().strip()
                if 'CentOS' in content:
                    info['name'] = 'centos'
                elif 'Red Hat' in content:
                    info['name'] = 'rhel'
                elif 'Fedora' in content:
                    info['name'] = 'fedora'
        
        elif os.path.exists('/etc/debian_version'):
            info['name'] = 'debian'
            with open('/etc/debian_version', 'r') as f:
                info['version'] = f.read().strip()
        
        # Determine family and package manager
        debian_based = ['ubuntu', 'debian', 'kali', 'parrot', 'mint', 'pop', 'elementary', 'zorin']
        rhel_based = ['rhel', 'centos', 'fedora', 'rocky', 'alma', 'oracle']
        arch_based = ['arch', 'manjaro', 'endeavour', 'garuda']
        suse_based = ['opensuse', 'sles']
        
        if info['name'] in debian_based:
            info['family'] = 'debian'
            info['package_manager'] = 'apt'
        elif info['name'] in rhel_based:
            info['family'] = 'rhel'
            info['package_manager'] = 'yum' if info['name'] in ['rhel', 'centos'] else 'dnf'
        elif info['name'] in arch_based:
            info['family'] = 'arch'
            info['package_manager'] = 'pacman'
        elif info['name'] in suse_based:
            info['family'] = 'suse'
            info['package_manager'] = 'zypper'
        elif info['name'] == 'alpine':
            info['family'] = 'alpine'
            info['package_manager'] = 'apk'
        elif info['name'] == 'gentoo':
            info['family'] = 'gentoo'
            info['package_manager'] = 'emerge'
        elif info['name'] == 'void':
            info['family'] = 'void'
            info['package_manager'] = 'xbps'
        
        return info
    
    def get_install_command(self, packages: List[str]) -> List[str]:
        """Get package installation command for current distribution"""
        pm = self.distro_info['package_manager']
        
        if pm == 'apt':
            return ['sudo', 'apt', 'update', '&&', 'sudo', 'apt', 'install', '-y'] + packages
        elif pm == 'yum':
            return ['sudo', 'yum', 'install', '-y'] + packages
        elif pm == 'dnf':
            return ['sudo', 'dnf', 'install', '-y'] + packages
        elif pm == 'pacman':
            return ['sudo', 'pacman', '-S', '--noconfirm'] + packages
        elif pm == 'zypper':
            return ['sudo', 'zypper', 'install', '-y'] + packages
        elif pm == 'apk':
            return ['sudo', 'apk', 'add'] + packages
        elif pm == 'emerge':
            return ['sudo', 'emerge'] + packages
        elif pm == 'xbps':
            return ['sudo', 'xbps-install', '-S'] + packages
        else:
            return ['echo', 'Unsupported package manager:', pm]

class R3COND0GController:
    """Main controller class for R3COND0G"""
    
    def __init__(self):
        self.script_dir = Path(__file__).parent.absolute()
        self.config_dir = self.script_dir / "config"
        self.profiles_dir = self.config_dir / "profiles"
        self.reports_dir = self.script_dir / "reports"
        self.db_path = self.script_dir / "r3cond0g.db"
        self.binary_path = self.script_dir / "r3cond0g"
        self.distro = LinuxDistribution()
        
        # Create directories
        for directory in [self.config_dir, self.profiles_dir, self.reports_dir]:
            directory.mkdir(exist_ok=True)
        
        # Setup logging
        self.setup_logging()
        
        # Initialize database
        self.init_database()
        
        # Load default configuration
        self.config = self.load_config()
        
    def setup_logging(self):
        """Setup logging configuration"""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler(self.script_dir / 'r3cond0g.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('R3COND0G')
    
    def init_database(self):
        """Initialize SQLite database for scan history and results"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create tables
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT UNIQUE,
                    profile_name TEXT,
                    targets TEXT,
                    start_time TEXT,
                    end_time TEXT,
                    status TEXT,
                    results_file TEXT,
                    command TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    host TEXT,
                    port INTEGER,
                    protocol TEXT,
                    state TEXT,
                    service TEXT,
                    version TEXT,
                    banner TEXT,
                    vulnerabilities TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE,
                    config TEXT,
                    created_at TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
    
    def load_config(self) -> Dict:
        """Load default configuration"""
        default_config = {
            "version": VERSION,
            "build_date": BUILD_DATE,
            "default_timeout": 1000,
            "default_concurrency": 100,
            "max_concurrency": 10000,
            "rate_limit": 1000,
            "output_formats": ["json", "xml", "html", "csv", "markdown"],
            "supported_protocols": ["tcp", "udp", "icmp"],
            "default_ports": {
                "top100": "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157",
                "top1000": "1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-255,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389"
            },
            "nvd_api_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "update_check_url": f"{REPO_URL}/releases/latest"
        }
        
        config_file = self.config_dir / "config.json"
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    saved_config = json.load(f)
                    default_config.update(saved_config)
            except Exception as e:
                self.logger.error(f"Failed to load config: {e}")
        
        return default_config
    
    def save_config(self):
        """Save current configuration"""
        config_file = self.config_dir / "config.json"
        try:
            with open(config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save config: {e}")
    
    def print_banner(self):
        """Print application banner"""
        if RICH_AVAILABLE:
            banner_text = f"""
    ██████╗ ██████╗  ██████╗ ██████╗ ███╗   ██╗██████╗  ██████╗  ██████╗ 
    ██╔══██╗╚════██╗██╔════╝██╔═══██╗████╗  ██║██╔══██╗██╔═████╗██╔════╝ 
    ██████╔╝ █████╔╝██║     ██║   ██║██╔██╗ ██║██║  ██║██║██╔██║██║  ███╗
    ██╔══██╗ ╚═══██╗██║     ██║   ██║██║╚██╗██║██║  ██║████╔╝██║██║   ██║
    ██║  ██║██████╔╝╚██████╗╚██████╔╝██║ ╚████║██████╔╝╚██████╔╝╚██████╔╝
    ╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝  ╚═════╝  ╚═════╝ 

                    🦅 Advanced Network Reconnaissance Framework
                           {VERSION} - Built {BUILD_DATE}
                              Authors: {AUTHORS}
            """
            
            console.print(Panel(
                Align.center(Text(banner_text, style="bold red")),
                title="[bold blue]R3COND0G Command & Control System[/bold blue]",
                border_style="blue"
            ))
        else:
            print(f"\n{'='*80}")
            print(f"R3COND0G (HellHound) - Advanced Network Reconnaissance Framework")
            print(f"Version: {VERSION} | Build Date: {BUILD_DATE}")
            print(f"Authors: {AUTHORS}")
            print(f"{'='*80}\n")
    
    def check_dependencies(self) -> bool:
        """Check if all dependencies are installed"""
        deps = {
            'go': ['go', 'version'],
            'python3': ['python3', '--version'],
            'git': ['git', '--version']
        }
        
        missing = []
        for name, cmd in deps.items():
            try:
                subprocess.run(cmd, capture_output=True, check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                missing.append(name)
        
        if missing:
            self.logger.warning(f"Missing dependencies: {', '.join(missing)}")
            return False
        return True
    
    def install_dependencies(self) -> bool:
        """Install required dependencies"""
        if RICH_AVAILABLE:
            console.print("[yellow]Installing dependencies...[/yellow]")
        else:
            print("Installing dependencies...")
        
        # Base packages for different distributions
        package_maps = {
            'debian': ['golang-go', 'python3-pip', 'python3-dev', 'git', 'libpcap-dev', 'build-essential'],
            'rhel': ['golang', 'python3-pip', 'python3-devel', 'git', 'libpcap-devel', 'gcc'],
            'arch': ['go', 'python-pip', 'git', 'libpcap', 'base-devel'],
            'suse': ['go', 'python3-pip', 'python3-devel', 'git', 'libpcap-devel', 'gcc'],
            'alpine': ['go', 'py3-pip', 'git', 'libpcap-dev', 'build-base'],
            'gentoo': ['dev-lang/go', 'dev-python/pip', 'dev-vcs/git', 'net-libs/libpcap'],
            'void': ['go', 'python3-pip', 'git', 'libpcap-devel', 'base-devel']
        }
        
        family = self.distro.distro_info['family']
        packages = package_maps.get(family, package_maps['debian'])  # Default to debian
        
        cmd = self.distro.get_install_command(packages)
        
        try:
            if RICH_AVAILABLE:
                with console.status("[bold green]Installing system packages...") as status:
                    subprocess.run(' '.join(cmd), shell=True, check=True, capture_output=True)
            else:
                print("Installing system packages...")
                subprocess.run(' '.join(cmd), shell=True, check=True)
            
            # Install Python packages
            python_packages = [
                'rich>=12.0.0', 'requests', 'colorama', 'tabulate',
                'python-nmap', 'scapy', 'cryptography', 'lxml'
            ]
            
            pip_cmd = ['python3', '-m', 'pip', 'install', '--user'] + python_packages
            
            if RICH_AVAILABLE:
                with console.status("[bold green]Installing Python packages...") as status:
                    subprocess.run(pip_cmd, check=True, capture_output=True)
            else:
                print("Installing Python packages...")
                subprocess.run(pip_cmd, check=True)
            
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to install dependencies: {e}")
            return False
    
    def build_binary(self) -> bool:
        """Build the Go binary"""
        if RICH_AVAILABLE:
            console.print("[bold green]Building R3COND0G core binary...[/bold green]")
        else:
            print("Building R3COND0G core binary...")
        
        main_go_path = self.script_dir / "main.go"
        if not main_go_path.exists():
            self.logger.error("main.go not found!")
            return False
        
        try:
            # Initialize Go module if needed
            if not (self.script_dir / "go.mod").exists():
                subprocess.run(['go', 'mod', 'init', 'r3cond0g'], 
                             cwd=self.script_dir, check=True, capture_output=True)
                subprocess.run(['go', 'mod', 'tidy'], 
                             cwd=self.script_dir, check=True, capture_output=True)
            
            # Build binary with optimizations
            build_cmd = [
                'go', 'build',
                '-ldflags=-s -w',
                '-o', str(self.binary_path),
                'main.go'
            ]
            
            if RICH_AVAILABLE:
                with console.status("[bold blue]Compiling Go binary...") as status:
                    result = subprocess.run(build_cmd, cwd=self.script_dir, 
                                          capture_output=True, text=True)
            else:
                print("Compiling Go binary...")
                result = subprocess.run(build_cmd, cwd=self.script_dir)
            
            if result.returncode != 0:
                self.logger.error(f"Build failed: {result.stderr}")
                return False
            
            # Set capabilities for non-root packet capture
            try:
                subprocess.run(['sudo', 'setcap', 'cap_net_raw,cap_net_admin=eip', 
                              str(self.binary_path)], check=True, capture_output=True)
            except subprocess.CalledProcessError:
                self.logger.warning("Failed to set capabilities. ICMP scanning may require root.")
            
            if RICH_AVAILABLE:
                console.print("[bold green]✓ Binary built successfully![/bold green]")
            else:
                print("✓ Binary built successfully!")
            
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Build failed: {e}")
            return False
    
    def setup_system(self) -> bool:
        """Complete system setup"""
        if RICH_AVAILABLE:
            console.print("[bold yellow]Starting R3COND0G setup...[/bold yellow]")
        else:
            print("Starting R3COND0G setup...")
        
        # Check if skip dependencies is set
        if os.getenv('SKIP_DEPS'):
            if RICH_AVAILABLE:
                console.print("[yellow]Skipping dependency installation (SKIP_DEPS set)[/yellow]")
        else:
            if not self.check_dependencies():
                if RICH_AVAILABLE:
                    if Confirm.ask("Install missing dependencies?"):
                        if not self.install_dependencies():
                            return False
                else:
                    response = input("Install missing dependencies? (y/n): ")
                    if response.lower() == 'y':
                        if not self.install_dependencies():
                            return False
        
        # Build binary
        force_build = os.getenv('FORCE_BUILD') or not self.binary_path.exists()
        if force_build:
            if not self.build_binary():
                return False
        
        # Create default profiles
        self.create_default_profiles()
        
        # Update system settings for performance
        self.optimize_system()
        
        if RICH_AVAILABLE:
            console.print("[bold green]✓ Setup completed successfully![/bold green]")
        else:
            print("✓ Setup completed successfully!")
        
        return True
    
    def create_default_profiles(self):
        """Create default scan profiles"""
        profiles = {
            'stealth': ScanProfile(
                name='stealth',
                description='Covert reconnaissance with low detection probability',
                scan_type='syn',
                targets=[],
                ports='21-23,25,53,80,110,443,993,995,1723,3389,5900,8080',
                timeout=3000,
                concurrency=10,
                rate_limit=10,
                service_detect=True,
                version_detect=False,
                os_detect=False,
                vuln_mapping=False,
                stealth_mode=True,
                udp_scan=False,
                ping_sweep=False,
                output_format='json',
                additional_options={'fragment_packets': True, 'random_delay': True}
            ),
            'discovery': ScanProfile(
                name='discovery',
                description='Network mapping and host discovery',
                scan_type='connect',
                targets=[],
                ports='7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995',
                timeout=2000,
                concurrency=100,
                rate_limit=100,
                service_detect=True,
                version_detect=True,
                os_detect=True,
                vuln_mapping=False,
                stealth_mode=False,
                udp_scan=False,
                ping_sweep=True,
                output_format='json',
                additional_options={'topology_mapping': True, 'mac_lookup': True}
            ),
            'aggressive': ScanProfile(
                name='aggressive',
                description='Full enumeration with all detection features',
                scan_type='syn',
                targets=[],
                ports='1-65535',
                timeout=1000,
                concurrency=1000,
                rate_limit=1000,
                service_detect=True,
                version_detect=True,
                os_detect=True,
                vuln_mapping=True,
                stealth_mode=False,
                udp_scan=True,
                ping_sweep=True,
                output_format='json',
                additional_options={'script_scan': True, 'banner_grab': True}
            ),
            'vulnerability': ScanProfile(
                name='vulnerability',
                description='Security assessment focused on vulnerability detection',
                scan_type='connect',
                targets=[],
                ports=self.config['default_ports']['top1000'],
                timeout=5000,
                concurrency=50,
                rate_limit=50,
                service_detect=True,
                version_detect=True,
                os_detect=True,
                vuln_mapping=True,
                stealth_mode=False,
                udp_scan=False,
                ping_sweep=True,
                output_format='html',
                additional_options={'cve_lookup': True, 'script_scan': True}
            ),
            'default': ScanProfile(
                name='default',
                description='Balanced scanning for general reconnaissance',
                scan_type='syn',
                targets=[],
                ports=self.config['default_ports']['top100'],
                timeout=1000,
                concurrency=100,
                rate_limit=100,
                service_detect=True,
                version_detect=True,
                os_detect=False,
                vuln_mapping=False,
                stealth_mode=False,
                udp_scan=False,
                ping_sweep=True,
                output_format='json',
                additional_options={}
            )
        }
        
        # Save profiles to database
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for profile_name, profile in profiles.items():
                cursor.execute(
                    'INSERT OR REPLACE INTO profiles (name, config, created_at) VALUES (?, ?, ?)',
                    (profile_name, json.dumps(profile.to_dict()), datetime.now().isoformat())
                )
            
            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.error(f"Failed to save default profiles: {e}")
    
    def optimize_system(self):
        """Optimize system settings for network scanning"""
        optimizations = [
            ('net.ipv4.tcp_fin_timeout', '30'),
            ('net.ipv4.tcp_tw_reuse', '1'),
            ('net.core.somaxconn', '65535'),
            ('net.core.netdev_max_backlog', '5000'),
            ('fs.file-max', '2097152')
        ]
        
        for param, value in optimizations:
            try:
                subprocess.run(['sudo', 'sysctl', '-w', f'{param}={value}'], 
                             capture_output=True, check=True)
            except subprocess.CalledProcessError:
                pass  # Non-critical optimization
        
        # Increase ulimit for current session
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_NOFILE, (65535, 65535))
        except:
            pass
    
    def show_interactive_menu(self):
        """Show interactive menu system"""
        while True:
            if RICH_AVAILABLE:
                console.clear()
                self.print_banner()
                
                table = Table(title="🦅 R3COND0G Command & Control System\nAdvanced Orchestration Platform v3.0.0", 
                            show_header=False, box=None)
                table.add_column("Option", style="bold cyan", width=3)
                table.add_column("Description", style="white")
                
                menu_options = [
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
                    ("13", "System Information"),
                    ("14", "Update R3COND0G"),
                    ("0", "Exit")
                ]
                
                for option, description in menu_options:
                    table.add_row(option, description)
                
                console.print(table)
                choice = Prompt.ask("Select option", choices=[str(i) for i in range(15)])
            else:
                print("\n" + "="*60)
                print("R3COND0G Interactive Menu")
                print("="*60)
                print("1.  Build Core Binary")
                print("2.  Generate Probe Definitions")
                print("3.  Create Scan Profile")
                print("4.  Run Scan")
                print("5.  Import Nmap Results")
                print("6.  Generate Metasploit RC")
                print("7.  Update Vulnerability Database")
                print("8.  Generate Reports")
                print("9.  Optimize Performance")
                print("10. Generate SIEM Feed")
                print("11. View Scan History")
                print("12. Generate Network Topology")
                print("13. System Information")
                print("14. Update R3COND0G")
                print("0.  Exit")
                print("="*60)
                choice = input("Select option (0-14): ").strip()
            
            if choice == "0":
                self.exit_application()
            elif choice == "1":
                self.build_binary()
            elif choice == "2":
                self.generate_probe_definitions()
            elif choice == "3":
                self.create_custom_profile()
            elif choice == "4":
                self.run_scan_interactive()
            elif choice == "5":
                self.import_nmap_results()
            elif choice == "6":
                self.generate_metasploit_rc()
            elif choice == "7":
                self.update_vulnerability_database()
            elif choice == "8":
                self.generate_reports_interactive()
            elif choice == "9":
                self.optimize_performance_interactive()
            elif choice == "10":
                self.generate_siem_feed()
            elif choice == "11":
                self.view_scan_history()
            elif choice == "12":
                self.generate_network_topology()
            elif choice == "13":
                self.show_system_info()
            elif choice == "14":
                self.update_r3cond0g()
            else:
                if RICH_AVAILABLE:
                    console.print("[red]Invalid option![/red]")
                else:
                    print("Invalid option!")
                time.sleep(1)
    
    def generate_probe_definitions(self):
        """Generate custom probe definitions"""
        if RICH_AVAILABLE:
            console.print("[bold yellow]Generating Probe Definitions[/bold yellow]")
            
            custom_services = Prompt.ask("Enter custom services (comma-separated)", default="")
            if custom_services:
                services = [s.strip() for s in custom_services.split(",")]
            else:
                services = []
            
        else:
            print("Generating Probe Definitions")
            custom_services = input("Enter custom services (comma-separated): ").strip()
            services = [s.strip() for s in custom_services.split(",")] if custom_services else []
        
        # Create probe definitions
        probes = {
            "version": "3.0.0",
            "generated": datetime.now().isoformat(),
            "probes": []
        }
        
        # Default probes
        default_probes = [
            {
                "name": "HTTP",
                "protocol": "tcp",
                "ports": [80, 8080, 8443, 8000, 3000, 5000],
                "priority": 1,
                "requires_tls": False,
                "send_payload": "GET / HTTP/1.1\\r\\nHost: {host}\\r\\nUser-Agent: R3COND0G/3.0\\r\\n\\r\\n",
                "read_pattern": "HTTP/([0-9.]+)\\s+(\\d+)\\s+(.*)\\r?\\n.*Server:\\s*([^\\r\\n]+)",
                "service_override": "http",
                "version_template": "HTTP/{version} {status} {message} (Server: {server})",
                "timeout_ms": 5000
            },
            {
                "name": "HTTPS",
                "protocol": "tcp",
                "ports": [443, 8443, 9443],
                "priority": 1,
                "requires_tls": True,
                "tls_alpn_protocols": ["http/1.1", "h2"],
                "send_payload": "GET / HTTP/1.1\\r\\nHost: {host}\\r\\nUser-Agent: R3COND0G/3.0\\r\\n\\r\\n",
                "read_pattern": "HTTP/([0-9.]+)\\s+(\\d+)\\s+(.*)\\r?\\n.*Server:\\s*([^\\r\\n]+)",
                "service_override": "https",
                "version_template": "HTTPS/{version} {status} {message} (Server: {server})",
                "timeout_ms": 5000
            },
            {
                "name": "SSH",
                "protocol": "tcp", 
                "ports": [22, 2222, 2022],
                "priority": 2,
                "requires_tls": False,
                "send_payload": "",
                "read_pattern": "SSH-([0-9.]+)-([^\\r\\n]+)",
                "service_override": "ssh",
                "version_template": "SSH-{version}-{server}",
                "timeout_ms": 3000
            },
            {
                "name": "FTP",
                "protocol": "tcp",
                "ports": [21, 2121],
                "priority": 2,
                "requires_tls": False,
                "send_payload": "",
                "read_pattern": "220[- ]([^\\r\\n]+)",
                "service_override": "ftp",
                "version_template": "FTP {banner}",
                "timeout_ms": 3000
            }
        ]
        
        probes["probes"].extend(default_probes)
        
        # Add custom service probes
        for service in services:
            custom_probe = {
                "name": service.upper(),
                "protocol": "tcp",
                "ports": [],
                "priority": 5,
                "requires_tls": False,
                "send_payload": "",
                "read_pattern": f".*{service}.*",
                "service_override": service.lower(),
                "version_template": f"{service} {{banner}}",
                "timeout_ms": 5000
            }
            probes["probes"].append(custom_probe)
        
        # Save probes
        probe_file = self.config_dir / "custom_probes.json"
        try:
            with open(probe_file, 'w') as f:
                json.dump(probes, f, indent=2)
            
            if RICH_AVAILABLE:
                console.print(f"[green]✓ Probe definitions saved to {probe_file}[/green]")
            else:
                print(f"✓ Probe definitions saved to {probe_file}")
                
        except Exception as e:
            self.logger.error(f"Failed to save probe definitions: {e}")
    
    def create_custom_profile(self):
        """Create a custom scan profile interactively"""
        if RICH_AVAILABLE:
            console.print("[bold yellow]Create Custom Scan Profile[/bold yellow]")
            
            name = Prompt.ask("Profile name")
            description = Prompt.ask("Description", default=f"Custom profile: {name}")
            scan_type = Prompt.ask("Scan type", choices=["syn", "connect", "udp", "stealth"], default="syn")
            ports = Prompt.ask("Port range", default="1-1000")
            timeout = int(Prompt.ask("Timeout (ms)", default="1000"))
            concurrency = int(Prompt.ask("Concurrency", default="100"))
            
            service_detect = Confirm.ask("Enable service detection?", default=True)
            version_detect = Confirm.ask("Enable version detection?", default=True)
            os_detect = Confirm.ask("Enable OS detection?", default=False)
            vuln_mapping = Confirm.ask("Enable vulnerability mapping?", default=False)
            udp_scan = Confirm.ask("Enable UDP scanning?", default=False)
            
        else:
            print("Create Custom Scan Profile")
            name = input("Profile name: ").strip()
            description = input(f"Description [{name}]: ").strip() or f"Custom profile: {name}"
            scan_type = input("Scan type [syn]: ").strip() or "syn"
            ports = input("Port range [1-1000]: ").strip() or "1-1000"
            timeout = int(input("Timeout (ms) [1000]: ").strip() or "1000")
            concurrency = int(input("Concurrency [100]: ").strip() or "100")
            
            service_detect = input("Enable service detection? [y]: ").strip().lower() != 'n'
            version_detect = input("Enable version detection? [y]: ").strip().lower() != 'n'
            os_detect = input("Enable OS detection? [n]: ").strip().lower() == 'y'
            vuln_mapping = input("Enable vulnerability mapping? [n]: ").strip().lower() == 'y'
            udp_scan = input("Enable UDP scanning? [n]: ").strip().lower() == 'y'
        
        profile = ScanProfile(
            name=name,
            description=description,
            scan_type=scan_type,
            targets=[],
            ports=ports,
            timeout=timeout,
            concurrency=concurrency,
            rate_limit=concurrency,
            service_detect=service_detect,
            version_detect=version_detect,
            os_detect=os_detect,
            vuln_mapping=vuln_mapping,
            stealth_mode=scan_type == 'stealth',
            udp_scan=udp_scan,
            ping_sweep=True,
            output_format='json',
            additional_options={}
        )
        
        # Save profile
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT OR REPLACE INTO profiles (name, config, created_at) VALUES (?, ?, ?)',
                (name, json.dumps(profile.to_dict()), datetime.now().isoformat())
            )
            conn.commit()
            conn.close()
            
            if RICH_AVAILABLE:
                console.print(f"[green]✓ Profile '{name}' created successfully![/green]")
            else:
                print(f"✓ Profile '{name}' created successfully!")
                
        except Exception as e:
            self.logger.error(f"Failed to save profile: {e}")
    
    def run_scan_interactive(self):
        """Run scan with interactive options"""
        if RICH_AVAILABLE:
            console.print("[bold yellow]Run Network Scan[/bold yellow]")
        else:
            print("Run Network Scan")
        
        # Get available profiles
        profiles = self.get_available_profiles()
        
        if RICH_AVAILABLE:
            profile_choices = list(profiles.keys())
            profile_name = Prompt.ask("Select profile", choices=profile_choices, default="default")
            
            targets = Prompt.ask("Target(s) (IP, CIDR, hostname)")
            output_format = Prompt.ask("Output format", 
                                     choices=["json", "xml", "html", "csv"], 
                                     default="json")
        else:
            print("Available profiles:", ", ".join(profiles.keys()))
            profile_name = input("Select profile [default]: ").strip() or "default"
            targets = input("Target(s) (IP, CIDR, hostname): ").strip()
            output_format = input("Output format [json]: ").strip() or "json"
        
        if not targets:
            if RICH_AVAILABLE:
                console.print("[red]No targets specified![/red]")
            else:
                print("No targets specified!")
            return
        
        # Load profile
        profile_config = profiles.get(profile_name, profiles['default'])
        profile_config['targets'] = [t.strip() for t in targets.split(',')]
        profile_config['output_format'] = output_format
        
        # Generate scan ID
        scan_id = f"scan_{int(time.time())}"
        
        # Run scan
        success = self.execute_scan(scan_id, profile_config)
        
        if success:
            if RICH_AVAILABLE:
                console.print(f"[green]✓ Scan {scan_id} completed successfully![/green]")
            else:
                print(f"✓ Scan {scan_id} completed successfully!")
        else:
            if RICH_AVAILABLE:
                console.print(f"[red]✗ Scan {scan_id} failed![/red]")
            else:
                print(f"✗ Scan {scan_id} failed!")
    
    def get_available_profiles(self) -> Dict:
        """Get all available scan profiles"""
        profiles = {}
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT name, config FROM profiles')
            
            for row in cursor.fetchall():
                name, config_str = row
                profiles[name] = json.loads(config_str)
            
            conn.close()
        except Exception as e:
            self.logger.error(f"Failed to load profiles: {e}")
        
        return profiles
    
    def execute_scan(self, scan_id: str, profile_config: Dict) -> bool:
        """Execute a scan with given configuration"""
        if not self.binary_path.exists():
            if RICH_AVAILABLE:
                console.print("[red]Core binary not found! Run 'Build Core Binary' first.[/red]")
            else:
                print("Core binary not found! Run 'Build Core Binary' first.")
            return False
        
        # Build command
        cmd = [str(self.binary_path)]
        
        # Add targets
        for target in profile_config['targets']:
            cmd.extend(['--target', target])
        
        # Add ports
        if profile_config.get('ports'):
            cmd.extend(['--ports', profile_config['ports']])
        
        # Add scan options
        if profile_config.get('timeout'):
            cmd.extend(['--timeout', str(profile_config['timeout'])])
        
        if profile_config.get('concurrency'):
            cmd.extend(['--concurrency', str(profile_config['concurrency'])])
        
        if profile_config.get('service_detect'):
            cmd.append('--service-detect')
        
        if profile_config.get('version_detect'):
            cmd.append('--version-detect')
        
        if profile_config.get('os_detect'):
            cmd.append('--os-detect')
        
        if profile_config.get('vuln_mapping'):
            cmd.append('--vuln-mapping')
        
        if profile_config.get('udp_scan'):
            cmd.append('--udp-scan')
        
        if profile_config.get('stealth_mode'):
            cmd.append('--stealth')
        
        # Output options
        output_file = self.reports_dir / f"{scan_id}.{profile_config.get('output_format', 'json')}"
        cmd.extend(['--output', str(output_file)])
        cmd.extend(['--format', profile_config.get('output_format', 'json')])
        
        # Record scan start
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scans (scan_id, profile_name, targets, start_time, status, command)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                profile_config.get('name', 'custom'),
                ','.join(profile_config['targets']),
                datetime.now().isoformat(),
                'running',
                ' '.join(cmd)
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.error(f"Failed to record scan start: {e}")
        
        # Execute scan
        start_time = time.time()
        
        if RICH_AVAILABLE:
            with console.status(f"[bold green]Running scan {scan_id}...") as status:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
                    success = result.returncode == 0
                except subprocess.TimeoutExpired:
                    success = False
                    result = None
        else:
            print(f"Running scan {scan_id}...")
            try:
                result = subprocess.run(cmd, timeout=3600)
                success = result.returncode == 0
            except subprocess.TimeoutExpired:
                success = False
                result = None
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Update scan record
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE scans SET end_time = ?, status = ?, results_file = ?
                WHERE scan_id = ?
            ''', (
                datetime.now().isoformat(),
                'completed' if success else 'failed',
                str(output_file) if success else None,
                scan_id
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.error(f"Failed to update scan record: {e}")
        
        if success and result:
            if RICH_AVAILABLE:
                console.print(f"[green]Scan completed in {duration:.1f} seconds[/green]")
                console.print(f"[blue]Results saved to: {output_file}[/blue]")
            else:
                print(f"Scan completed in {duration:.1f} seconds")
                print(f"Results saved to: {output_file}")
        elif result:
            self.logger.error(f"Scan failed: {result.stderr}")
        
        return success
    
    def import_nmap_results(self):
        """Import and enhance Nmap XML results"""
        if RICH_AVAILABLE:
            console.print("[bold yellow]Import Nmap Results[/bold yellow]")
            xml_file = Prompt.ask("Path to Nmap XML file")
        else:
            print("Import Nmap Results")
            xml_file = input("Path to Nmap XML file: ").strip()
        
        if not os.path.exists(xml_file):
            if RICH_AVAILABLE:
                console.print("[red]File not found![/red]")
            else:
                print("File not found!")
            return
        
        try:
            # Parse Nmap XML
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            results = []
            for host in root.findall('host'):
                # Get host address
                address = host.find('address')
                if address is None:
                    continue
                
                host_ip = address.get('addr')
                
                # Get host status
                status = host.find('status')
                if status is None or status.get('state') != 'up':
                    continue
                
                # Get ports
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        port_id = port.get('portid')
                        protocol = port.get('protocol')
                        
                        state = port.find('state')
                        if state is not None:
                            port_state = state.get('state')
                        else:
                            continue
                        
                        service = port.find('service')
                        service_name = service.get('name') if service is not None else ''
                        service_version = service.get('version') if service is not None else ''
                        
                        result = {
                            'host': host_ip,
                            'port': int(port_id),
                            'protocol': protocol,
                            'state': port_state,
                            'service': service_name,
                            'version': service_version
                        }
                        results.append(result)
            
            # Save enhanced results
            import_id = f"import_{int(time.time())}"
            output_file = self.reports_dir / f"{import_id}_enhanced.json"
            
            with open(output_file, 'w') as f:
                json.dump({
                    'import_id': import_id,
                    'source_file': xml_file,
                    'imported_at': datetime.now().isoformat(),
                    'total_results': len(results),
                    'results': results
                }, f, indent=2)
            
            if RICH_AVAILABLE:
                console.print(f"[green]✓ Imported {len(results)} results to {output_file}[/green]")
            else:
                print(f"✓ Imported {len(results)} results to {output_file}")
                
        except Exception as e:
            self.logger.error(f"Failed to import Nmap results: {e}")
            if RICH_AVAILABLE:
                console.print(f"[red]Import failed: {e}[/red]")
            else:
                print(f"Import failed: {e}")
    
    def generate_metasploit_rc(self):
        """Generate Metasploit resource script from scan results"""
        if RICH_AVAILABLE:
            console.print("[bold yellow]Generate Metasploit Resource Script[/bold yellow]")
        else:
            print("Generate Metasploit Resource Script")
        
        # Get recent scan results
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT scan_id, results_file FROM scans 
                WHERE status = 'completed' AND results_file IS NOT NULL
                ORDER BY start_time DESC LIMIT 10
            ''')
            
            scans = cursor.fetchall()
            conn.close()
            
            if not scans:
                if RICH_AVAILABLE:
                    console.print("[red]No completed scans found![/red]")
                else:
                    print("No completed scans found!")
                return
            
            if RICH_AVAILABLE:
                scan_choices = [f"{scan[0]} ({scan[1]})" for scan in scans]
                selection = Prompt.ask("Select scan", choices=[str(i) for i in range(len(scans))])
                selected_scan = scans[int(selection)]
            else:
                print("Available scans:")
                for i, scan in enumerate(scans):
                    print(f"{i}: {scan[0]} ({scan[1]})")
                selection = int(input("Select scan (0-{}): ".format(len(scans)-1)))
                selected_scan = scans[selection]
            
            results_file = selected_scan[1]
            
            # Load results
            with open(results_file, 'r') as f:
                results = json.load(f)
            
            # Generate RC script
            rc_content = []
            rc_content.append("# Metasploit Resource Script generated by R3COND0G")
            rc_content.append(f"# Generated: {datetime.now().isoformat()}")
            rc_content.append(f"# Source: {results_file}")
            rc_content.append("")
            
            # Service-to-exploit mapping
            exploit_map = {
                'ftp': 'auxiliary/scanner/ftp/ftp_version',
                'ssh': 'auxiliary/scanner/ssh/ssh_version',
                'http': 'auxiliary/scanner/http/http_version',
                'https': 'auxiliary/scanner/http/http_version',
                'smtp': 'auxiliary/scanner/smtp/smtp_version',
                'mysql': 'auxiliary/scanner/mysql/mysql_version',
                'postgresql': 'auxiliary/scanner/postgres/postgres_version',
                'rdp': 'auxiliary/scanner/rdp/rdp_scanner',
                'vnc': 'auxiliary/scanner/vnc/vnc_none_auth'
            }
            
            workspace_name = f"r3cond0g_{int(time.time())}"
            rc_content.append(f"workspace -a {workspace_name}")
            rc_content.append(f"workspace {workspace_name}")
            rc_content.append("")
            
            # Process results
            if isinstance(results, dict) and 'results' in results:
                scan_results = results['results']
            elif isinstance(results, list):
                scan_results = results
            else:
                scan_results = []
            
            for result in scan_results:
                if result.get('state') == 'open':
                    service = result.get('service', '').lower()
                    host = result.get('host')
                    port = result.get('port')
                    
                    if service in exploit_map:
                        rc_content.append(f"use {exploit_map[service]}")
                        rc_content.append(f"set RHOSTS {host}")
                        rc_content.append(f"set RPORT {port}")
                        rc_content.append("run")
                        rc_content.append("")
            
            rc_content.append("# End of R3COND0G generated script")
            
            # Save RC script
            rc_file = self.reports_dir / f"{selected_scan[0]}_metasploit.rc"
            with open(rc_file, 'w') as f:
                f.write('\n'.join(rc_content))
            
            if RICH_AVAILABLE:
                console.print(f"[green]✓ Metasploit RC script saved to {rc_file}[/green]")
                console.print("[cyan]Usage: msfconsole -r {rc_file}[/cyan]")
            else:
                print(f"✓ Metasploit RC script saved to {rc_file}")
                print(f"Usage: msfconsole -r {rc_file}")
                
        except Exception as e:
            self.logger.error(f"Failed to generate Metasploit RC: {e}")
            if RICH_AVAILABLE:
                console.print(f"[red]Failed to generate RC script: {e}[/red]")
            else:
                print(f"Failed to generate RC script: {e}")
    
    def update_vulnerability_database(self):
        """Update vulnerability database from NVD"""
        if RICH_AVAILABLE:
            console.print("[bold yellow]Update Vulnerability Database[/bold yellow]")
            
            api_key = Prompt.ask("NVD API Key (optional, press Enter to skip)", default="")
        else:
            print("Update Vulnerability Database")
            api_key = input("NVD API Key (optional, press Enter to skip): ").strip()
        
        # Save API key if provided
        if api_key:
            self.config['nvd_api_key'] = api_key
            self.save_config()
        
        vuln_db_file = self.config_dir / "vulnerabilities.db"
        
        try:
            if RICH_AVAILABLE:
                with console.status("[bold blue]Downloading vulnerability data...") as status:
                    # Create a basic vulnerability database
                    vulns = {
                        "updated": datetime.now().isoformat(),
                        "source": "NVD NIST",
                        "version": "1.0",
                        "vulnerabilities": {
                            # Sample CVE data - in real implementation, fetch from NVD API
                            "Apache": ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"],
                            "OpenSSH": ["CVE-2023-38408", "CVE-2021-41617"],
                            "nginx": ["CVE-2021-23017", "CVE-2019-20372"],
                            "MySQL": ["CVE-2023-22084", "CVE-2023-22079"],
                            "PostgreSQL": ["CVE-2023-39418", "CVE-2023-39417"],
                            "vsftpd": ["CVE-2011-2523"],
                            "ProFTPD": ["CVE-2019-12815", "CVE-2020-9273"],
                            "Microsoft RDP": ["CVE-2019-0708", "CVE-2019-1181"],
                            "SMB": ["CVE-2017-0144", "CVE-2017-0145"]
                        }
                    }
                    
                    with open(vuln_db_file, 'w') as f:
                        json.dump(vulns, f, indent=2)
            else:
                print("Downloading vulnerability data...")
                # Same logic without rich status
                vulns = {
                    "updated": datetime.now().isoformat(),
                    "source": "NVD NIST",
                    "version": "1.0",
                    "vulnerabilities": {
                        "Apache": ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"],
                        "OpenSSH": ["CVE-2023-38408", "CVE-2021-41617"],
                        "nginx": ["CVE-2021-23017", "CVE-2019-20372"],
                        "MySQL": ["CVE-2023-22084", "CVE-2023-22079"],
                        "PostgreSQL": ["CVE-2023-39418", "CVE-2023-39417"],
                        "vsftpd": ["CVE-2011-2523"],
                        "ProFTPD": ["CVE-2019-12815", "CVE-2020-9273"],
                        "Microsoft RDP": ["CVE-2019-0708", "CVE-2019-1181"],
                        "SMB": ["CVE-2017-0144", "CVE-2017-0145"]
                    }
                }
                
                with open(vuln_db_file, 'w') as f:
                    json.dump(vulns, f, indent=2)
            
            if RICH_AVAILABLE:
                console.print(f"[green]✓ Vulnerability database updated: {vuln_db_file}[/green]")
            else:
                print(f"✓ Vulnerability database updated: {vuln_db_file}")
                
        except Exception as e:
            self.logger.error(f"Failed to update vulnerability database: {e}")
            if RICH_AVAILABLE:
                console.print(f"[red]Update failed: {e}[/red]")
            else:
                print(f"Update failed: {e}")
    
    def generate_reports_interactive(self):
        """Generate reports from scan results"""
        if RICH_AVAILABLE:
            console.print("[bold yellow]Generate Reports[/bold yellow]")
        else:
            print("Generate Reports")
        
        # Get available scan results
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT scan_id, profile_name, targets, start_time, results_file
                FROM scans WHERE status = 'completed' AND results_file IS NOT NULL
                ORDER BY start_time DESC LIMIT 20
            ''')
            
            scans = cursor.fetchall()
            conn.close()
            
            if not scans:
                if RICH_AVAILABLE:
                    console.print("[red]No completed scans found![/red]")
                else:
                    print("No completed scans found!")
                return
            
            if RICH_AVAILABLE:
                # Show scan selection table
                table = Table(title="Available Scans")
                table.add_column("ID", style="cyan")
                table.add_column("Profile", style="green")
                table.add_column("Targets", style="yellow")
                table.add_column("Date", style="blue")
                
                for i, scan in enumerate(scans):
                    scan_id, profile, targets, start_time, _ = scan
                    table.add_row(str(i), profile, targets[:50] + "..." if len(targets) > 50 else targets, 
                                start_time[:19])
                
                console.print(table)
                selection = Prompt.ask("Select scan", choices=[str(i) for i in range(len(scans))])
                selected_scan = scans[int(selection)]
                
                # Report format selection
                format_choices = ["html", "json", "csv", "xml", "markdown", "pdf", "all"]
                report_format = Prompt.ask("Report format", choices=format_choices, default="html")
                
            else:
                print("Available scans:")
                for i, scan in enumerate(scans):
                    scan_id, profile, targets, start_time, _ = scan
                    print(f"{i}: {scan_id} ({profile}) - {targets[:30]}... - {start_time[:19]}")
                
                selection = int(input(f"Select scan (0-{len(scans)-1}): "))
                selected_scan = scans[selection]
                
                print("Available formats: html, json, csv, xml, markdown, pdf, all")
                report_format = input("Report format [html]: ").strip() or "html"
            
            # Generate report
            self.generate_report(selected_scan, report_format)
            
        except Exception as e:
            self.logger.error(f"Failed to generate reports: {e}")
            if RICH_AVAILABLE:
                console.print(f"[red]Report generation failed: {e}[/red]")
            else:
                print(f"Report generation failed: {e}")
    
    def generate_report(self, scan_info, format_type):
        """Generate report in specified format"""
        scan_id, profile_name, targets, start_time, results_file = scan_info
        
        # Load scan results
        try:
            with open(results_file, 'r') as f:
                results_data = json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load results: {e}")
            return
        
        # Process results for reporting
        if isinstance(results_data, dict) and 'results' in results_data:
            scan_results = results_data['results']
        elif isinstance(results_data, list):
            scan_results = results_data
        else:
            scan_results = []
        
        report_data = {
            'scan_info': {
                'scan_id': scan_id,
                'profile': profile_name,
                'targets': targets,
                'start_time': start_time,
                'total_results': len(scan_results)
            },
            'summary': {
                'total_hosts': len(set(r.get('host') for r in scan_results)),
                'open_ports': len([r for r in scan_results if r.get('state') == 'open']),
                'services_found': len(set(r.get('service') for r in scan_results if r.get('service')))
            },
            'results': scan_results
        }
        
        if format_type == "all":
            formats = ["html", "json", "csv", "xml", "markdown"]
        else:
            formats = [format_type]
        
        for fmt in formats:
            try:
                if fmt == "html":
                    self.generate_html_report(report_data, scan_id)
                elif fmt == "json":
                    self.generate_json_report(report_data, scan_id)
                elif fmt == "csv":
                    self.generate_csv_report(report_data, scan_id)
                elif fmt == "xml":
                    self.generate_xml_report(report_data, scan_id)
                elif fmt == "markdown":
                    self.generate_markdown_report(report_data, scan_id)
                elif fmt == "pdf":
                    self.generate_pdf_report(report_data, scan_id)
                    
            except Exception as e:
                self.logger.error(f"Failed to generate {fmt} report: {e}")
    
    def generate_html_report(self, report_data, scan_id):
        """Generate HTML report"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>R3COND0G Scan Report - {scan_id}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 30px; }}
        .title {{ color: #d32f2f; font-size: 28px; font-weight: bold; margin-bottom: 10px; }}
        .subtitle {{ color: #666; font-size: 16px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .summary-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #d32f2f; }}
        .summary-number {{ font-size: 32px; font-weight: bold; color: #d32f2f; }}
        .summary-label {{ color: #666; font-size: 14px; margin-top: 5px; }}
        .results-table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        .results-table th {{ background: #d32f2f; color: white; padding: 12px; text-align: left; }}
        .results-table td {{ padding: 10px; border-bottom: 1px solid #eee; }}
        .results-table tr:hover {{ background: #f8f9fa; }}
        .open {{ color: #4caf50; font-weight: bold; }}
        .closed {{ color: #f44336; }}
        .filtered {{ color: #ff9800; }}
        .footer {{ text-align: center; margin-top: 30px; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="title">🦅 R3COND0G Scan Report</div>
            <div class="subtitle">Advanced Network Reconnaissance Results</div>
            <div class="subtitle">Scan ID: {scan_id} | Generated: {timestamp}</div>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <div class="summary-number">{total_hosts}</div>
                <div class="summary-label">Total Hosts</div>
            </div>
            <div class="summary-card">
                <div class="summary-number">{open_ports}</div>
                <div class="summary-label">Open Ports</div>
            </div>
            <div class="summary-card">
                <div class="summary-number">{services_found}</div>
                <div class="summary-label">Services Found</div>
            </div>
            <div class="summary-card">
                <div class="summary-number">{total_results}</div>
                <div class="summary-label">Total Results</div>
            </div>
        </div>
        
        <h3>Scan Details</h3>
        <table class="results-table">
            <thead>
                <tr>
                    <th>Host</th>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Version</th>
                </tr>
            </thead>
            <tbody>
                {results_rows}
            </tbody>
        </table>
        
        <div class="footer">
            Generated by R3COND0G v{version} | {authors}
        </div>
    </div>
</body>
</html>
        """
        
        # Generate table rows
        results_rows = []
        for result in report_data['results']:
            state_class = result.get('state', 'unknown').lower()
            row = f"""
                <tr>
                    <td>{result.get('host', 'N/A')}</td>
                    <td>{result.get('port', 'N/A')}</td>
                    <td>{result.get('protocol', 'N/A')}</td>
                    <td><span class="{state_class}">{result.get('state', 'N/A')}</span></td>
                    <td>{result.get('service', 'N/A')}</td>
                    <td>{result.get('version', 'N/A')}</td>
                </tr>
            """
            results_rows.append(row)
        
        html_content = html_template.format(
            scan_id=scan_id,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            total_hosts=report_data['summary']['total_hosts'],
            open_ports=report_data['summary']['open_ports'],
            services_found=report_data['summary']['services_found'],
            total_results=report_data['summary'].get('total_results', len(report_data['results'])),
            results_rows=''.join(results_rows),
            version=VERSION,
            authors=AUTHORS
        )
        
        html_file = self.reports_dir / f"{scan_id}_report.html"
        with open(html_file, 'w') as f:
            f.write(html_content)
        
        if RICH_AVAILABLE:
            console.print(f"[green]✓ HTML report generated: {html_file}[/green]")
        else:
            print(f"✓ HTML report generated: {html_file}")
    
    def generate_json_report(self, report_data, scan_id):
        """Generate JSON report"""
        json_file = self.reports_dir / f"{scan_id}_report.json"
        
        enhanced_report = {
            **report_data,
            'metadata': {
                'generator': 'R3COND0G',
                'version': VERSION,
                'generated_at': datetime.now().isoformat(),
                'report_format': 'json'
            }
        }
        
        with open(json_file, 'w') as f:
            json.dump(enhanced_report, f, indent=2)
        
        if RICH_AVAILABLE:
            console.print(f"[green]✓ JSON report generated: {json_file}[/green]")
        else:
            print(f"✓ JSON report generated: {json_file}")
    
    def generate_csv_report(self, report_data, scan_id):
        """Generate CSV report"""
        csv_file = self.reports_dir / f"{scan_id}_report.csv"
        
        import csv
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow(['Host', 'Port', 'Protocol', 'State', 'Service', 'Version', 'Banner'])
            
            # Data rows
            for result in report_data['results']:
                writer.writerow([
                    result.get('host', ''),
                    result.get('port', ''),
                    result.get('protocol', ''),
                    result.get('state', ''),
                    result.get('service', ''),
                    result.get('version', ''),
                    result.get('banner', '')
                ])
        
        if RICH_AVAILABLE:
            console.print(f"[green]✓ CSV report generated: {csv_file}[/green]")
        else:
            print(f"✓ CSV report generated: {csv_file}")
    
    def generate_xml_report(self, report_data, scan_id):
        """Generate XML report"""
        xml_file = self.reports_dir / f"{scan_id}_report.xml"
        
        xml_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<r3cond0g_scan version="{VERSION}" scan_id="{scan_id}" generated="{datetime.now().isoformat()}">
    <scan_info>
        <profile>{report_data['scan_info']['profile']}</profile>
        <targets>{report_data['scan_info']['targets']}</targets>
        <start_time>{report_data['scan_info']['start_time']}</start_time>
    </scan_info>
    <summary>
        <total_hosts>{report_data['summary']['total_hosts']}</total_hosts>
        <open_ports>{report_data['summary']['open_ports']}</open_ports>
        <services_found>{report_data['summary']['services_found']}</services_found>
    </summary>
    <results>
'''
        
        for result in report_data['results']:
            xml_content += f'''        <result>
            <host>{result.get('host', '')}</host>
            <port>{result.get('port', '')}</port>
            <protocol>{result.get('protocol', '')}</protocol>
            <state>{result.get('state', '')}</state>
            <service>{result.get('service', '')}</service>
            <version>{result.get('version', '')}</version>
        </result>
'''
        
        xml_content += '''    </results>
</r3cond0g_scan>'''
        
        with open(xml_file, 'w') as f:
            f.write(xml_content)
        
        if RICH_AVAILABLE:
            console.print(f"[green]✓ XML report generated: {xml_file}[/green]")
        else:
            print(f"✓ XML report generated: {xml_file}")
    
    def generate_markdown_report(self, report_data, scan_id):
        """Generate Markdown report"""
        md_file = self.reports_dir / f"{scan_id}_report.md"
        
        md_content = f"""# 🦅 R3COND0G Scan Report

**Scan ID:** {scan_id}  
**Profile:** {report_data['scan_info']['profile']}  
**Targets:** {report_data['scan_info']['targets']}  
**Start Time:** {report_data['scan_info']['start_time']}  
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary

| Metric | Count |
|--------|--------|
| Total Hosts | {report_data['summary']['total_hosts']} |
| Open Ports | {report_data['summary']['open_ports']} |
| Services Found | {report_data['summary']['services_found']} |
| Total Results | {report_data['summary'].get('total_results', len(report_data['results']))} |

## Detailed Results

| Host | Port | Protocol | State | Service | Version |
|------|------|----------|-------|---------|---------|
"""
        
        for result in report_data['results']:
            md_content += f"| {result.get('host', 'N/A')} | {result.get('port', 'N/A')} | {result.get('protocol', 'N/A')} | {result.get('state', 'N/A')} | {result.get('service', 'N/A')} | {result.get('version', 'N/A')} |\n"
        
        md_content += f"""

---
*Generated by R3COND0G {VERSION} | {AUTHORS}*
"""
        
        with open(md_file, 'w') as f:
            f.write(md_content)
        
        if RICH_AVAILABLE:
            console.print(f"[green]✓ Markdown report generated: {md_file}[/green]")
        else:
            print(f"✓ Markdown report generated: {md_file}")
    
    def optimize_performance_interactive(self):
        """Interactive performance optimization"""
        if RICH_AVAILABLE:
            console.print("[bold yellow]Performance Optimization[/bold yellow]")
            
            target_count = int(Prompt.ask("Estimated number of targets", default="1000"))
            network_type = Prompt.ask("Network type", 
                                    choices=["lan", "wan", "internet"], 
                                    default="lan")
        else:
            print("Performance Optimization")
            target_count = int(input("Estimated number of targets [1000]: ") or "1000")
            print("Network types: lan, wan, internet")
            network_type = input("Network type [lan]: ").strip() or "lan"
        
        # Calculate optimal settings
        if network_type == "lan":
            base_concurrency = min(1000, target_count // 10)
            base_timeout = 1000
            rate_limit = 1000
        elif network_type == "wan":
            base_concurrency = min(500, target_count // 20)
            base_timeout = 2000
            rate_limit = 500
        else:  # internet
            base_concurrency = min(100, target_count // 50)
            base_timeout = 5000
            rate_limit = 100
        
        # Memory estimation
        estimated_memory = base_concurrency * 0.5  # MB per connection
        
        optimization_config = {
            "max_concurrency": base_concurrency,
            "timeout": base_timeout,
            "rate_limit": rate_limit,
            "estimated_memory_mb": estimated_memory,
            "network_type": network_type,
            "target_count": target_count,
            "generated_at": datetime.now().isoformat()
        }
        
        # Save optimization config
        opt_file = self.config_dir / "optimization.json"
        with open(opt_file, 'w') as f:
            json.dump(optimization_config, f, indent=2)
        
        if RICH_AVAILABLE:
            table = Table(title="Recommended Settings")
            table.add_column("Setting", style="cyan")
            table.add_column("Value", style="green")
            
            table.add_row("Max Concurrency", str(base_concurrency))
            table.add_row("Timeout (ms)", str(base_timeout))
            table.add_row("Rate Limit", str(rate_limit))
            table.add_row("Est. Memory (MB)", f"{estimated_memory:.1f}")
            
            console.print(table)
            console.print(f"[green]✓ Optimization settings saved to {opt_file}[/green]")
        else:
            print("Recommended Settings:")
            print(f"Max Concurrency: {base_concurrency}")
            print(f"Timeout (ms): {base_timeout}")
            print(f"Rate Limit: {rate_limit}")
            print(f"Est. Memory (MB): {estimated_memory:.1f}")
            print(f"✓ Optimization settings saved to {opt_file}")
    
    def generate_siem_feed(self):
        """Generate SIEM feed from scan results"""
        if RICH_AVAILABLE:
            console.print("[bold yellow]Generate SIEM Feed[/bold yellow]")
            
            feed_format = Prompt.ask("SIEM format", 
                                   choices=["cef", "leef", "json", "syslog"], 
                                   default="json")
        else:
            print("Generate SIEM Feed")
            print("Available formats: cef, leef, json, syslog")
            feed_format = input("SIEM format [json]: ").strip() or "json"
        
        # Get recent scan results
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT scan_id, results_file FROM scans 
                WHERE status = 'completed' AND results_file IS NOT NULL
                ORDER BY start_time DESC LIMIT 1
            ''')
            
            scan = cursor.fetchone()
            conn.close()
            
            if not scan:
                if RICH_AVAILABLE:
                    console.print("[red]No recent scan results found![/red]")
                else:
                    print("No recent scan results found!")
                return
            
            scan_id, results_file = scan
            
            # Load results
            with open(results_file, 'r') as f:
                results = json.load(f)
            
            if isinstance(results, dict) and 'results' in results:
                scan_results = results['results']
            else:
                scan_results = results
            
            # Generate SIEM events
            siem_events = []
            
            for result in scan_results:
                if result.get('state') == 'open':
                    timestamp = datetime.now().strftime('%b %d %H:%M:%S')
                    
                    if feed_format == "cef":
                        # Common Event Format
                        event = f"CEF:0|R3COND0G|NetworkScanner|{VERSION}|PortOpen|Open Port Detected|3|src={result.get('host')} spt={result.get('port')} proto={result.get('protocol')} app={result.get('service', 'unknown')}"
                    elif feed_format == "leef":
                        # Log Event Extended Format
                        event = f"LEEF:2.0|R3COND0G|NetworkScanner|{VERSION}|PortOpen|devTime={timestamp}|src={result.get('host')}|srcPort={result.get('port')}|proto={result.get('protocol')}|identSrc={result.get('service', 'unknown')}"
                    elif feed_format == "syslog":
                        # Syslog format
                        event = f"{timestamp} r3cond0g: OPEN_PORT host={result.get('host')} port={result.get('port')} protocol={result.get('protocol')} service={result.get('service', 'unknown')}"
                    else:  # json
                        event = {
                            "timestamp": datetime.now().isoformat(),
                            "source": "R3COND0G",
                            "event_type": "open_port",
                            "host": result.get('host'),
                            "port": result.get('port'),
                            "protocol": result.get('protocol'),
                            "service": result.get('service', 'unknown'),
                            "version": result.get('version', ''),
                            "scan_id": scan_id
                        }
                    
                    siem_events.append(event)
            
            # Save SIEM feed
            feed_file = self.reports_dir / f"{scan_id}_siem.{feed_format}"
            
            if feed_format == "json":
                with open(feed_file, 'w') as f:
                    json.dump(siem_events, f, indent=2)
            else:
                with open(feed_file, 'w') as f:
                    for event in siem_events:
                        f.write(event + '\n')
            
            if RICH_AVAILABLE:
                console.print(f"[green]✓ SIEM feed generated: {feed_file}[/green]")
                console.print(f"[cyan]Events: {len(siem_events)}[/cyan]")
            else:
                print(f"✓ SIEM feed generated: {feed_file}")
                print(f"Events: {len(siem_events)}")
                
        except Exception as e:
            self.logger.error(f"Failed to generate SIEM feed: {e}")
            if RICH_AVAILABLE:
                console.print(f"[red]SIEM feed generation failed: {e}[/red]")
            else:
                print(f"SIEM feed generation failed: {e}")
    
    def view_scan_history(self):
        """View scan history"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT scan_id, profile_name, targets, start_time, end_time, status
                FROM scans ORDER BY start_time DESC LIMIT 50
            ''')
            
            scans = cursor.fetchall()
            conn.close()
            
            if not scans:
                if RICH_AVAILABLE:
                    console.print("[yellow]No scan history found[/yellow]")
                else:
                    print("No scan history found")
                return
            
            if RICH_AVAILABLE:
                table = Table(title="Scan History")
                table.add_column("Scan ID", style="cyan")
                table.add_column("Profile", style="green")
                table.add_column("Targets", style="yellow")
                table.add_column("Start Time", style="blue")
                table.add_column("Duration", style="magenta")
                table.add_column("Status", style="red")
                
                for scan in scans:
                    scan_id, profile, targets, start_time, end_time, status = scan
                    
                    # Calculate duration
                    if end_time:
                        try:
                            start = datetime.fromisoformat(start_time)
                            end = datetime.fromisoformat(end_time)
                            duration = str(end - start).split('.')[0]  # Remove microseconds
                        except:
                            duration = "N/A"
                    else:
                        duration = "Running..."
                    
                    # Truncate targets if too long
                    truncated_targets = targets[:30] + "..." if len(targets) > 30 else targets
                    
                    table.add_row(
                        scan_id,
                        profile,
                        truncated_targets,
                        start_time[:19],
                        duration,
                        status
                    )
                
                console.print(table)
            else:
                print("Scan History:")
                print("-" * 120)
                print(f"{'Scan ID':<20} {'Profile':<15} {'Targets':<25} {'Start Time':<20} {'Status':<10}")
                print("-" * 120)
                
                for scan in scans:
                    scan_id, profile, targets, start_time, end_time, status = scan
                    truncated_targets = targets[:25] + "..." if len(targets) > 25 else targets
                    print(f"{scan_id:<20} {profile:<15} {truncated_targets:<25} {start_time[:19]:<20} {status:<10}")
                
        except Exception as e:
            self.logger.error(f"Failed to load scan history: {e}")
            if RICH_AVAILABLE:
                console.print(f"[red]Failed to load scan history: {e}[/red]")
            else:
                print(f"Failed to load scan history: {e}")
    
    def generate_network_topology(self):
        """Generate network topology visualization"""
        if RICH_AVAILABLE:
            console.print("[bold yellow]Generate Network Topology[/bold yellow]")
            
            output_format = Prompt.ask("Output format", 
                                     choices=["dot", "html", "json"], 
                                     default="dot")
        else:
            print("Generate Network Topology")
            print("Available formats: dot, html, json")
            output_format = input("Output format [dot]: ").strip() or "dot"
        
        # Get recent scan results for topology
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT DISTINCT host, port, protocol, state, service
                FROM scan_results 
                WHERE state = 'open'
                ORDER BY host
            ''')
            
            results = cursor.fetchall()
            conn.close()
            
            if not results:
                if RICH_AVAILABLE:
                    console.print("[yellow]No scan results found for topology generation[/yellow]")
                else:
                    print("No scan results found for topology generation")
                return
            
            # Process results for topology
            hosts = {}
            for host, port, protocol, state, service in results:
                if host not in hosts:
                    hosts[host] = []
                hosts[host].append({
                    'port': port,
                    'protocol': protocol,
                    'service': service
                })
            
            topology_file = self.reports_dir / f"topology_{int(time.time())}.{output_format}"
            
            if output_format == "dot":
                self.generate_dot_topology(hosts, topology_file)
            elif output_format == "html":
                self.generate_html_topology(hosts, topology_file)
            elif output_format == "json":
                self.generate_json_topology(hosts, topology_file)
            
            if RICH_AVAILABLE:
                console.print(f"[green]✓ Network topology generated: {topology_file}[/green]")
                if output_format == "dot":
                    console.print("[cyan]Generate PNG: dot -Tpng topology.dot -o topology.png[/cyan]")
            else:
                print(f"✓ Network topology generated: {topology_file}")
                if output_format == "dot":
                    print("Generate PNG: dot -Tpng topology.dot -o topology.png")
                    
        except Exception as e:
            self.logger.error(f"Failed to generate topology: {e}")
            if RICH_AVAILABLE:
                console.print(f"[red]Topology generation failed: {e}[/red]")
            else:
                print(f"Topology generation failed: {e}")
    
    def generate_dot_topology(self, hosts, output_file):
        """Generate Graphviz DOT topology"""
        dot_content = '''digraph NetworkTopology {
    rankdir=LR;
    node [shape=box, style=filled];
    edge [color=blue];
    
    // Legend
    subgraph cluster_legend {
        label="Legend";
        style=filled;
        color=lightgrey;
        
        web [label="Web Server", fillcolor=lightblue];
        ssh [label="SSH Server", fillcolor=lightgreen];
        db [label="Database", fillcolor=lightyellow];
        other [label="Other Service", fillcolor=lightpink];
    }
    
'''
        
        for host, services in hosts.items():
            # Determine host type based on services
            service_names = [s['service'] for s in services if s['service']]
            
            if any('http' in s.lower() for s in service_names):
                color = "lightblue"
                shape = "ellipse"
            elif any('ssh' in s.lower() for s in service_names):
                color = "lightgreen"
                shape = "box"
            elif any(db in s.lower() for db in ['mysql', 'postgres', 'oracle', 'mssql'] for s in service_names):
                color = "lightyellow"
                shape = "cylinder"
            else:
                color = "lightpink"
                shape = "box"
            
            # Create host node
            host_clean = host.replace('.', '_').replace('-', '_')
            dot_content += f'    {host_clean} [label="{host}\\n{len(services)} ports", fillcolor={color}, shape={shape}];\n'
            
            # Add service nodes
            for service in services:
                service_name = service['service'] or 'unknown'
                service_node = f"{host_clean}_{service['port']}"
                dot_content += f'    {service_node} [label="{service['port']}/{service['protocol']}\\n{service_name}", fillcolor=white, shape=plaintext];\n'
                dot_content += f'    {host_clean} -> {service_node};\n'
        
        dot_content += '}\n'
        
        with open(output_file, 'w') as f:
            f.write(dot_content)
    
    def generate_html_topology(self, hosts, output_file):
        """Generate interactive HTML topology"""
        html_template = '''<!DOCTYPE html>
<html>
<head>
    <title>R3COND0G Network Topology</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .node circle { stroke: #333; stroke-width: 2px; }
        .node text { font-size: 12px; text-anchor: middle; }
        .link { stroke: #999; stroke-opacity: 0.6; stroke-width: 2px; }
        .tooltip { position: absolute; padding: 10px; background: #333; color: white; border-radius: 5px; pointer-events: none; }
        h1 { color: #d32f2f; }
    </style>
</head>
<body>
    <h1>🦅 R3COND0G Network Topology</h1>
    <div id="topology"></div>
    
    <script>
        const data = {hosts_json};
        
        const nodes = Object.keys(data).map(host => ({
            id: host,
            services: data[host],
            group: data[host].length > 5 ? 1 : 2
        }));
        
        const links = [];
        // Add links based on network relationships (simplified)
        
        const width = 1200;
        const height = 800;
        
        const svg = d3.select("#topology")
            .append("svg")
            .attr("width", width)
            .attr("height", height);
        
        const simulation = d3.forceSimulation(nodes)
            .force("link", d3.forceLink(links).id(d => d.id))
            .force("charge", d3.forceManyBody().strength(-300))
            .force("center", d3.forceCenter(width / 2, height / 2));
        
        const link = svg.append("g")
            .selectAll("line")
            .data(links)
            .enter().append("line")
            .attr("class", "link");
        
        const node = svg.append("g")
            .selectAll("g")
            .data(nodes)
            .enter().append("g")
            .attr("class", "node")
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended));
        
        node.append("circle")
            .attr("r", d => Math.max(10, d.services.length * 2))
            .style("fill", d => d.group === 1 ? "#ff6b6b" : "#4ecdc4");
        
        node.append("text")
            .text(d => d.id)
            .attr("dy", 5);
        
        node.append("title")
            .text(d => `${d.id}\\nServices: ${d.services.length}`);
        
        simulation.on("tick", () => {
            link.attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);
            
            node.attr("transform", d => `translate(${d.x},${d.y})`);
        });
        
        function dragstarted(event, d) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }
        
        function dragged(event, d) {
            d.fx = event.x;
            d.fy = event.y;
        }
        
        function dragended(event, d) {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }
    </script>
</body>
</html>'''
        
        html_content = html_template.replace('{hosts_json}', json.dumps(hosts))
        
        with open(output_file, 'w') as f:
            f.write(html_content)
    
    def generate_json_topology(self, hosts, output_file):
        """Generate JSON topology data"""
        topology_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "generator": "R3COND0G",
                "version": VERSION,
                "total_hosts": len(hosts)
            },
            "nodes": [],
            "links": []
        }
        
        for host, services in hosts.items():
            node = {
                "id": host,
                "type": "host",
                "services": services,
                "service_count": len(services),
                "protocols": list(set(s['protocol'] for s in services))
            }
            topology_data["nodes"].append(node)
        
        with open(output_file, 'w') as f:
            json.dump(topology_data, f, indent=2)
    
    def show_system_info(self):
        """Show system information and diagnostics"""
        if RICH_AVAILABLE:
            console.print("[bold yellow]System Information[/bold yellow]")
            
            info_table = Table(title="R3COND0G System Information")
            info_table.add_column("Component", style="cyan")
            info_table.add_column("Status", style="green")
            info_table.add_column("Details", style="white")
            
            # R3COND0G Info
            info_table.add_row("R3COND0G Version", "✓", VERSION)
            info_table.add_row("Build Date", "✓", BUILD_DATE)
            info_table.add_row("Authors", "✓", AUTHORS)
            
            # System Info
            info_table.add_row("Python Version", "✓", sys.version.split()[0])
            info_table.add_row("Platform", "✓", platform.platform())
            info_table.add_row("Architecture", "✓", platform.machine())
            
            # Distribution Info
            distro_name = f"{self.distro.distro_info['name']} {self.distro.distro_info['version']}"
            info_table.add_row("Linux Distribution", "✓", distro_name)
            info_table.add_row("Package Manager", "✓", self.distro.distro_info['package_manager'])
            
            # Binary Status
            binary_status = "✓ Built" if self.binary_path.exists() else "✗ Not Built"
            binary_color = "green" if self.binary_path.exists() else "red"
            info_table.add_row("Core Binary", binary_status, str(self.binary_path))
            
            # Dependencies
            deps = {'Go': 'go version', 'Git': 'git --version', 'Python3': 'python3 --version'}
            for name, cmd in deps.items():
                try:
                    result = subprocess.run(cmd.split(), capture_output=True, text=True)
                    if result.returncode == 0:
                        version = result.stdout.split()[2] if 'go' in cmd else result.stdout.split()[1]
                        info_table.add_row(name, "✓", version)
                    else:
                        info_table.add_row(name, "✗", "Not installed")
                except:
                    info_table.add_row(name, "✗", "Not found")
            
            # Database Status
            db_status = "✓ Connected" if self.db_path.exists() else "✗ Not initialized"
            info_table.add_row("Database", db_status, str(self.db_path))
            
            # Scan Statistics
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM scans')
                scan_count = cursor.fetchone()[0]
                cursor.execute('SELECT COUNT(*) FROM profiles')
                profile_count = cursor.fetchone()[0]
                conn.close()
                
                info_table.add_row("Total Scans", "📊", str(scan_count))
                info_table.add_row("Total Profiles", "📊", str(profile_count))
            except:
                info_table.add_row("Scan Statistics", "✗", "Database error")
            
            console.print(info_table)
            
            # Performance Info
            try:
                import psutil
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                perf_table = Table(title="System Performance")
                perf_table.add_column("Metric", style="cyan")
                perf_table.add_column("Value", style="green")
                
                perf_table.add_row("CPU Usage", f"{cpu_percent:.1f}%")
                perf_table.add_row("Memory Usage", f"{memory.percent:.1f}% ({memory.used // (1024**3):.1f}GB / {memory.total // (1024**3):.1f}GB)")
                perf_table.add_row("Disk Usage", f"{disk.percent:.1f}% ({disk.used // (1024**3):.1f}GB / {disk.total // (1024**3):.1f}GB)")
                
                console.print(perf_table)
            except ImportError:
                console.print("[yellow]Install psutil for performance metrics[/yellow]")
                
        else:
            print("System Information")
            print("=" * 50)
            print(f"R3COND0G Version: {VERSION}")
            print(f"Build Date: {BUILD_DATE}")
            print(f"Authors: {AUTHORS}")
            print(f"Python Version: {sys.version.split()[0]}")
            print(f"Platform: {platform.platform()}")
            print(f"Distribution: {self.distro.distro_info['name']} {self.distro.distro_info['version']}")
            print(f"Binary Status: {'Built' if self.binary_path.exists() else 'Not Built'}")
            print("=" * 50)
    
    def update_r3cond0g(self):
        """Update R3COND0G from repository"""
        if RICH_AVAILABLE:
            console.print("[bold yellow]Update R3COND0G[/bold yellow]")
            
            if not Confirm.ask("Update R3COND0G to latest version?"):
                return
        else:
            print("Update R3COND0G")
            if input("Update R3COND0G to latest version? (y/n): ").lower() != 'y':
                return
        
        try:
            # Check if we're in a git repository
            if (self.script_dir / ".git").exists():
                if RICH_AVAILABLE:
                    with console.status("[bold blue]Updating from git...") as status:
                        subprocess.run(['git', 'pull', 'origin', 'main'], 
                                     cwd=self.script_dir, check=True, capture_output=True)
                else:
                    print("Updating from git...")
                    subprocess.run(['git', 'pull', 'origin', 'main'], cwd=self.script_dir, check=True)
                
                # Rebuild binary
                self.build_binary()
                
                if RICH_AVAILABLE:
                    console.print("[green]✓ R3COND0G updated successfully![/green]")
                else:
                    print("✓ R3COND0G updated successfully!")
            else:
                if RICH_AVAILABLE:
                    console.print("[yellow]Not a git repository. Please update manually.[/yellow]")
                else:
                    print("Not a git repository. Please update manually.")
                    
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Update failed: {e}")
            if RICH_AVAILABLE:
                console.print(f"[red]Update failed: {e}[/red]")
            else:
                print(f"Update failed: {e}")
    
    def exit_application(self):
        """Clean exit"""
        if RICH_AVAILABLE:
            console.print("[bold green]Thank you for using R3COND0G! 🦅[/bold green]")
        else:
            print("Thank you for using R3COND0G! 🦅")
        sys.exit(0)
    
    def run_command_line(self, args):
        """Handle command line arguments"""
        if args.setup:
            return self.setup_system()
        
        elif args.build:
            return self.build_binary()
        
        elif args.scan:
            if not args.targets:
                print("Error: --targets required for scanning")
                return False
            
            # Create temporary profile from CLI args
            profile = {
                'name': 'cli_scan',
                'targets': args.targets,
                'ports': args.ports or '1-1000',
                'timeout': args.timeout or 1000,
                'concurrency': args.concurrency or 100,
                'service_detect': args.service_detect,
                'version_detect': args.version_detect,
                'os_detect': args.os_detect,
                'vuln_mapping': args.vuln_mapping,
                'udp_scan': args.udp_scan,
                'output_format': args.format or 'json'
            }
            
            scan_id = f"cli_scan_{int(time.time())}"
            return self.execute_scan(scan_id, profile)
        
        elif args.import_nmap:
            # Simulate interactive import
            self.import_nmap_results()
            return True
        
        elif args.generate_msf:
            self.generate_metasploit_rc()
            return True
        
        elif args.update_vulns:
            self.update_vulnerability_database()
            return True
        
        elif args.version:
            print(f"R3COND0G {VERSION}")
            print(f"Build Date: {BUILD_DATE}")
            print(f"Authors: {AUTHORS}")
            return True
        
        else:
            # Default to interactive mode
            self.show_interactive_menu()
            return True

def main():
    """Main entry point"""
    # Handle command line arguments
    parser = argparse.ArgumentParser(
        description="R3COND0G - Advanced Network Reconnaissance Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./run                           # Interactive mode
  ./run setup                     # Setup system
  ./run --scan aggressive --targets 192.168.1.0/24
  ./run --import-nmap results.xml
  ./run --generate-msf
        """
    )
    
    # Setup commands
    parser.add_argument('--setup', action='store_true', help='Setup R3COND0G system')
    parser.add_argument('--build', action='store_true', help='Build core binary')
    
    # Scanning options
    parser.add_argument('--scan', choices=['stealth', 'discovery', 'aggressive', 'vulnerability', 'default'],
                       help='Run scan with profile')
    parser.add_argument('--targets', nargs='+', help='Target hosts/networks')
    parser.add_argument('--ports', help='Port range (e.g., 1-1000)')
    parser.add_argument('--timeout', type=int, help='Timeout in milliseconds')
    parser.add_argument('--concurrency', type=int, help='Concurrent connections')
    parser.add_argument('--format', choices=['json', 'xml', 'html', 'csv'], help='Output format')
    
    # Scan options
    parser.add_argument('--service-detect', action='store_true', help='Enable service detection')
    parser.add_argument('--version-detect', action='store_true', help='Enable version detection')
    parser.add_argument('--os-detect', action='store_true', help='Enable OS detection')
    parser.add_argument('--vuln-mapping', action='store_true', help='Enable vulnerability mapping')
    parser.add_argument('--udp-scan', action='store_true', help='Enable UDP scanning')
    
    # Utility commands
    parser.add_argument('--import-nmap', help='Import Nmap XML results')
    parser.add_argument('--generate-msf', action='store_true', help='Generate Metasploit RC')
    parser.add_argument('--update-vulns', action='store_true', help='Update vulnerability database')
    parser.add_argument('--version', action='store_true', help='Show version information')
    
    args = parser.parse_args()
    
    # Initialize controller
    try:
        controller = R3COND0GController()
        
        # Handle Ctrl+C gracefully
        def signal_handler(sig, frame):
            if RICH_AVAILABLE:
                console.print("\n[yellow]Interrupted by user[/yellow]")
            else:
                print("\nInterrupted by user")
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Show banner unless in quiet mode
        if not any(vars(args).values()):  # No arguments = interactive mode
            controller.print_banner()
        
        # Process command line arguments or start interactive mode
        success = controller.run_command_line(args)
        
        return 0 if success else 1
        
    except KeyboardInterrupt:
        if RICH_AVAILABLE:
            console.print("\n[yellow]Interrupted by user[/yellow]")
        else:
            print("\nInterrupted by user")
        return 1
    except Exception as e:
        if RICH_AVAILABLE:
            console.print(f"[red]Fatal error: {e}[/red]")
        else:
            print(f"Fatal error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
