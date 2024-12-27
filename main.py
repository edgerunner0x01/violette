#!/usr/bin/env python3

#########################################################
#        Violette - Network Scanner Framework           #
#              Author  - edgerunner0x01                 #
#        https://github.com/edgerunner0x01/violette     #
#########################################################


import socket
import sqlite3
import ipaddress
import concurrent.futures
import argparse
from datetime import datetime
import nmap
import logging
import sys
import os
import signal
import psutil
import requests
import json
from packaging import version
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint
from rich.text import Text

VERSION = "1.0.0"
GITHUB_REPO = "edgerunner0x01/violette"

BANNER_TEXT = f"""[cyan]
#########################################################
#     Violette - Network Scanner Framework              #
#              Author  - edgerunner0x01                 #
#        https://github.com/{GITHUB_REPO}     #
#########################################################
#                                                       #
#  Version    : {VERSION}                                   #
#  Powered by : Python3, Nmap, Rich                     #
#  License    : MIT                                     #
#                                                       #
#########################################################[/]

[yellow][ * ][/] Initializing scanner...
[yellow][ * ][/] Checking dependencies...
[yellow][ * ][/] Loading modules...\n"""

class NetworkScanner:
    def __init__(self, db_path='scanner.db', threads=10, timeout=300):
        self.fresh_scan = True  
        self.version = VERSION
        self.console = Console()
        self.display_banner()
        self.check_dependencies()
        self.check_for_updates()
        self.check_root()
        self.db_path = db_path
        self.threads = threads
        self.timeout = timeout
        self.setup_database()
        self.nm = nmap.PortScanner()
        self.setup_logging()
        self.active_hosts = 0
        signal.signal(signal.SIGINT, self.handle_exit)

    def check_dependencies(self):
        """Check if all required dependencies are installed"""
        try:
            self.console.print("[yellow][ * ][/] Checking Nmap installation...")
            if os.system("which nmap > /dev/null 2>&1") != 0:
                self.console.print("[red][ ! ] Error: Nmap is not installed. Please install it first.[/]")
                sys.exit(1)
            self.console.print("[green][ ✓ ][/] All dependencies satisfied.")
        except Exception as e:
            self.console.print(f"[red][ ! ] Error checking dependencies: {e}[/]")
            sys.exit(1)

    def display_banner(self):
        """Display the tool's banner with version and author information"""
        self.console.print(BANNER_TEXT)
        
    def check_for_updates(self):
        """Check for updates from GitHub repository"""
        try:
            self.console.print("[yellow][ * ][/] Checking for updates...")
            response = requests.get(f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest")
            if response.status_code == 200:
                latest_version = response.json()["tag_name"].lstrip("v")
                if version.parse(latest_version) > version.parse(self.version):
                    self.console.print(f"[red][ ! ][/] New version {latest_version} available!")
                    if self.prompt_update():
                        self.update_tool(latest_version)
                else:
                    self.console.print("[green][ ✓ ][/] You're running the latest version!")
        except Exception as e:
            self.console.print("[red][ ! ][/] Failed to check for updates")
            logging.error(f"Update check failed: {e}")

    def prompt_update(self):
        """Prompt user for update confirmation"""
        return input("\n[?] Would you like to update now? (y/n): ").lower() == 'y'

    def update_tool(self, latest_version):
        """Update the tool to the latest version"""
        try:
            self.console.print("[yellow][ * ][/] Downloading update...")
            os.system(f"git pull origin master")
            self.console.print("[green][ ✓ ][/] Update successful! Please restart the tool.")
            sys.exit(0)
        except Exception as e:
            self.console.print("[red][ ! ][/] Update failed!")
            logging.error(f"Update failed: {e}")

    def check_root(self):
        if os.geteuid() != 0:
            rprint("[red][ ! ] Error: This scanner requires root privileges")
            sys.exit(1)

    def handle_exit(self, signum, frame):
        rprint("\n[yellow] Gracefully shutting down...")
        self.cleanup()
        sys.exit(0)

    def cleanup(self):
        try:
            self.console.print("[yellow][ * ][/] Cleaning up...")
            for proc in psutil.process_iter(['pid', 'name']):
                if 'nmap' in proc.info['name']:
                    proc.kill()
            self.console.print("[green] Cleanup complete")
        except:
            pass

    def setup_logging(self):
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            filename='scanner.log',
            level=logging.INFO,
            format=log_format,
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(log_format))
        logging.getLogger().addHandler(console_handler)

    def setup_database(self):
        try:
            self.console.print("[yellow][ * ][/] Setting up database...")
            conn = sqlite3.connect(self.db_path, timeout=20)
            c = conn.cursor()
            
            # Enable WAL mode for better concurrent access
            c.execute('PRAGMA journal_mode=WAL')
            c.execute('PRAGMA synchronous=NORMAL')
            
            # Create tables
            c.executescript('''
                DROP TABLE IF EXISTS ports;
                DROP TABLE IF EXISTS hosts;
                
                CREATE TABLE hosts (
                    id INTEGER PRIMARY KEY,
                    ip TEXT UNIQUE,
                    hostname TEXT,
                    last_scan TEXT,
                    os_guess TEXT,
                    status TEXT
                );
                
                CREATE TABLE ports (
                    id INTEGER PRIMARY KEY,
                    host_id INTEGER,
                    port_number INTEGER,
                    service TEXT,
                    version TEXT,
                    FOREIGN KEY (host_id) REFERENCES hosts(id)
                );
                
                CREATE INDEX IF NOT EXISTS idx_ip ON hosts(ip);
                CREATE INDEX IF NOT EXISTS idx_ports ON ports(host_id);
            ''')
            
            conn.commit()
            conn.close()
            self.console.print("[green][ ✓ ][/] Database setup complete")
        except sqlite3.Error as e:
            self.console.print(f"[red][ ! ] Database error: {e}[/]")
            logging.error(f"Database error: {e}")
            sys.exit(1)

    def is_already_scanned(self, ip, hours_threshold=24):
        try:
            with sqlite3.connect(self.db_path, timeout=20) as conn:
                c = conn.cursor()
                c.execute('''
                    SELECT last_scan FROM hosts 
                    WHERE ip = ? AND datetime(last_scan) > datetime('now', '-' || ? || ' hours')
                ''', (ip, hours_threshold))
                result = c.fetchone()
                return bool(result)
        except sqlite3.Error as e:
            logging.error(f"Database error checking scan history: {e}")
        return False

    def scan_host(self, ip):
        try:
            if self.is_already_scanned(ip) and not self.fresh_scan:
                return None
                
            scan_args = f'-sS -sV -O -A --host-timeout {self.timeout}s'
            self.nm.scan(ip, arguments=scan_args)
            
            if ip not in self.nm.all_hosts():
                return None

            scan_result = self.nm[ip]
            
            with sqlite3.connect(self.db_path, timeout=20) as conn:
                c = conn.cursor()
                
                os_guess = 'Unknown'
                try:
                    if 'osmatch' in scan_result and scan_result['osmatch']:
                        os_guess = scan_result['osmatch'][0].get('name', 'Unknown')
                    elif 'osclass' in scan_result and scan_result['osclass']:
                        os_guess = scan_result['osclass'][0].get('osfamily', 'Unknown')
                except (KeyError, IndexError):
                    os_guess = 'Unknown'
                
                c.execute('''
                    INSERT OR REPLACE INTO hosts (ip, hostname, last_scan, os_guess, status)
                    VALUES (?, ?, ?, ?, ?)
                ''', (ip, socket.getfqdn(ip), datetime.now().isoformat(), 
                     os_guess, scan_result['status']['state']))
                
                host_id = c.lastrowid
                
                for proto in scan_result.all_protocols():
                    for port in scan_result[proto]:
                        port_info = scan_result[proto][port]
                        c.execute('''
                            INSERT INTO ports (host_id, port_number, service, version)
                            VALUES (?, ?, ?, ?)
                        ''', (host_id, port, port_info.get('name', ''), 
                             port_info.get('version', '')))
                
                conn.commit()
            
            self.active_hosts += 1
            return {
                'ip': ip,
                'os': os_guess,
                'ports': scan_result.get('tcp', {})
            }
            
        except Exception as e:
            logging.error(f"Error scanning {ip}: {e}")
            return None

    def scan_network(self, network_range):
        try:
            self.console.print(f"\n[yellow][ * ][/] Starting scan of network: {network_range}\n")
            network = ipaddress.ip_network(network_range)
            total_hosts = sum(1 for _ in network.hosts())
            completed = 0
            
            with Progress(
                SpinnerColumn(),
                *Progress.get_default_columns(),
                TimeElapsedColumn(),
                refresh_per_second=1
            ) as progress:
                task = progress.add_task("[cyan]Scanning network...", total=total_hosts)
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                    future_to_ip = {
                        executor.submit(self.scan_host, str(ip)): ip 
                        for ip in network.hosts()
                    }
                    
                    for future in concurrent.futures.as_completed(future_to_ip):
                        try:
                            result = future.result()
                            if result:
                                self.display_result(result)
                        except Exception as e:
                            ip = future_to_ip[future]
                            logging.error(f"Scan failed for {ip}: {e}")
                        finally:
                            completed += 1
                            progress.update(task, completed=completed)
            
            self.display_summary()
            
        except KeyboardInterrupt:
            self.handle_exit(None, None)
        except Exception as e:
            logging.error(f"Critical error: {e}")
        finally:
            self.cleanup()

    def display_result(self, result):
        self.console.print(f"[green] - Found host: {result['ip']} [cyan](OS: {result['os']})")
        for port, info in result['ports'].items():
            self.console.print(f" Port {port}: {info.get('name', '')} {info.get('version', '')}")

    def display_summary(self):
        panel = Panel(f"""
[bold green][ ✓ ] Scan Complete[/]
[ * ] Total active hosts: {self.active_hosts}
[ * ] Scan duration: {datetime.now() - self.start_time}
[ * ] Results saved to: {self.db_path}
        """, title="Scan Summary")
        self.console.print(panel)

def main():
    parser = argparse.ArgumentParser(
        description='Violette - Advanced Network Scanner Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('target', help='Target network range (CIDR notation)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of concurrent threads')
    parser.add_argument('--timeout', type=int, default=300, help='Timeout per host in seconds')
    parser.add_argument('--db', default='scanner.db', help='Database file path')
    parser.add_argument('--fresh', action='store_true', help='Ignore previous scans')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--quick', action='store_true', help='Quick scan mode (fewer port checks)')
    parser.add_argument('--exclude', help='Exclude IP addresses (comma-separated)')
    parser.add_argument('--no-update', action='store_true', help='Skip update check')
    parser.add_argument('--version', action='version', version=f'Violette v{VERSION}')
    
    args = parser.parse_args()
    
    scanner = NetworkScanner(
        db_path=args.db,
        threads=args.threads,
        timeout=args.timeout
    )
    scanner.fresh_scan = args.fresh
    scanner.start_time = datetime.now()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    scanner.scan_network(args.target)

if __name__ == "__main__":
    main()