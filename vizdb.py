#!/usr/bin/env python3

import sqlite3
import argparse
from rich.console import Console
from rich.table import Table
from rich.style import Style
from rich import box
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime

@dataclass
class Host:
    id: int
    ip: str
    hostname: str
    last_scan: str
    os_guess: str
    status: str
    ports: List[Dict]

class NetworkDB:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.console = Console()

    def connect(self) -> sqlite3.Connection:
        """Establish database connection"""
        try:
            return sqlite3.connect(self.db_path)
        except sqlite3.Error as e:
            self.console.print(f"[red]Error connecting to database: {e}[/red]")
            raise

    def get_host_ports(self, conn: sqlite3.Connection, host_id: int) -> List[Dict]:
        """Retrieve ports for a specific host"""
        cursor = conn.cursor()
        cursor.execute("""
            SELECT port_number, service, version 
            FROM ports 
            WHERE host_id = ?
            ORDER BY port_number
        """, (host_id,))
        return [{"port": port, "service": svc, "version": ver} 
                for port, svc, ver in cursor.fetchall()]

    def get_all_hosts(self) -> List[Host]:
        """Retrieve all hosts with their associated ports"""
        with self.connect() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, ip, hostname, last_scan, os_guess, status 
                FROM hosts
                ORDER BY id
            """)
            
            hosts = []
            for row in cursor.fetchall():
                host_id, ip, hostname, last_scan, os_guess, status = row
                ports = self.get_host_ports(conn, host_id)
                hosts.append(Host(
                    id=host_id,
                    ip=ip,
                    hostname=hostname,
                    last_scan=last_scan,
                    os_guess=os_guess or "Unknown",
                    status=status,
                    ports=ports
                ))
            return hosts

    def format_ports(self, ports: List[Dict]) -> str:
        """Format ports list into a readable string"""
        if not ports:
            return "No open ports"
        return ", ".join(f"{p['port']}/{p['service']}" for p in ports)

    def display_hosts(self, show_all: bool = False):
        """Display hosts in a Rich table format"""
        try:
            hosts = self.get_all_hosts()
            
            table = Table(
                title="Network Hosts Inventory",
                box=box.ROUNDED,
                header_style="bold cyan",
                show_lines=True
            )

            # Add columns
            table.add_column("ID", style="dim")
            table.add_column("IP Address")
            table.add_column("Hostname")
            table.add_column("Status", justify="center")
            table.add_column("OS", justify="center")
            table.add_column("Open Ports", justify="left")
            table.add_column("Last Scan", justify="right")

            # Status styles
            status_styles = {
                "up": Style(color="green"),
                "down": Style(color="red"),
                "unknown": Style(color="yellow")
            }

            for host in hosts:
                # Skip hosts with no open ports if show_all is False
                if not show_all and not host.ports:
                    continue

                status_style = status_styles.get(host.status.lower(), status_styles["unknown"])
                
                table.add_row(
                    str(host.id),
                    host.ip,
                    host.hostname or "N/A",
                    host.status,
                    host.os_guess,
                    self.format_ports(host.ports),
                    host.last_scan,
                    style=status_style
                )

            self.console.print(table)

        except Exception as e:
            self.console.print(f"[red]Error displaying hosts: {e}[/red]")

def main():
    parser = argparse.ArgumentParser(
        description="Display network hosts information in a tabular format"
    )
    parser.add_argument(
        "-d", 
        "--database", 
        default="network.db",
        help="Path to SQLite database (default: network.db)"
    )
    parser.add_argument(
        "-a", 
        "--all",
        action="store_true",
        help="Show all hosts, including those with no open ports"
    )
    args = parser.parse_args()

    try:
        db = NetworkDB(args.database)
        db.display_hosts(show_all=args.all)
    except Exception as e:
        console = Console()
        console.print(f"[red]Error: {e}[/red]")
        exit(1)

if __name__ == "__main__":
    main()
