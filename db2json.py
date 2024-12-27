#!/usr/bin/env python3

#########################################################
#        Violette - Network Scanner Framework           #
#              Author  - edgerunner0x01                 #
#        https://github.com/edgerunner0x01/violette     #
#########################################################

import sqlite3
import json
from datetime import datetime
import argparse
import sys
from pathlib import Path

def connect_to_database(db_path):
    """Connect to the SQLite database."""
    if not Path(db_path).exists():
        print(f"Error: Database file '{db_path}' not found!")
        sys.exit(1)
    
    try:
        return sqlite3.connect(db_path)
    except sqlite3.Error as e:
        print(f"Error connecting to database: {e}")
        sys.exit(1)

def fetch_scan_data(conn):
    """Fetch all scan data from the database."""
    try:
        cursor = conn.cursor()
        
        # Get all hosts with their details
        cursor.execute("""
            SELECT 
                h.id, h.ip, h.hostname, h.last_scan, h.os_guess, h.status
            FROM hosts h
        """)
        
        hosts = []
        for host_row in cursor.fetchall():
            host_id, ip, hostname, last_scan, os_guess, status = host_row
            
            # Get all ports for this host
            cursor.execute("""
                SELECT port_number, service, version
                FROM ports
                WHERE host_id = ?
            """, (host_id,))
            
            ports = []
            for port_row in cursor.fetchall():
                port_number, service, version = port_row
                ports.append({
                    "port": port_number,
                    "service": service,
                    "version": version
                })
            
            # Build host dictionary
            host_data = {
                "ip": ip,
                "hostname": hostname,
                "last_scan": last_scan,
                "os_guess": os_guess,
                "status": status,
                "ports": ports
            }
            
            hosts.append(host_data)
        
        return {
            "scan_results": hosts,
            "metadata": {
                "export_date": datetime.now().isoformat(),
                "total_hosts": len(hosts)
            }
        }
        
    except sqlite3.Error as e:
        print(f"Error fetching data: {e}")
        sys.exit(1)

def export_to_json(data, output_file):
    """Export the data to a JSON file."""
    try:
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"Successfully exported scan results to {output_file}")
        print(f"Total hosts exported: {data['metadata']['total_hosts']}")
    except IOError as e:
        print(f"Error writing to file: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Export Violette scanner results to JSON')
    parser.add_argument('--db', default='scanner.db', help='Input database file (default: scanner.db)')
    parser.add_argument('--output', default='scan_results.json', help='Output JSON file (default: scan_results.json)')
    
    args = parser.parse_args()
    
    # Connect to database
    conn = connect_to_database(args.db)
    
    # Fetch all scan data
    print(f"Fetching data from {args.db}...")
    scan_data = fetch_scan_data(conn)
    
    # Export to JSON
    export_to_json(scan_data, args.output)
    
    # Close database connection
    conn.close()

if __name__ == "__main__":
    main()
