#!/usr/bin/env python3

#########################################################
#        Violette - Network Scanner Framework           #
#              Author  - edgerunner0x01                 #
#        https://github.com/edgerunner0x01/violette     #
#########################################################


from flask import Flask, render_template_string, Response
import sqlite3
import argparse
import logging
from datetime import datetime
import json
import time

class SimpleScanServer:
    def __init__(self, db_path, host='0.0.0.0', port=8080):
        self.db_path = db_path
        self.host = host
        self.port = port
        self.app = Flask(__name__)
        self.last_modified = self.get_last_modified()
        self.setup_routes()

    def get_last_modified(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT MAX(last_scan) FROM hosts')
                result = cursor.fetchone()[0]
                return result if result else ''
        except sqlite3.Error:
            return ''

    def get_scan_results(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT 
                        h.ip,
                        h.hostname,
                        h.os_guess,
                        h.last_scan,
                        GROUP_CONCAT(p.port_number || '/' || p.service || 
                                   CASE WHEN p.version != '' 
                                   THEN ' (' || p.version || ')' 
                                   ELSE '' END, ', ') as port_info
                    FROM hosts h
                    LEFT JOIN ports p ON h.id = p.host_id
                    GROUP BY h.ip
                    ORDER BY h.ip
                ''')
                return cursor.fetchall()
        except sqlite3.Error as e:
            logging.error(f"Database error: {e}")
            return []

    def setup_routes(self):
        @self.app.route('/')
        def index():
            results = self.get_scan_results()
            return render_template_string(HTML_TEMPLATE, results=results)

        @self.app.route('/stream')
        def stream():
            def event_stream():
                last_check = self.get_last_modified()
                while True:
                    current = self.get_last_modified()
                    if current != last_check:
                        results = self.get_scan_results()
                        data = []
                        for row in results:
                            data.append({
                                'ip': row[0],
                                'hostname': row[1],
                                'os': row[2],
                                'ports': row[4] if row[4] else '-',
                                'last_scan': row[3].split('.')[0].replace('T', ' ')
                            })
                        yield f"data: {json.dumps(data)}\n\n"
                        last_check = current
                    time.sleep(1)
            return Response(event_stream(), mimetype="text/event-stream")

    def run(self):
        self.app.run(host=self.host, port=self.port, threaded=True)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan Results</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
            margin: 10px;
            background: #fff;
            font-size: 13px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 5px;
            table-layout: auto;
        }
        th, td {
            padding: 8px 12px;
            border: 1px solid #eee;
            text-align: left;
            word-wrap: break-word;
        }
        th {
            background: #fafafa;
            font-weight: 500;
            border-bottom: 2px solid #eee;
        }
        tr:hover {
            background: #f8f8f8;
        }
        .port-info {
            max-width: 400px;
            word-wrap: break-word;
        }
        .mono {
            font-family: monospace;
        }
        #status {
            position: fixed;
            bottom: 10px;
            right: 10px;
            padding: 5px 10px;
            background: #f0f0f0;
            border-radius: 3px;
            font-size: 11px;
            opacity: 0.8;
        }

        /* Responsive styles for small screens */
        @media (max-width: 768px) {
            body {
                font-size: 12px;
            }
            th, td {
                padding: 6px;
            }
            table {
                font-size: 12px;
            }
            #status {
                font-size: 10px;
            }
        }

        /* For smaller mobile screens */
        @media (max-width: 480px) {
            th, td {
                padding: 4px;
            }
            #status {
                font-size: 9px;
            }
            table {
                font-size: 11px;
            }
            .port-info {
                font-size: 11px;
            }
        }

        /* Responsive scrolling for table */
        @media (max-width: 600px) {
            table {
                display: block;
                overflow-x: auto;
                white-space: nowrap;
            }
        }
    </style>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const tbody = document.querySelector('tbody');
            const status = document.getElementById('status');
            const evtSource = new EventSource('/stream');

            evtSource.onmessage = function(event) {
                const data = JSON.parse(event.data);
                let newHtml = '';
                
                data.forEach(row => {
                    newHtml += `
                        <tr>
                            <td class="mono">${row.ip}</td>
                            <td>${row.hostname}</td>
                            <td>${row.os}</td>
                            <td class="port-info">${row.ports}</td>
                            <td>${row.last_scan}</td>
                        </tr>
                    `;
                });
                
                tbody.innerHTML = newHtml;
                status.textContent = 'Updated: ' + new Date().toLocaleTimeString();
            };

            evtSource.onerror = function() {
                status.textContent = 'Connection lost. Reconnecting...';
            };
        });
    </script>
</head>
<body>
    <table>
        <thead>
            <tr>
                <th>IP</th>
                <th>Hostname</th>
                <th>OS</th>
                <th>Ports</th>
                <th>Last Scan</th>
            </tr>
        </thead>
        <tbody>
            {% for row in results %}
            <tr>
                <td class="mono">{{ row[0] }}</td>
                <td>{{ row[1] }}</td>
                <td>{{ row[2] }}</td>
                <td class="port-info">{{ row[4] if row[4] else '-' }}</td>
                <td>{{ row[3].split('.')[0].replace('T', ' ') }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    <div id="status">Connected</div>
</body>
</html>
"""

def main():
    parser = argparse.ArgumentParser(description='Simple Scan Results Server')
    parser.add_argument('--db', default='scanner.db', help='Path to scanner database')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8080, help='Port to listen on')
    
    args = parser.parse_args()
    
    server = SimpleScanServer(args.db, args.host, args.port)
    server.run()

if __name__ == "__main__":
    main()