# Violette Network Scanner

Violette is a sophisticated network scanning and visualization framework that combines powerful scanning capabilities with real-time web-based result visualization. It consists of two main components: a network scanner (`main.py`) and a real-time web interface (`live_db.py`).

## Features

- **Advanced Network Scanning**
  - Multi-threaded scanning for improved performance
  - OS detection and fingerprinting
  - Service version detection
  - Port state identification
  - SQLite database storage for scan results

- **Real-time Web Interface**
  - Live updating results via Server-Sent Events (SSE)
  - Responsive design that works on desktop and mobile
  - Clean, modern UI with sortable columns
  - Real-time status updates

## Prerequisites

- Python 3.6+
- Root privileges (required for SYN scanning)
- Required Python packages:
  ```
  python-nmap
  flask
  rich
  psutil
  ```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/edgerunner0x01/violette.git
cd violette
```

2. Install required packages:
```bash
pip install python-nmap flask rich psutil
```

3. Ensure you have nmap installed on your system:
```bash
sudo apt-get install nmap  # For Debian/Ubuntu
sudo yum install nmap      # For CentOS/RHEL
```

## Usage

### Network Scanner (main.py)

The main scanner script offers various options for customizing your scan:

```bash
sudo python main.py [target] [options]
```

#### Required Arguments:
- `target`: Target network range in CIDR notation (e.g., 192.168.1.0/24)

#### Optional Arguments:
- `-t, --threads`: Number of concurrent scanning threads (default: 10)
- `--timeout`: Timeout per host in seconds (default: 300)
- `--db`: Custom database file path (default: scanner.db)
- `--fresh`: Ignore previous scan results and perform a fresh scan
- `-v, --verbose`: Enable verbose output logging
- `--quick`: Enable quick scan mode (fewer port checks)
- `--exclude`: Comma-separated list of IP addresses to exclude

#### Example Usage:
```bash
# Basic scan of local network
sudo python main.py 192.168.1.0/24

# Advanced scan with custom options
sudo python main.py 192.168.1.0/24 -t 20 --timeout 600 --fresh -v

# Quick scan excluding specific hosts
sudo python main.py 192.168.1.0/24 --quick --exclude "192.168.1.1,192.168.1.254"
```

### Web Interface (live_db.py)

The web interface provides real-time visualization of scan results:

```bash
python live_db.py [options]
```

#### Optional Arguments:
- `--db`: Path to scanner database (default: scanner.db)
- `--host`: Host to bind to (default: 0.0.0.0)
- `--port`: Port to listen on (default: 8080)

#### Example Usage:
```bash
# Start web interface with default options
python live_db.py

# Custom configuration
python live_db.py --db custom.db --port 8888
```

## Database Schema

Violette uses SQLite with the following schema:

### Hosts Table
```sql
CREATE TABLE hosts (
    id INTEGER PRIMARY KEY,
    ip TEXT UNIQUE,
    hostname TEXT,
    last_scan TEXT,
    os_guess TEXT,
    status TEXT
);
```

### Ports Table
```sql
CREATE TABLE ports (
    id INTEGER PRIMARY KEY,
    host_id INTEGER,
    port_number INTEGER,
    service TEXT,
    version TEXT,
    FOREIGN KEY (host_id) REFERENCES hosts(id)
);
```

## Security Considerations

1. The scanner requires root privileges due to its use of SYN scanning.
2. The web interface binds to all interfaces (0.0.0.0) by default - consider restricting this in production.
3. No authentication is implemented in the web interface - use with caution.
4. Consider network and target system impacts when setting thread count and timeout values.

## Error Handling

- The scanner implements graceful shutdown on CTRL+C
- Failed scans are logged to `scanner.log`
- Database errors are handled with appropriate error messages
- Web interface includes automatic reconnection on connection loss

## Contributing

Contributions are welcome! Please feel free to submit pull requests with improvements or bug fixes.

## License

[MIT](https://opensource.org/licenses/MIT)

## Acknowledgments

- Uses Nmap for network scanning capabilities
- Built with Flask for the web interface
- Uses Rich for beautiful console output
- Implements Server-Sent Events for real-time updates
