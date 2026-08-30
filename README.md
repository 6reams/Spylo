<p align="center">
  <img src="logo.png" alt="SPYLO Logo" width="300">
</p>

<h1 align="center">SPYLO</h1>

<p align="center">
  <strong>Advanced OSINT Framework</strong>
</p>

<p align="center">
  A powerful Open Source Intelligence (OSINT) framework for domain and username reconnaissance with an interactive CLI interface.
</p>

```
    ███████╗██████╗ ██╗   ██╗██╗      ██████╗ 
    ██╔════╝██╔══██╗╚██╗ ██╔╝██║     ██╔═══██╗
    ███████╗██████╔╝ ╚████╔╝ ██║     ██║   ██║
    ╚════██║██╔═══╝   ╚██╔╝  ██║     ██║   ██║
    ███████║██║        ██║   ███████╗╚██████╔╝
    ╚══════╝╚═╝        ╚═╝   ╚══════╝ ╚═════╝ 
```

## Features

### Domain Reconnaissance
- **DNS Analysis** - A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, DS, DNSKEY records
- **Port Scanning** - Service detection and version identification
- **WHOIS Lookup** - Domain registration information
- **Subdomain Enumeration** - Certificate Transparency search and brute-force
- **Service Detection** - HTTP/HTTPS, SSH, FTP, SMTP, Databases
- **TLS/SSL Analysis** - Certificate information and validation
- **GeoIP Lookup** - Location data for discovered IPs
- **Zone Transfer Testing** - AXFR attempts

### Username Reconnaissance
- **80+ Platforms** - Search across major social networks, development platforms, gaming sites, and security platforms
- **Concurrent Scanning** - Fast parallel processing
- **Proxy Support** - Route through proxies to avoid blocking
- **User-Agent Rotation** - Randomized browser identities
- **Smart Retry Logic** - Handle transient failures gracefully

### Output Formats
- JSON - Structured data for processing
- CSV - Spreadsheet compatible
- Markdown - Documentation format
- Table - Terminal display

## Installation

### Requirements
- Python 3.9+
- pip

### Setup

```bash
# Clone repository
git clone https://github.com/S4ddler/Spylo.git
cd Spylo

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate              # Linux/Mac
# or
.venv\Scripts\activate                 # Windows

# Install dependencies
pip install -r requirements.txt

# Run
python main.py
```

## Quick Start

```bash
spylo> help                           # Show all commands
spylo> add site domain example.com    # Add a domain target
spylo> scan site                      # Full domain scan
spylo> scan site dns                  # DNS records only
spylo> scan site ports                # Port scan only
spylo> scan site whois                # WHOIS info only

spylo> add user username johndoe      # Add username target
spylo> scan user                      # Search username across platforms

spylo> list                           # Show all targets
spylo> config                         # Show settings
spylo> set timeout 30                 # Change settings
spylo> exit                           # Exit program
```

## Commands

### Target Management
- `add <alias> <type> <value>` - Add target (domain or username)
- `del <alias>` - Delete target
- `list` or `l` - List all targets
- `clear` or `c` - Clear all targets

### Scanning
- `scan <alias>` - Full scan
- `scan <alias> dns` - DNS enumeration
- `scan <alias> ports` - Port scanning
- `scan <alias> whois` - WHOIS lookup
- `s <alias>` - Short form

### Settings
- `set <option> <value>` - Configure options
- `config` - Show current settings

### Examples
```bash
spylo> set timeout 30              # Request timeout in seconds
spylo> set proxy http://127.0.0.1:8080    # Use HTTP proxy
spylo> set retries 5               # Number of retries
spylo> set top_ports 80,443,22,3306       # Ports to scan
spylo> set dns_server 8.8.8.8      # Custom DNS server
spylo> set wordlist subdomains.txt # Wordlist for brute-force
```

### Help
- `help` or `?` - Show commands
- `exit` or `q` - Exit

## Usage Examples

### Scan a Domain
```bash
spylo> add google domain google.com
spylo> scan google

# Results saved to: out/domain_google.json
# Includes: WHOIS, DNS records, open ports, services, subdomains, etc.
```

### Search Username
```bash
spylo> add john username johndoe
spylo> scan john

# Searches across 80+ platforms
# Results saved to: out/username_johndoe.json
```

### Targeted Scan
```bash
spylo> set timeout 30
spylo> set proxy http://127.0.0.1:8080
spylo> add site domain example.com
spylo> scan site dns
```

## Project Structure

```
Spylo/
├── main.py                 # Main program
├── requirements.txt        # Dependencies
├── README.md              # This file
├── LICENSE                # MIT License
├── .gitignore             # Git ignore
│
├── core/
│   ├── reporting.py       # Report generation
│   └── utils.py           # Utilities
│
├── modules/
│   ├── domain_osint.py    # Domain reconnaissance
│   └── username_osint.py  # Username search
│
└── data/
    └── sites.json         # 80+ platforms database
```

## Output

Results are saved to the `out/` directory in multiple formats:
- `domain_example.json` - JSON format
- `domain_example.csv` - CSV format
- `domain_example.md` - Markdown format
- Console - Table display

## Security Notes

⚠️ **Important:**
- Obtain authorization before scanning targets
- Use only for authorized security assessments
- Respect platform terms of service
- SPYLO uses passive reconnaissance by default
- Optional port scanning is non-intrusive

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Missing modules | `pip install -r requirements.txt` |
| Connection timeout | `set timeout 30` |
| Rate limited | `set proxy http://...` or use delays |

## Dependencies

- aiohttp - Async HTTP
- dnspython - DNS toolkit
- requests - HTTP library
- rich - Terminal UI
- beautifulsoup4 - HTML parsing
- cryptography - SSL/TLS

## License

MIT License - see LICENSE file

## Support

- Issues: https://github.com/S4ddler/Spylo/issues
- Discussions: https://github.com/S4ddler/Spylo/discussions
- Twitter: @kerbrute

## Version

0.1.0 - Active Development

---

Made with ❤️ by the SPYLO Team
