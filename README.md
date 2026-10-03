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
- **90+ Platforms** - Search across major social networks, development platforms, gaming sites, and security platforms
- **Concurrent Scanning** - Fast parallel processing
- **Proxy Support** - Route through proxies to avoid blocking
- **User-Agent Rotation** - Randomized browser identities
- **Smart Retry Logic** - Handle transient failures gracefully
- **TLS Verification** - Certificates are verified by default

### Shell
- **Persistent Sessions** - Targets and settings survive restarts
- **Tab Completion** - Complete aliases, scan types and setting names
- **Input Validation** - Malformed domains and usernames are rejected up front

### Output Formats
- JSON - Structured data for processing
- CSV - Spreadsheet compatible
- Markdown - Documentation format
- Table - Terminal display

Select any combination with `set formats`, for example `set formats table,json,csv`.

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
- `reset` - Remove every target (asks for confirmation)
- `clear` or `c` - Clear the screen

### Scanning
- `scan <alias>` - Full scan
- `scan <alias> dns` - DNS enumeration
- `scan <alias> ports` - Port scanning
- `scan <alias> whois` - WHOIS lookup
- `s <alias>` - Short form

### Settings
- `set <option> <value>` - Configure options
- `config` - Show current settings
- `save` - Write targets and settings to disk immediately

| Option | Default | Description |
|--------|---------|-------------|
| `output_dir` | `out` | Directory for saved reports |
| `formats` | `table,json` | Any of `table`, `json`, `csv`, `md` |
| `timeout` | `15` | Per-request timeout in seconds |
| `retries` | `2` | Retry attempts for failed requests |
| `concurrency` | `50` | Concurrent requests for username scans |
| `top_ports` | 67 common ports | Comma-separated ports to scan |
| `wordlist` | not set | Subdomain brute-force wordlist path |
| `dns_server` | not set | DNS server IP to query |
| `verify_tls` | `true` | Verify TLS certificates |
| `no_axfr` | `false` | Skip AXFR zone-transfer attempts |
| `no_scan_ports` | `false` | Skip port scanning during full scans |
| `proxy` | not set | Proxy URL (never written to disk) |

### Examples
```bash
spylo> set timeout 30                     # Request timeout in seconds
spylo> set proxy http://127.0.0.1:8080    # Use HTTP proxy
spylo> set retries 5                      # Number of retries
spylo> set top_ports 80,443,22,3306       # Ports to scan
spylo> set dns_server 8.8.8.8             # Custom DNS server (must be an IP)
spylo> set wordlist subdomains.txt        # Wordlist for brute-force
spylo> set formats table,json,csv,md      # Report formats
spylo> set dns_server none                # Clear an optional setting
```

### Sessions

Targets and settings are stored in `~/.spylo/session.json` (owner-readable
only) and restored on the next launch. The proxy URL is deliberately excluded,
since proxy URLs often embed credentials.

### Help
- `help` or `?` - Show commands
- `exit` or `q` - Exit

## Usage Examples

### Scan a Domain
```bash
spylo> add google domain google.com
spylo> scan google

# Results saved to: out/domain_google.com_all_<timestamp>.json
# Includes: WHOIS, DNS records, open ports, services, subdomains, etc.
```

### Search Username
```bash
spylo> add john username johndoe
spylo> scan john

# Searches across 90+ platforms
# Results saved to: out/username_johndoe_<timestamp>.json
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
├── main.py                 # Interactive shell and session handling
├── requirements.txt        # Runtime dependencies
├── requirements-dev.txt    # Test dependencies
├── pytest.ini             # Test configuration
├── README.md              # This file
├── LICENSE                # MIT License
├── .gitignore             # Git ignore
│
├── core/
│   ├── reporting.py       # Report generation
│   ├── validation.py      # Target and setting validation
│   ├── ratelimit.py       # Throttling for third-party APIs
│   └── utils.py           # Utilities
│
├── modules/
│   ├── domain_osint.py    # Domain reconnaissance
│   └── username_osint.py  # Username search
│
├── tests/                 # Offline test suite
│
└── data/
    └── sites.json         # 90+ platforms database
```

## Output

Results are saved to the `out/` directory. Filenames carry the module, target,
scan type and UTC timestamp, so repeat scans accumulate rather than overwrite
each other:

- `domain_example.com_dns_20260101T120000Z.json`
- `domain_example.com_dns_20260101T120000Z.csv`
- `domain_example.com_dns_20260101T120000Z.md`
- Console - Table display

## Development

```bash
pip install -r requirements-dev.txt
python -m pytest
```

The suite runs fully offline -- every network call is stubbed -- so it is safe
to run anywhere. CI runs the same tests on Python 3.9 through 3.12.

## Security Notes

⚠️ **Important:**
- Obtain authorization before scanning targets
- Use only for authorized security assessments
- Respect platform terms of service
- SPYLO uses passive reconnaissance by default
- Optional port scanning is non-intrusive

**Defaults worth knowing:**
- TLS certificates are verified on every request. `set verify_tls false` turns
  verification off and prints a warning on each scan -- only do this when you
  understand that responses can then be tampered with.
- Requests to crt.sh and ipapi.co are rate limited client-side and honor
  `Retry-After`, so a large scan will not hammer either service.
- `dns_server` must be a literal IP, since the value reaches `dig` arguments.
- The saved session file is created with `0600` permissions and never contains
  the proxy URL.

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
