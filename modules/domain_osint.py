import concurrent.futures
import socket
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import quote

import dns.resolver
import requests
import whois
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.box import SQUARE

# Modern minimal color scheme
PRIMARY_BLUE = "#0066cc"  # Deeper blue for main elements
SECONDARY_BLUE = "#4d94ff"  # Lighter blue for secondary elements
WHITE = "#ffffff"  # Pure white

from core.ratelimit import crtsh_limiter, geoip_limiter, rate_limited_get
from core.utils import which, run_cmd, grab_banner, fetch_tls_cert, extract_cert_summary
from core.validation import parse_ports, validate_dns_server

console = Console()


def _first_line(text: Optional[str], limit: int = 80) -> str:
    """Condense a banner to one printable line.

    Banners are whole HTTP responses, which are unusable both as a table
    cell and as a `service` value in the saved report.
    """
    if not text:
        return ""
    line = text.splitlines()[0].strip() if text.strip() else ""
    return line[:limit]


def _describe_cert(cert_info: Optional[dict]) -> str:
    """Render a certificate summary as a short string."""
    if not cert_info:
        return ""
    expires = cert_info.get("notAfter")
    return f"cert expires {expires}" if expires else "cert present"


SUPPORTED_RRTYPES = [
    "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "DS", "DNSKEY",
]

DEFAULT_TOP_PORTS = (
    "21,22,23,25,53,80,81,110,111,135,139,143,443,445,465,587,993,995,1025,1433,1521,"
    "1723,2082,2083,2086,2087,2095,2096,2222,2375,2376,3000,3128,3306,3389,4444,5000,"
    "5432,5555,5672,5900,5984,6379,7000,8000,8008,8080,8081,8082,8083,8086,8088,8443,"
    "8880,8888,9000,9042,9090,9200,9300,10000,11211,27017,27018,28017,50000,50070"
)


@dataclass
class DomainScanner:
    timeout: int = 15
    proxy: Optional[str] = None
    no_axfr: bool = False
    no_scan_ports: bool = False
    top_ports: str = DEFAULT_TOP_PORTS
    wordlist: Optional[str] = None
    dns_server: Optional[str] = None

    def __post_init__(self):
        # dns_server is interpolated into `dig @<server>` argv, so it is
        # pinned to a literal IP here rather than trusted downstream.
        self.dns_server = validate_dns_server(self.dns_server)
        self.ports = parse_ports(self.top_ports)

    def scan_whois(self, domain: str) -> dict:
        """Perform WHOIS lookup for a domain"""
        result = {"whois": {}}
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task(f"[{PRIMARY_BLUE}]Fetching WHOIS information[/{PRIMARY_BLUE}]")
            
            try:
                w = whois.whois(domain)
                
                # Handle dates - some might be lists, take first non-None value
                def get_date(date_field):
                    if isinstance(date_field, (list, tuple)):
                        return next((d for d in date_field if d is not None), None)
                    return date_field
                
                # Handle statuses - ensure we have a list and clean it up
                def clean_status(status):
                    if not status:
                        return None
                    if isinstance(status, str):
                        return [status]
                    if isinstance(status, (list, tuple)):
                        return [s for s in status if s]
                    return None
                
                whois_info = {
                    "domain_name": self._safe(w.domain_name),
                    "registrar": self._safe(w.registrar),
                    "creation_date": self._safe(get_date(w.creation_date)),
                    "expiration_date": self._safe(get_date(w.expiration_date)),
                    "updated_date": self._safe(get_date(w.updated_date)),
                    "name_servers": list(sorted(set([str(x).lower() for x in (w.name_servers or []) if x]))),
                    "status": clean_status(w.status),
                }
                result["whois"] = whois_info
                
                # Build and display modern table
                table = Table(box=SQUARE)
                table.add_column(f"[{WHITE}]Field[/{WHITE}]")
                table.add_column(f"[{WHITE}]Value[/{WHITE}]")
                
                # Display fields in a specific order with nice formatting
                field_order = [
                    ("domain_name", "Domain Name"),
                    ("registrar", "Registrar"),
                    ("creation_date", "Created"),
                    ("expiration_date", "Expires"),
                    ("updated_date", "Updated"),
                    ("name_servers", "Nameservers"),
                    ("status", "Status")
                ]
                
                for key, display_name in field_order:
                    value = whois_info.get(key)
                    if value:
                        if isinstance(value, list):
                            # Format lists vertically with bullet points
                            formatted_value = "\n• " + "\n• ".join(value)
                        else:
                            formatted_value = str(value)
                        table.add_row(
                            f"[{PRIMARY_BLUE}]{display_name}[/{PRIMARY_BLUE}]",
                            f"[{SECONDARY_BLUE}]{formatted_value}[/{SECONDARY_BLUE}]"
                        )
                
                if table.row_count > 0:
                    console.print()
                    console.print(Panel(table, title=f"[{WHITE}]WHOIS Information[/{WHITE}]", box=SQUARE))
                else:
                    console.print()
                    console.print(Panel(
                        f"[{SECONDARY_BLUE}]No WHOIS information found[/{SECONDARY_BLUE}]",
                        title=f"[{WHITE}]WHOIS Information[/{WHITE}]",
                        box=SQUARE
                    ))
                
            except Exception as e:
                result["whois_error"] = str(e)
                console.print(Panel(
                    f"[{SECONDARY_BLUE}]Error: Could not fetch WHOIS information ({str(e)})[/{SECONDARY_BLUE}]",
                    title=f"[{WHITE}]Error[/{WHITE}]",
                    box=SQUARE
                ))
            
            progress.update(task, completed=100)
        
        return result

    def scan_dns(self, domain: str) -> dict:
        """Perform DNS enumeration for a domain"""
        result = {"dns": {"records": {}}}
        
        resolver = dns.resolver.Resolver()
        if self.dns_server:
            resolver.nameservers = [self.dns_server]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task(
                f"[{PRIMARY_BLUE}]Gathering DNS records[/{PRIMARY_BLUE}]",
                total=len(SUPPORTED_RRTYPES)
            )
            
            dns_table = Table(box=SQUARE)
            dns_table.add_column(f"[{PRIMARY_BLUE}]Record[/{PRIMARY_BLUE}]")
            dns_table.add_column(f"[{PRIMARY_BLUE}]Value[/{PRIMARY_BLUE}]")
            
            for rr in SUPPORTED_RRTYPES:
                progress.update(
                    task,
                    advance=1,
                    description=f"[{PRIMARY_BLUE}]Checking {rr} records[/{PRIMARY_BLUE}]"
                )
                
                recs = self._dig(domain, rr)
                if not recs:
                    recs = self._dns_query(resolver, domain, rr)
                if recs:
                    result["dns"]["records"][rr] = recs
                    dns_table.add_row(
                        f"[{SECONDARY_BLUE}]{rr}[/{SECONDARY_BLUE}]",
                        f"[{WHITE}]{chr(10).join(recs)}[/{WHITE}]"
                    )
        
        if dns_table.row_count > 0:
            console.print()
            console.print(Panel(
                dns_table,
                title=f"[{WHITE}]DNS Records[/{WHITE}]",
                box=SQUARE
            ))
        
        return result

    def scan_ports(self, domain: str) -> dict:
        """Perform port scanning for a domain"""
        result = {"ports": {}}
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True
        ) as progress:
            try:
                # First task: Resolving IPs
                ips = set()
                resolver = dns.resolver.Resolver()
                resolve_task = progress.add_task(
                    f"[{PRIMARY_BLUE}]Resolving IP addresses[/{PRIMARY_BLUE}]"
                )

                if self.dns_server:
                    resolver.nameservers = [self.dns_server]
                
                # First resolve IPs
                for rr in ["A", "AAAA"]:
                    try:
                        answers = resolver.resolve(domain, rr)
                        ips.update(str(rdata) for rdata in answers)
                    except Exception:
                        pass
                
                progress.update(resolve_task, completed=100)
                
                if not ips:
                    console.print(Panel(
                        f"[{SECONDARY_BLUE}]Could not resolve domain to IP address[/{SECONDARY_BLUE}]",
                        title=f"[{WHITE}]Error[/{WHITE}]",
                        box=SQUARE
                    ))
                    return result
                
                # Start port scanning
                total_ports = len(ips) * len(self.ports)
                scan_task = progress.add_task(
                    f"[{PRIMARY_BLUE}]Scanning ports[/{PRIMARY_BLUE}]",
                    total=total_ports
                )
                
                scan_table = Table(box=SQUARE)
                scan_table.add_column(f"[{PRIMARY_BLUE}]IP[/{PRIMARY_BLUE}]")
                scan_table.add_column(f"[{PRIMARY_BLUE}]Port[/{PRIMARY_BLUE}]")
                scan_table.add_column(f"[{PRIMARY_BLUE}]Service[/{PRIMARY_BLUE}]")
                scan_table.add_column(f"[{PRIMARY_BLUE}]Details[/{PRIMARY_BLUE}]")
                
                found_open_ports = False
                for ip in ips:
                    result["ports"][ip] = {}
                    for port in self.ports:
                        progress.update(
                            scan_task,
                            advance=1,
                            description=f"[{PRIMARY_BLUE}]Checking {ip}:{port}[/{PRIMARY_BLUE}]"
                        )
                        
                        try:
                            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                                sock.settimeout(self.timeout)
                                if sock.connect_ex((ip, port)) != 0:
                                    continue
                        except OSError:
                            continue

                        found_open_ports = True
                        banner = grab_banner(ip, port, self.timeout)
                        service_name = _first_line(banner) or "unknown"

                        # A cert that cannot be fetched or verified must not
                        # discard the open port we already confirmed.
                        cert_info = None
                        if port in (443, 8443):
                            try:
                                cert_info = extract_cert_summary(fetch_tls_cert(ip, port))
                            except Exception:
                                cert_info = None

                        entry = {"state": "open", "service": service_name}
                        if cert_info:
                            entry["tls"] = cert_info
                        result["ports"][ip][port] = entry

                        scan_table.add_row(
                            f"[{SECONDARY_BLUE}]{ip}[/{SECONDARY_BLUE}]",
                            f"[{WHITE}]{port}[/{WHITE}]",
                            f"[{SECONDARY_BLUE}]{service_name}[/{SECONDARY_BLUE}]",
                            f"[{WHITE}]{_describe_cert(cert_info)}[/{WHITE}]"
                        )
                
                console.print()
                if found_open_ports:
                    console.print(Panel(
                        scan_table,
                        title=f"[{WHITE}]Port Scan Results[/{WHITE}]",
                        box=SQUARE
                    ))
                else:
                    console.print(Panel(
                        f"[{SECONDARY_BLUE}]No open ports found[/{SECONDARY_BLUE}]",
                        title=f"[{WHITE}]Port Scan Results[/{WHITE}]",
                        box=SQUARE
                    ))
            except Exception as e:
                console.print(Panel(
                    f"[{SECONDARY_BLUE}]Error during port scan: {str(e)}[/{SECONDARY_BLUE}]",
                    title=f"[{WHITE}]Error[/{WHITE}]",
                    box=SQUARE
                ))
        
        return result

    def scan(self, domain: str) -> dict:
        """Perform full scan including WHOIS, DNS, and ports"""
        result = {}
        
        # Call individual scan methods with modern styling
        whois_result = self.scan_whois(domain)
        result.update(whois_result)
        
        dns_result = self.scan_dns(domain)
        result.update(dns_result)
        
        if not self.no_scan_ports:
            ports_result = self.scan_ports(domain)
            result.update(ports_result)
        
        # Gather IPs from A and AAAA records before the passive recon phase
        result.setdefault("dns", {"records": {}})
        ips = set()
        for rec in ["A", "AAAA"]:
            ips.update(result["dns"].get("records", {}).get(rec, []))

        # Start with reverse DNS lookups
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task(f"[{PRIMARY_BLUE}]Performing reverse DNS lookups[/{PRIMARY_BLUE}]")
            rev = {}
            for ip in ips:
                try:
                    rev[ip] = socket.gethostbyaddr(ip)[0]
                except Exception:
                    rev[ip] = None
            result["dns"]["reverse"] = rev
            progress.update(task, completed=100)

        # Check DNSSEC
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task(f"[{PRIMARY_BLUE}]Checking DNSSEC[/{PRIMARY_BLUE}]")
            dnssec_present = bool(result["dns"].get("records", {}).get("DS") or
                                  result["dns"].get("records", {}).get("DNSKEY"))
            result["dns"]["dnssec_present"] = dnssec_present
            progress.update(task, completed=100)

        # Zone transfers if enabled
        if not self.no_axfr:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=console,
                transient=True
            ) as progress:
                task = progress.add_task(f"[{PRIMARY_BLUE}]Checking zone transfers[/{PRIMARY_BLUE}]")
                axfr_findings = []
                nameservers = result["dns"].get("records", {}).get("NS", []) or []

                for i, ns in enumerate(nameservers):
                    progress.update(task, completed=(i / len(nameservers)) * 100)
                    host = ns.split()[0].strip(".") if " " in ns else ns.strip(".")
                    ok, out = self._try_axfr(host, domain)
                    if ok:
                        axfr_findings.append({"ns": host, "lines": out.splitlines()[:200]})

                result["dns"]["axfr"] = axfr_findings
                progress.update(task, completed=100)

        # Enumerate subdomains
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task(f"[{PRIMARY_BLUE}]Enumerating subdomains[/{PRIMARY_BLUE}]")
            subdomains = self._enum_crtsh(domain)

            if self.wordlist:
                progress.update(task, description=f"[{PRIMARY_BLUE}]Bruteforcing subdomains[/{PRIMARY_BLUE}]")
                resolver = dns.resolver.Resolver()
                if self.dns_server:
                    resolver.nameservers = [self.dns_server]
                subs = self._brute_subdomains(domain, self.wordlist, resolver)
                subdomains.extend(subs)

            result["subdomains"] = sorted(set(subdomains))
            progress.update(task, completed=100)

        # GeoIP lookup
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task(f"[{PRIMARY_BLUE}]Looking up GeoIP information[/{PRIMARY_BLUE}]")

            geo = {}
            for i, ip in enumerate(ips):
                progress.update(task, completed=(i / len(ips)) * 100)
                g = self._geoip(ip)
                if g:
                    geo[ip] = g

            result["geoip"] = geo
            progress.update(task, completed=100)

        # HTTP and TLS checks
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task(f"[{PRIMARY_BLUE}]Checking HTTP and TLS[/{PRIMARY_BLUE}]")

            try:
                cert = fetch_tls_cert(domain, 443, timeout=8)
                result["tls"] = extract_cert_summary(cert)
            except Exception:
                result["tls"] = {}

            progress.update(task, description=f"[{PRIMARY_BLUE}]Fingerprinting HTTP servers[/{PRIMARY_BLUE}]")
            result["http"] = self._http_fingerprint(domain)

            progress.update(task, completed=100)

        # Summarize only once every section above has populated the result
        result["summary"] = {
            "a_records": len(result["dns"].get("records", {}).get("A", []) or []),
            "subdomains": len(result.get("subdomains", [])),
            "dnssec": result["dns"].get("dnssec_present", False),
            "open_services": sum(len(p) for p in result.get("ports", {}).values()),
            "whois_registrar": (result.get("whois", {}) or {}).get("registrar"),
        }

        console.print()
        console.print(Panel(
            "\n".join([
                f"[{SECONDARY_BLUE}]A Records:[/{SECONDARY_BLUE}] [{WHITE}]{result['summary']['a_records']}[/{WHITE}]",
                f"[{SECONDARY_BLUE}]Subdomains:[/{SECONDARY_BLUE}] [{WHITE}]{result['summary']['subdomains']}[/{WHITE}]",
                f"[{SECONDARY_BLUE}]DNSSEC:[/{SECONDARY_BLUE}] [{WHITE}]{'Enabled' if result['summary']['dnssec'] else 'Disabled'}[/{WHITE}]",
                f"[{SECONDARY_BLUE}]Open Services:[/{SECONDARY_BLUE}] [{WHITE}]{result['summary']['open_services']}[/{WHITE}]",
                f"[{SECONDARY_BLUE}]Registrar:[/{SECONDARY_BLUE}] [{WHITE}]{result['summary']['whois_registrar'] or 'Unknown'}[/{WHITE}]"
            ]),
            title=f"[{WHITE}]Domain Scan Summary[/{WHITE}]",
            box=SQUARE
        ))

        return result

    def _safe(self, v):
        if v is None:
            return None
        if isinstance(v, (list, tuple, set)):
            # Filter out None values and convert remaining to strings
            return [str(x) for x in v if x is not None]
        # Handle date objects by getting just the date part
        if hasattr(v, 'strftime'):
            return v.strftime('%Y-%m-%d')
        return str(v)

    def _dig(self, domain: str, rr: str) -> List[str]:
        if not which("dig"):
            return []
        cmd = ["dig", "+short", rr, domain]
        if self.dns_server:
            cmd = ["dig", f"@{self.dns_server}", rr, domain, "+short"]
        code, out, _ = run_cmd(cmd)
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        return lines

    def _dns_query(self, resolver: dns.resolver.Resolver, domain: str, rr: str) -> List[str]:
        try:
            answers = resolver.resolve(domain, rr, lifetime=self.timeout)
            vals = []
            for r in answers:
                vals.append(r.to_text())
            return vals
        except Exception:
            return []

    def _try_axfr(self, ns_host: str, domain: str):
        if not which("dig"):
            return False, ""
        cmd = ["dig", f"@{ns_host}", domain, "AXFR", "+time=5", "+tries=1"]
        code, out, err = run_cmd(cmd)
        if code == 0 and out and "XFR size" in out:
            return True, out
        return False, out or err

    def _enum_crtsh(self, domain: str) -> List[str]:
        try:
            url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
            r = rate_limited_get(url, crtsh_limiter, timeout=self.timeout)
            if r is None or r.status_code != 200:
                return []
            data = r.json()
            subs = []
            for e in data:
                name = e.get("name_value", "")
                for part in name.split("\n"):
                    part = part.strip().lstrip("*.")
                    if part.endswith(domain):
                        subs.append(part)
            return subs
        except Exception:
            return []

    def _brute_subdomains(self, domain: str, wordlist_path: str, resolver: dns.resolver.Resolver) -> List[str]:
        subs = []
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                words = [w.strip() for w in f if w.strip()]
            with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
                futures = {ex.submit(self._resolve_sub, resolver, f"{w}.{domain}"): w for w in words}
                for fut in concurrent.futures.as_completed(futures):
                    val = fut.result()
                    if val:
                        subs.append(val)
        except Exception:
            pass
        return subs

    def _resolve_sub(self, resolver: dns.resolver.Resolver, fqdn: str) -> Optional[str]:
        try:
            resolver.resolve(fqdn, "A", lifetime=min(self.timeout, 5))
            return fqdn
        except Exception:
            return None

    def _geoip(self, ip: str) -> Optional[dict]:
        try:
            r = rate_limited_get(f"https://ipapi.co/{quote(ip)}/json/", geoip_limiter, timeout=8)
            if r is not None and r.status_code == 200:
                data = r.json()
                return {
                    "ip": ip,
                    "country": data.get("country_name"),
                    "city": data.get("city"),
                    "asn": data.get("asn"),
                    "org": data.get("org"),
                    "latitude": data.get("latitude"),
                    "longitude": data.get("longitude"),
                }
        except Exception:
            return None
        return None

    def _http_fingerprint(self, domain: str) -> dict:
        out = {"http": {}, "https": {}}
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task(f"[{PRIMARY_BLUE}]Checking HTTP[/{PRIMARY_BLUE}]", total=2)
            
            try:
                progress.update(task, description=f"[{PRIMARY_BLUE}]Testing HTTP connection[/{PRIMARY_BLUE}]")
                r = requests.get(f"http://{domain}", timeout=6, allow_redirects=True)
                out["http"] = {
                    "status": r.status_code,
                    "final_url": r.url,
                    "server": r.headers.get("Server"),
                    "powered_by": r.headers.get("X-Powered-By"),
                }
                
                # Display HTTP info
                http_table = Table(box=SQUARE)
                http_table.add_column(f"[{PRIMARY_BLUE}]Field[/{PRIMARY_BLUE}]")
                http_table.add_column(f"[{PRIMARY_BLUE}]Value[/{PRIMARY_BLUE}]")
                
                http_table.add_row(f"[{SECONDARY_BLUE}]Status[/{SECONDARY_BLUE}]", f"[{WHITE}]{r.status_code}[/{WHITE}]")
                http_table.add_row(f"[{SECONDARY_BLUE}]URL[/{SECONDARY_BLUE}]", f"[{WHITE}]{r.url}[/{WHITE}]")
                if r.headers.get("Server"):
                    http_table.add_row(f"[{SECONDARY_BLUE}]Server[/{SECONDARY_BLUE}]", f"[{WHITE}]{r.headers['Server']}[/{WHITE}]")
                if r.headers.get("X-Powered-By"):
                    http_table.add_row(f"[{SECONDARY_BLUE}]Powered By[/{SECONDARY_BLUE}]", f"[{WHITE}]{r.headers['X-Powered-By']}[/{WHITE}]")
                
                console.print()
                console.print(Panel(http_table, title=f"[{WHITE}]HTTP Server Information[/{WHITE}]", box=SQUARE))
                
            except Exception:
                pass
            
            progress.update(task, advance=1, description=f"[{PRIMARY_BLUE}]Testing HTTPS connection[/{PRIMARY_BLUE}]")
            
            try:
                r = requests.get(f"https://{domain}", timeout=8, allow_redirects=True)
                out["https"] = {
                    "status": r.status_code,
                    "final_url": r.url,
                    "server": r.headers.get("Server"),
                    "powered_by": r.headers.get("X-Powered-By"),
                }
                
                # Display HTTPS info
                https_table = Table(box=SQUARE)
                https_table.add_column(f"[{PRIMARY_BLUE}]Field[/{PRIMARY_BLUE}]")
                https_table.add_column(f"[{PRIMARY_BLUE}]Value[/{PRIMARY_BLUE}]")
                
                https_table.add_row(f"[{SECONDARY_BLUE}]Status[/{SECONDARY_BLUE}]", f"[{WHITE}]{r.status_code}[/{WHITE}]")
                https_table.add_row(f"[{SECONDARY_BLUE}]URL[/{SECONDARY_BLUE}]", f"[{WHITE}]{r.url}[/{WHITE}]")
                if r.headers.get("Server"):
                    https_table.add_row(f"[{SECONDARY_BLUE}]Server[/{SECONDARY_BLUE}]", f"[{WHITE}]{r.headers['Server']}[/{WHITE}]")
                if r.headers.get("X-Powered-By"):
                    https_table.add_row(f"[{SECONDARY_BLUE}]Powered By[/{SECONDARY_BLUE}]", f"[{WHITE}]{r.headers['X-Powered-By']}[/{WHITE}]")
                
                console.print()
                console.print(Panel(https_table, title=f"[{WHITE}]HTTPS Server Information[/{WHITE}]", box=SQUARE))
                
            except Exception:
                pass
            
            progress.update(task, completed=100)
        
        return out
