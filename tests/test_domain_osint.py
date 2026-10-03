
import pytest

from core.validation import ValidationError
from modules import domain_osint
from modules.domain_osint import DEFAULT_TOP_PORTS, DomainScanner


def test_default_port_list_has_no_duplicates():
    raw = [p for p in DEFAULT_TOP_PORTS.split(",") if p]
    assert len(raw) == len(set(raw))


def test_scanner_parses_and_dedups_ports():
    scanner = DomainScanner(top_ports="443,80,443,22")
    assert scanner.ports == [22, 80, 443]


def test_scanner_rejects_bad_ports():
    with pytest.raises(ValidationError):
        DomainScanner(top_ports="80,not-a-port")


def test_scanner_rejects_non_ip_dns_server():
    with pytest.raises(ValidationError):
        DomainScanner(dns_server="dns.google")


def test_scanner_accepts_ip_dns_server():
    assert DomainScanner(dns_server=" 8.8.8.8 ").dns_server == "8.8.8.8"


def test_scanner_allows_no_dns_server():
    assert DomainScanner().dns_server is None


@pytest.fixture
def recon_scanner(monkeypatch):
    """A scanner with every network call replaced by a counting stub."""
    scanner = DomainScanner(no_axfr=True, no_scan_ports=True, wordlist=None)
    calls = {"crtsh": 0, "geoip": [], "http": 0, "tls": 0, "reverse": []}

    monkeypatch.setattr(scanner, "scan_whois", lambda d: {"whois": {"registrar": "ACME"}})
    monkeypatch.setattr(scanner, "scan_dns", lambda d: {
        "dns": {"records": {"A": ["1.2.3.4"], "AAAA": ["2001:db8::1"], "NS": ["ns1.example.com."]}}
    })

    def fake_crtsh(domain):
        calls["crtsh"] += 1
        return ["www.example.com"]

    def fake_geoip(ip):
        calls["geoip"].append(ip)
        return {"ip": ip, "country": "Ireland"}

    def fake_http(domain):
        calls["http"] += 1
        return {"http": {"status": 200}, "https": {"status": 200}}

    def fake_cert(host, port=443, timeout=8):
        calls["tls"] += 1
        return {"notAfter": "Jan 1 00:00:00 2027 GMT"}

    def fake_reverse(ip):
        calls["reverse"].append(ip)
        return ("host.example.com", [], [ip])

    monkeypatch.setattr(scanner, "_enum_crtsh", fake_crtsh)
    monkeypatch.setattr(scanner, "_geoip", fake_geoip)
    monkeypatch.setattr(scanner, "_http_fingerprint", fake_http)
    monkeypatch.setattr(domain_osint, "fetch_tls_cert", fake_cert)
    monkeypatch.setattr(domain_osint, "extract_cert_summary", lambda c: c or {})
    monkeypatch.setattr(domain_osint.socket, "gethostbyaddr", fake_reverse)

    return scanner, calls


# Regression: the recon phase was indented inside the `for rec in ["A","AAAA"]`
# loop, so every passive lookup (crt.sh, GeoIP, HTTP, TLS) ran twice per scan.
def test_recon_phase_runs_exactly_once(recon_scanner):
    scanner, calls = recon_scanner
    scanner.scan("example.com")

    assert calls["crtsh"] == 1
    assert calls["http"] == 1
    assert calls["tls"] == 1


def test_each_ip_is_looked_up_once(recon_scanner):
    scanner, calls = recon_scanner
    scanner.scan("example.com")

    assert sorted(calls["geoip"]) == ["1.2.3.4", "2001:db8::1"]
    assert sorted(calls["reverse"]) == ["1.2.3.4", "2001:db8::1"]


# Regression: the summary was computed before subdomains and DNSSEC were
# gathered, so it always reported 0 subdomains and DNSSEC disabled.
def test_summary_reflects_data_gathered_during_the_scan(recon_scanner):
    scanner, _ = recon_scanner
    result = scanner.scan("example.com")

    assert result["summary"]["subdomains"] == 1
    assert result["summary"]["subdomains"] == len(result["subdomains"])
    assert result["summary"]["a_records"] == 1
    assert result["summary"]["whois_registrar"] == "ACME"


def test_summary_reports_dnssec_when_present(monkeypatch, recon_scanner):
    scanner, _ = recon_scanner
    monkeypatch.setattr(scanner, "scan_dns", lambda d: {
        "dns": {"records": {"A": ["1.2.3.4"], "DS": ["12345 13 2 ABCD"]}}
    })

    result = scanner.scan("example.com")
    assert result["dns"]["dnssec_present"] is True
    assert result["summary"]["dnssec"] is True


def test_scan_populates_every_section(recon_scanner):
    scanner, _ = recon_scanner
    result = scanner.scan("example.com")

    for key in ("whois", "dns", "subdomains", "geoip", "tls", "http", "summary"):
        assert key in result
    assert result["dns"]["reverse"]["1.2.3.4"] == "host.example.com"


def test_scan_skips_axfr_when_disabled(recon_scanner, monkeypatch):
    scanner, _ = recon_scanner

    def unexpected(*args, **kwargs):
        raise AssertionError("AXFR should be skipped")

    monkeypatch.setattr(scanner, "_try_axfr", unexpected)
    scanner.scan("example.com")


def test_scan_attempts_axfr_per_nameserver(recon_scanner, monkeypatch):
    scanner, _ = recon_scanner
    scanner.no_axfr = False
    attempted = []

    monkeypatch.setattr(scanner, "scan_dns", lambda d: {
        "dns": {"records": {"A": ["1.2.3.4"], "NS": ["ns1.example.com.", "ns2.example.com."]}}
    })
    monkeypatch.setattr(scanner, "_try_axfr", lambda ns, dom: (attempted.append(ns), (False, ""))[1])

    result = scanner.scan("example.com")
    assert attempted == ["ns1.example.com", "ns2.example.com"]
    assert result["dns"]["axfr"] == []


def test_scan_survives_domain_with_no_ips(recon_scanner, monkeypatch):
    scanner, calls = recon_scanner
    monkeypatch.setattr(scanner, "scan_dns", lambda d: {"dns": {"records": {}}})

    result = scanner.scan("example.com")
    assert result["geoip"] == {}
    assert result["dns"]["reverse"] == {}
    assert result["summary"]["a_records"] == 0
    assert calls["geoip"] == []


def test_enum_crtsh_parses_names(monkeypatch):
    scanner = DomainScanner()

    class FakeResponse:
        status_code = 200

        @staticmethod
        def json():
            return [
                {"name_value": "*.example.com\nwww.example.com"},
                {"name_value": "api.example.com"},
                {"name_value": "other.test"},
            ]

    monkeypatch.setattr(domain_osint, "rate_limited_get", lambda url, limiter, **kw: FakeResponse())
    subs = scanner._enum_crtsh("example.com")
    assert sorted(set(subs)) == ["api.example.com", "example.com", "www.example.com"]


def test_enum_crtsh_is_rate_limited(monkeypatch):
    scanner = DomainScanner()
    used = {}

    def fake_get(url, limiter, **kwargs):
        used["limiter"] = limiter
        used["url"] = url
        return None

    monkeypatch.setattr(domain_osint, "rate_limited_get", fake_get)
    assert scanner._enum_crtsh("example.com") == []
    assert used["limiter"] is domain_osint.crtsh_limiter


def test_geoip_is_rate_limited(monkeypatch):
    scanner = DomainScanner()
    used = {}

    class FakeResponse:
        status_code = 200

        @staticmethod
        def json():
            return {"country_name": "Ireland", "city": "Dublin", "org": "ACME", "asn": "AS1"}

    def fake_get(url, limiter, **kwargs):
        used["limiter"] = limiter
        return FakeResponse()

    monkeypatch.setattr(domain_osint, "rate_limited_get", fake_get)
    geo = scanner._geoip("1.2.3.4")
    assert used["limiter"] is domain_osint.geoip_limiter
    assert geo["country"] == "Ireland"


def test_geoip_returns_none_when_throttled(monkeypatch):
    scanner = DomainScanner()
    monkeypatch.setattr(domain_osint, "rate_limited_get", lambda *a, **kw: None)
    assert scanner._geoip("1.2.3.4") is None


def test_dead_helpers_are_gone():
    for name in ("_scan_ports", "_extract_version_info", "_extract_http_server"):
        assert not hasattr(DomainScanner, name)


@pytest.mark.parametrize("banner,expected", [
    (None, ""),
    ("", ""),
    ("   ", ""),
    ("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n", "HTTP/1.1 200 OK"),
    ("SSH-2.0-OpenSSH_9.0\n", "SSH-2.0-OpenSSH_9.0"),
])
def test_first_line_condenses_banners(banner, expected):
    assert domain_osint._first_line(banner) == expected


def test_first_line_truncates():
    assert len(domain_osint._first_line("x" * 500)) == 80


@pytest.mark.parametrize("cert,expected", [
    (None, ""),
    ({}, ""),
    ({"notAfter": "Jan 1 2027"}, "cert expires Jan 1 2027"),
    ({"subject": "x"}, "cert present"),
])
def test_describe_cert(cert, expected):
    assert domain_osint._describe_cert(cert) == expected


class FakeSocket:
    def __init__(self, open_ports):
        self.open_ports = open_ports

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def settimeout(self, timeout):
        pass

    def connect_ex(self, address):
        return 0 if address[1] in self.open_ports else 1


@pytest.fixture
def port_scanner(monkeypatch):
    """A scanner whose sockets and DNS are stubbed; caller sets open ports."""
    open_ports = {443}

    class FakeResolver:
        nameservers = []

        def resolve(self, domain, rr, lifetime=None):
            if rr == "A":
                return ["1.2.3.4"]
            raise RuntimeError("no record")

    monkeypatch.setattr(domain_osint.dns.resolver, "Resolver", FakeResolver)
    monkeypatch.setattr(domain_osint.socket, "socket", lambda *a, **kw: FakeSocket(open_ports))
    monkeypatch.setattr(domain_osint, "grab_banner", lambda ip, port, timeout: "SSH-2.0-OpenSSH_9.0\r\n")
    return open_ports


# Regression: a cert fetch that raised propagated to the per-port `except`,
# dropping an open port that had already been confirmed.
def test_open_port_survives_a_failing_cert_fetch(port_scanner, monkeypatch):
    def boom(*args, **kwargs):
        raise OSError("certificate verify failed")

    monkeypatch.setattr(domain_osint, "fetch_tls_cert", boom)

    scanner = DomainScanner(top_ports="443", timeout=1)
    result = scanner.scan_ports("example.com")

    assert 443 in result["ports"]["1.2.3.4"]
    assert result["ports"]["1.2.3.4"][443]["state"] == "open"
    assert "tls" not in result["ports"]["1.2.3.4"][443]


# Regression: extract_cert_summary returns a dict, which was passed straight
# into ' '.join(...) and raised TypeError on every successful cert fetch.
def test_open_port_with_a_cert_is_recorded(port_scanner, monkeypatch):
    monkeypatch.setattr(domain_osint, "fetch_tls_cert", lambda ip, port, **kw: {"raw": True})
    monkeypatch.setattr(domain_osint, "extract_cert_summary", lambda c: {"notAfter": "Jan 1 2027"})

    scanner = DomainScanner(top_ports="443", timeout=1)
    result = scanner.scan_ports("example.com")

    entry = result["ports"]["1.2.3.4"][443]
    assert entry["state"] == "open"
    assert entry["tls"] == {"notAfter": "Jan 1 2027"}


def test_service_is_a_single_line(port_scanner, monkeypatch):
    monkeypatch.setattr(domain_osint, "fetch_tls_cert", lambda *a, **kw: None)
    scanner = DomainScanner(top_ports="22", timeout=1)
    port_scanner.clear()
    port_scanner.add(22)

    entry = scanner.scan_ports("example.com")["ports"]["1.2.3.4"][22]
    assert entry["service"] == "SSH-2.0-OpenSSH_9.0"
    assert "\n" not in entry["service"]


def test_closed_ports_are_not_recorded(port_scanner, monkeypatch):
    monkeypatch.setattr(domain_osint, "fetch_tls_cert", lambda *a, **kw: None)
    scanner = DomainScanner(top_ports="22,443,8080", timeout=1)

    result = scanner.scan_ports("example.com")
    assert sorted(result["ports"]["1.2.3.4"]) == [443]


def test_unresolvable_domain_yields_no_ports(monkeypatch):
    class DeadResolver:
        nameservers = []

        def resolve(self, domain, rr, lifetime=None):
            raise RuntimeError("nxdomain")

    monkeypatch.setattr(domain_osint.dns.resolver, "Resolver", DeadResolver)
    scanner = DomainScanner(top_ports="443", timeout=1)
    assert scanner.scan_ports("nope.example") == {"ports": {}}
