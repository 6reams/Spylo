import csv
import datetime
import json
from pathlib import Path

import pytest

from core.reporting import (
    print_table_summary,
    render_markdown,
    report_basename,
    save_reports,
)

DOMAIN_META = {
    "tool": "spylo",
    "module": "domain",
    "alias": "site1",
    "target": "example.com",
    "scan_type": "all",
    "timestamp_utc": "20260101T000000Z",
}

DOMAIN_RESULT = {
    "whois": {"registrar": "Example Registrar"},
    "dns": {"records": {"A": ["1.2.3.4"], "NS": ["ns1.example.com."]}, "dnssec_present": True},
    "ports": {"1.2.3.4": {443: {"state": "open", "service": "nginx"}}},
    "subdomains": ["www.example.com", "api.example.com"],
    "geoip": {"1.2.3.4": {"country": "Ireland", "city": "Dublin", "org": "ACME"}},
    "tls": {"notAfter": "Jan 1 00:00:00 2027 GMT"},
    "summary": {
        "a_records": 1,
        "subdomains": 2,
        "dnssec": True,
        "open_services": 1,
        "whois_registrar": "Example Registrar",
    },
}

USERNAME_META = {
    "module": "username",
    "alias": "user1",
    "target": "john_doe",
    "scan_type": "username",
    "timestamp_utc": "20260101T000000Z",
}

USERNAME_RESULT = {
    "accounts": [{"site": "GitHub", "url": "https://github.com/john_doe", "status": "FOUND"}],
    "summary": {"username": "john_doe", "found": 1},
}


def test_report_basename_includes_scan_type_and_timestamp():
    assert report_basename(DOMAIN_META) == "domain_example.com_all_20260101T000000Z"


def test_report_basename_omits_redundant_scan_type():
    assert report_basename(USERNAME_META) == "username_john_doe_20260101T000000Z"


def test_report_basename_tolerates_missing_keys():
    assert report_basename({}) == "scan_target"


def test_report_basename_strips_path_traversal():
    meta = {"module": "domain", "target": "../../etc/passwd", "scan_type": "all"}
    base = report_basename(meta)
    assert "/" not in base and ".." not in base


def test_save_reports_writes_inside_out_dir_for_hostile_target(tmp_path):
    meta = dict(DOMAIN_META, target="../../escaped")
    written = save_reports(meta, DOMAIN_RESULT, str(tmp_path), ["json"])
    assert len(written) == 1
    assert tmp_path in Path(written[0]).resolve().parents


def test_save_reports_all_formats(tmp_path):
    written = save_reports(DOMAIN_META, DOMAIN_RESULT, str(tmp_path), ["table", "json", "csv", "md"])
    suffixes = sorted(p.rsplit(".", 1)[1] for p in written)
    assert suffixes == ["csv", "json", "md"]
    for path in written:
        assert Path(path).is_file()


def test_save_reports_table_only_writes_nothing(tmp_path):
    assert save_reports(DOMAIN_META, DOMAIN_RESULT, str(tmp_path), ["table"]) == []
    assert list(tmp_path.iterdir()) == []


def test_save_reports_creates_missing_out_dir(tmp_path):
    target = tmp_path / "nested" / "deeper"
    written = save_reports(DOMAIN_META, DOMAIN_RESULT, str(target), ["json"])
    assert written and target.is_dir()


def test_save_reports_json_roundtrips(tmp_path):
    written = save_reports(DOMAIN_META, DOMAIN_RESULT, str(tmp_path), ["json"])
    payload = json.loads(Path(written[0]).read_text())
    assert payload["meta"]["module"] == "domain"
    assert payload["meta"]["target"] == "example.com"
    assert payload["result"]["summary"]["subdomains"] == 2


def test_save_reports_json_handles_non_serializable(tmp_path):
    result = {"whois": {"creation_date": datetime.date(2020, 1, 1)}}
    written = save_reports(DOMAIN_META, result, str(tmp_path), ["json"])
    payload = json.loads(Path(written[0]).read_text())
    assert payload["result"]["whois"]["creation_date"] == "2020-01-01"


def test_csv_has_header_and_rows(tmp_path):
    written = save_reports(DOMAIN_META, DOMAIN_RESULT, str(tmp_path), ["csv"])
    with open(written[0], newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    kinds = {r["kind"] for r in rows}
    assert kinds == {"dns", "port", "subdomain", "geoip"}
    port_row = next(r for r in rows if r["kind"] == "port")
    assert port_row["name"] == "1.2.3.4"
    assert port_row["value"] == "443"
    assert port_row["detail"] == "nginx"


def test_csv_writes_header_for_empty_result(tmp_path):
    written = save_reports(USERNAME_META, {}, str(tmp_path), ["csv"])
    content = Path(written[0]).read_text()
    assert content.strip() == "kind,name,value,detail"


def test_csv_includes_accounts(tmp_path):
    written = save_reports(USERNAME_META, USERNAME_RESULT, str(tmp_path), ["csv"])
    with open(written[0], newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert rows[0]["kind"] == "account"
    assert rows[0]["name"] == "GitHub"


def test_render_markdown_includes_sections():
    md = render_markdown(DOMAIN_META, DOMAIN_RESULT)
    for heading in ["## Metadata", "## Summary", "## DNS Records", "## WHOIS",
                    "## Open Ports", "## Subdomains", "## GeoIP", "## TLS Certificate"]:
        assert heading in md
    assert "example.com" in md


def test_render_markdown_tolerates_empty_result():
    md = render_markdown({"module": "domain", "target": "example.com"}, {})
    assert md.startswith("# OSINT Report — domain :: example.com")


def test_render_markdown_reports_errors():
    md = render_markdown(USERNAME_META, {"error": "boom", "accounts": []})
    assert "## Error" in md and "boom" in md


# Regression: both helpers used to read meta['module'] while the shell only
# supplied 'scan_type', so every scan raised KeyError.
@pytest.mark.parametrize("meta", [
    DOMAIN_META,
    USERNAME_META,
    {"target": "example.com", "scan_type": "all"},
    {},
])
def test_print_table_summary_never_raises(meta):
    print_table_summary(meta, DOMAIN_RESULT)
    print_table_summary(meta, USERNAME_RESULT)
    print_table_summary(meta, {})


def test_save_reports_does_not_need_module_key(tmp_path):
    meta = {"target": "example.com", "scan_type": "dns", "timestamp_utc": "20260101T000000Z"}
    written = save_reports(meta, DOMAIN_RESULT, str(tmp_path), ["json", "csv", "md"])
    assert len(written) == 3
