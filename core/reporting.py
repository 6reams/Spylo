import csv
import json
from pathlib import Path
from typing import Iterable

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from core.validation import safe_filename

console = Console()

SUPPORTED_FORMATS = ("table", "json", "csv", "md")


def report_basename(meta: dict) -> str:
    """Build the filename stem for a report.

    Includes the scan type and timestamp so repeat scans of one target
    accumulate instead of overwriting each other.
    """
    parts = [
        safe_filename(meta.get("module", "scan"), "scan"),
        safe_filename(meta.get("target", "target")),
    ]
    scan_type = meta.get("scan_type")
    if scan_type and scan_type != meta.get("module"):
        parts.append(safe_filename(scan_type, "scan"))
    timestamp = meta.get("timestamp_utc")
    if timestamp:
        parts.append(safe_filename(timestamp, "ts"))
    return "_".join(parts)


def save_reports(meta: dict, result: dict, out_dir: str, formats: Iterable[str]) -> list[str]:
    """Write `result` in each requested format. Returns the paths written."""
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    base = out_path / report_basename(meta)
    payload = {"meta": meta, "result": result}
    formats = [f.strip().lower() for f in formats if str(f).strip()]
    written = []

    if "json" in formats:
        json_path = str(base) + ".json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False, default=str)
        written.append(json_path)
    if "csv" in formats:
        csv_path = str(base) + ".csv"
        _save_csv(result, csv_path)
        written.append(csv_path)
    if "md" in formats:
        md_path = str(base) + ".md"
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(render_markdown(meta, result))
        written.append(md_path)

    return written


def _save_csv(result: dict, path: str):
    """Flatten the result into rows.

    Sections have different shapes, so each row carries a `kind` column
    naming the section it came from.
    """
    rows = []
    for account in result.get("accounts") or []:
        rows.append({
            "kind": "account",
            "name": account.get("site"),
            "value": account.get("url"),
            "detail": account.get("status"),
        })
    for rtype, values in (result.get("dns") or {}).get("records", {}).items():
        for value in values:
            rows.append({"kind": "dns", "name": rtype, "value": value})
    for ip, ports in (result.get("ports") or {}).items():
        for port, info in ports.items():
            rows.append({
                "kind": "port",
                "name": ip,
                "value": port,
                "detail": (info or {}).get("service"),
            })
    for sub in result.get("subdomains") or []:
        rows.append({"kind": "subdomain", "value": sub})
    for ip, geo in (result.get("geoip") or {}).items():
        rows.append({
            "kind": "geoip",
            "name": ip,
            "value": (geo or {}).get("country"),
            "detail": (geo or {}).get("org"),
        })

    fieldnames = ["kind", "name", "value", "detail"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def render_markdown(meta: dict, result: dict) -> str:
    module = meta.get("module", "scan")
    target = meta.get("target", "unknown")
    md = [f"# OSINT Report — {module} :: {target}", ""]

    md.append("## Metadata")
    for k, v in meta.items():
        md.append(f"- **{k}**: {v}")
    md.append("")

    if result.get("error"):
        md.append("## Error")
        md.append(f"- {result['error']}")
        md.append("")
    if result.get("summary"):
        md.append("## Summary")
        for k, v in result["summary"].items():
            md.append(f"- **{k}**: {v}")
        md.append("")
    if result.get("accounts"):
        md.append("## Accounts Found")
        for a in result["accounts"]:
            md.append(f"- {a.get('site')}: {a.get('url')}")
        md.append("")
    if (result.get("dns") or {}).get("records"):
        md.append("## DNS Records")
        for rtype, vals in result["dns"]["records"].items():
            md.append(f"### {rtype}")
            for v in vals:
                md.append(f"- {v}")
        md.append("")
    if result.get("whois"):
        md.append("## WHOIS")
        for k, v in result["whois"].items():
            md.append(f"- **{k}**: {v}")
        md.append("")
    if result.get("ports"):
        md.append("## Open Ports")
        for ip, ports in result["ports"].items():
            if not ports:
                continue
            md.append(f"### {ip}")
            for port, info in ports.items():
                service = (info or {}).get("service", "unknown")
                md.append(f"- {port}: {service}")
        md.append("")
    if result.get("subdomains"):
        md.append("## Subdomains")
        for s in result["subdomains"]:
            md.append(f"- {s}")
        md.append("")
    if result.get("geoip"):
        md.append("## GeoIP")
        for ip, geo in result["geoip"].items():
            geo = geo or {}
            md.append(f"- **{ip}**: {geo.get('city')}, {geo.get('country')} ({geo.get('org')})")
        md.append("")
    if result.get("tls"):
        md.append("## TLS Certificate")
        for k, v in result["tls"].items():
            md.append(f"- **{k}**: {v}")
        md.append("")

    return "\n".join(md)


def print_table_summary(meta: dict, result: dict):
    module = meta.get("module")
    target = meta.get("target", "unknown")

    if module == "username":
        _print_username_summary(target, result)
    elif module == "domain":
        _print_domain_summary(target, result)


def _print_username_summary(target: str, result: dict):
    found = result.get("accounts") or []
    if not found:
        console.print(Panel(
            "[bold red]No accounts found for this username![/bold red]",
            border_style="red",
            title="❌ Results"
        ))
        return

    tbl = Table(
        title=f"[bold yellow]Username Results for [cyan]{target}[/cyan][/bold yellow]",
        show_header=True,
        header_style="bold green",
        border_style="blue",
        expand=True
    )
    tbl.add_column("🌐 Site", style="cyan")
    tbl.add_column("🔗 URL", style="magenta")
    for r in found:
        tbl.add_row(
            f"[bold]{r.get('site', '')}[/bold]",
            f"[link]{r.get('url', '')}[/link]"
        )
    console.print(Panel(tbl, border_style="green", title="✅ Found Accounts"))


def _print_domain_summary(target: str, result: dict):
    summary = result.get("summary") or {}
    if not summary:
        return

    tbl = Table(
        title=f"[bold yellow]Domain Analysis for [cyan]{target}[/cyan][/bold yellow]",
        show_header=True,
        header_style="bold green",
        border_style="blue",
        expand=True
    )
    tbl.add_column("📊 Metric", style="cyan")
    tbl.add_column("📈 Value", style="magenta")

    if summary.get("a_records") is not None:
        tbl.add_row("DNS Records", f"[green]✓[/green] {summary['a_records']} A records found")
    if summary.get("subdomains") is not None:
        tbl.add_row("Subdomains", f"[green]✓[/green] {summary['subdomains']} subdomains discovered")
    if "dnssec" in summary:
        tbl.add_row("DNSSEC", "[green]✓[/green] Enabled" if summary["dnssec"] else "[red]✗[/red] Disabled")
    if summary.get("open_services") is not None:
        tbl.add_row("Open Services", f"[yellow]⚠[/yellow] {summary['open_services']} services detected")
    if summary.get("whois_registrar"):
        tbl.add_row("Registrar", f"[blue]ℹ[/blue] {summary['whois_registrar']}")

    console.print(Panel(tbl, border_style="green", title="🎯 Domain Analysis Results"))
