import cmd
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.box import ROUNDED, SQUARE

# Modern minimal color scheme
PRIMARY_BLUE = "#0066cc"
SECONDARY_BLUE = "#4d94ff"
WHITE = "#ffffff"

from modules.username_osint import UsernameScanner
from modules.domain_osint import DomainScanner, DEFAULT_TOP_PORTS
from modules.email_osint import EmailScanner
from core.reporting import save_reports, print_table_summary, SUPPORTED_FORMATS
from core.utils import ensure_dir
from core.validation import (
    ValidationError,
    parse_ports,
    validate_alias,
    validate_dns_server,
    validate_target,
)

console = Console()

VERSION = "0.1.0"
DOMAIN_SCAN_TYPES = ("all", "dns", "ports", "whois")
EMAIL_SCAN_TYPES = ("all", "dns", "gravatar", "platforms", "breaches")
TARGET_TYPES = ("domain", "username", "email")

SESSION_FILE = Path.home() / ".spylo" / "session.json"

BANNER = """
    ██████╗██████╗ ██╗   ██╗██╗      ██████╗
    ██╔════╝██╔══██╗╚██╗ ██╔╝██║     ██╔═══██╗
    ██████╗ ██████╔╝ ╚████╔╝ ██║     ██║   ██║
    ╚════██╗██╔═══╝   ╚██╔╝  ██║     ██║   ██║
    ███████║██║        ██║   ██████╗╚██████╔╝
    ╚══════╝╚═╝        ╚═╝   ╚═════╝ ╚═════╝

"""


def _parse_bool(value: str) -> bool:
    lowered = str(value).strip().lower()
    if lowered in ("true", "yes", "on", "1"):
        return True
    if lowered in ("false", "no", "off", "0"):
        return False
    raise ValidationError(f"Expected a boolean (true/false), got '{value}'")


def _parse_positive_int(value: str) -> int:
    try:
        parsed = int(str(value).strip())
    except ValueError:
        raise ValidationError(f"Expected an integer, got '{value}'")
    if parsed < 1:
        raise ValidationError("Value must be at least 1")
    return parsed


def _parse_formats(value: str) -> str:
    formats = [f.strip().lower() for f in str(value).split(",") if f.strip()]
    if not formats:
        raise ValidationError("At least one output format is required")
    unknown = [f for f in formats if f not in SUPPORTED_FORMATS]
    if unknown:
        raise ValidationError(
            f"Unknown format(s): {', '.join(unknown)}. Supported: {', '.join(SUPPORTED_FORMATS)}"
        )
    return ",".join(dict.fromkeys(formats))


def _parse_optional_path(value: str) -> Optional[str]:
    text = str(value).strip()
    if not text or text.lower() in ("none", "null", ""):
        return None
    if not Path(text).is_file():
        raise ValidationError(f"File not found: {text}")
    return text


def _parse_optional_str(value: str) -> Optional[str]:
    text = str(value).strip()
    if not text or text.lower() in ("none", "null"):
        return None
    return text


def _parse_ports_setting(value: str) -> str:
    return ",".join(str(p) for p in parse_ports(value))


def _parse_dns_server(value: str) -> Optional[str]:
    if _parse_optional_str(value) is None:
        return None
    return validate_dns_server(value)


def _parse_output_dir(value: str) -> str:
    text = str(value).strip()
    if not text:
        raise ValidationError("Output directory must not be empty")
    return text


# name -> (parser, persisted, description)
SETTING_SPECS = {
    "output_dir": (_parse_output_dir, True, "Directory for saved reports"),
    "formats": (_parse_formats, True, f"Output formats ({', '.join(SUPPORTED_FORMATS)})"),
    "timeout": (_parse_positive_int, True, "Per-request timeout in seconds"),
    "retries": (_parse_positive_int, True, "Retry attempts for failed requests"),
    "concurrency": (_parse_positive_int, True, "Concurrent requests for username scans"),
    "top_ports": (_parse_ports_setting, True, "Comma-separated ports to scan"),
    "wordlist": (_parse_optional_path, True, "Subdomain bruteforce wordlist path"),
    "dns_server": (_parse_dns_server, True, "DNS server IP to query"),
    "verify_tls": (_parse_bool, True, "Verify TLS certificates (disable at your own risk)"),
    "no_axfr": (_parse_bool, True, "Skip AXFR zone-transfer attempts"),
    "no_scan_ports": (_parse_bool, True, "Skip port scanning during full scans"),
    "no_platform_probe": (_parse_bool, True, "Skip third-party platform probing in email scans"),
    # Proxy URLs can embed credentials, so this one is never written to disk.
    "proxy": (_parse_optional_str, False, "Proxy URL (not saved to disk)"),
    # HIBP key is sensitive; user must supply it per-session.
    "hibp_api_key": (_parse_optional_str, False, "HaveIBeenPwned API key (not saved to disk)"),
}

DEFAULT_SETTINGS = {
    "output_dir": "out",
    "formats": "table,json",
    "timeout": 15,
    "retries": 2,
    "concurrency": 50,
    "top_ports": DEFAULT_TOP_PORTS,
    "wordlist": None,
    "dns_server": None,
    "verify_tls": True,
    "no_axfr": False,
    "no_scan_ports": False,
    "no_platform_probe": False,
    "proxy": None,
    "hibp_api_key": None,
}


class Session:
    def __init__(self, session_file: Path = SESSION_FILE):
        self.targets = {}
        self.settings = dict(DEFAULT_SETTINGS)
        self.session_file = Path(session_file)
        self.ensure_output_dir()

    def __getattr__(self, name):
        # Settings are reachable as attributes (session.timeout) for the
        # scanner call sites, which read them by name.
        if name in DEFAULT_SETTINGS:
            return self.settings[name]
        raise AttributeError(name)

    @property
    def output_dir(self) -> str:
        return self.settings["output_dir"]

    def ensure_output_dir(self):
        Path(self.settings["output_dir"]).mkdir(parents=True, exist_ok=True)

    def formats_list(self) -> list[str]:
        return [f for f in self.settings["formats"].split(",") if f]

    def add_target(self, alias, target_type, target_value):
        self.targets[alias] = {
            "type": target_type,
            "value": target_value,
            "last_scan": None,
        }

    def set_setting(self, name: str, raw_value: str):
        if name not in SETTING_SPECS:
            raise ValidationError(f"Unknown setting '{name}'")
        parser, _, _ = SETTING_SPECS[name]
        self.settings[name] = parser(raw_value)
        if name == "output_dir":
            self.ensure_output_dir()

    def save(self) -> Optional[Path]:
        """Persist targets and settings. Returns the path, or None on failure."""
        payload = {
            "version": VERSION,
            "targets": self.targets,
            "settings": {
                name: self.settings[name]
                for name, (_, persisted, _) in SETTING_SPECS.items()
                if persisted
            },
        }
        try:
            self.session_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.session_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            os.chmod(self.session_file, 0o600)
            return self.session_file
        except OSError:
            return None

    def load(self) -> tuple[int, list[str]]:
        """Restore a saved session. Returns (targets loaded, warnings)."""
        warnings = []
        if not self.session_file.is_file():
            return 0, warnings

        try:
            with open(self.session_file, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            return 0, [f"Could not read saved session: {exc}"]

        for name, raw in (payload.get("settings") or {}).items():
            if name not in SETTING_SPECS:
                continue
            parser, persisted, _ = SETTING_SPECS[name]
            if not persisted:
                continue
            try:
                self.settings[name] = parser(raw) if raw is not None else None
            except ValidationError as exc:
                warnings.append(f"Ignored saved setting '{name}': {exc}")

        loaded = 0
        for alias, info in (payload.get("targets") or {}).items():
            if not isinstance(info, dict):
                continue
            try:
                clean_alias = validate_alias(alias)
                target_type = info.get("type")
                if target_type not in TARGET_TYPES:
                    raise ValidationError(f"unknown type '{target_type}'")
                value = validate_target(target_type, info.get("value", ""))
            except ValidationError as exc:
                warnings.append(f"Ignored saved target '{alias}': {exc}")
                continue
            self.targets[clean_alias] = {
                "type": target_type,
                "value": value,
                "last_scan": info.get("last_scan"),
            }
            loaded += 1

        self.ensure_output_dir()
        return loaded, warnings


class SPYLOShell(cmd.Cmd):
    intro = None  # Set in __init__
    prompt = "spylo> "

    def __init__(self, session: Optional[Session] = None, show_banner: bool = True):
        super().__init__()
        self.session = session or Session()
        self.console = Console()

        if show_banner:
            banner_panel = Panel(
                Text(BANNER, style="green bold"),
                border_style="white",
                padding=(1, 2),
                title="[bold cyan]SPYLO OSINT FRAMEWORK[/bold cyan]",
                box=ROUNDED
            )
            self.console.print(banner_panel)

        loaded, warnings = self.session.load()
        for warning in warnings:
            self.console.print(f"[yellow]{warning}[/yellow]")
        if loaded and show_banner:
            self.console.print(f"[green]Restored {loaded} target(s) from previous session[/green]")

        if show_banner:
            self.console.print("[bold blue]Type 'help' or '?' to list commands.[/bold blue]\n")
        self.intro = ""

    # ------------------------------------------------------------------
    # Help
    # ------------------------------------------------------------------

    def _get_command_groups(self):
        """Get organized command groups for help display"""
        return {
            "Scanning Commands": [
                ("s <alias> [module]", "Scan a target (modules: whois, dns, ports, all)"),
                ("scan <alias> [module]", "Same as 's' command")
            ],
            "Target Management": [
                ("add <alias> <type> <value>", "Add a new target (type: domain, username)"),
                ("del <alias>", "Remove a target"),
                ("list", "List all targets"),
                ("l", "Shortcut for 'list'"),
                ("reset", "Remove every target")
            ],
            "Settings": [
                ("set <option> <value>", "Set configuration option"),
                ("config", "Show current configuration"),
                ("save", "Save targets and settings now")
            ],
            "System": [
                ("clear", "Clear the screen"),
                ("c", "Shortcut for 'clear'"),
                ("exit", "Exit the program"),
                ("q", "Shortcut for 'exit'")
            ],
            "Help": [
                ("help", "Show this help message"),
                ("h", "Shortcut for 'help'")
            ]
        }

    def do_help(self, arg):
        """Show help about commands"""
        if arg:
            return super().do_help(arg)

        for group, commands in self._get_command_groups().items():
            table = Table(box=SQUARE, show_header=False)
            table.add_column(f"[{PRIMARY_BLUE}]Command[/{PRIMARY_BLUE}]")
            table.add_column(f"[{PRIMARY_BLUE}]Description[/{PRIMARY_BLUE}]")

            for name, desc in commands:
                table.add_row(
                    f"[{SECONDARY_BLUE}]{name}[/{SECONDARY_BLUE}]",
                    f"[{WHITE}]{desc}[/{WHITE}]"
                )

            self.console.print(Panel(
                table,
                title=f"[{WHITE}]{group}[/{WHITE}]",
                box=SQUARE
            ))
            self.console.print()

    def emptyline(self):
        """Do nothing on empty line"""
        pass

    def default(self, line):
        """Handle unknown commands"""
        self.console.print(f"[red]Unknown command: {line}[/red]")
        self.console.print("Type 'help' or '?' to list available commands.")

    # ------------------------------------------------------------------
    # Shortcuts
    # ------------------------------------------------------------------

    def do_h(self, arg):
        """Shortcut for help command"""
        return self.do_help(arg)

    def do_q(self, arg):
        """Shortcut for exit"""
        return self.do_exit(arg)

    def do_l(self, arg):
        """Shortcut for list"""
        return self.do_list(arg)

    def do_a(self, arg):
        """Shortcut for add"""
        return self.do_add(arg)

    def do_s(self, arg):
        """Shortcut for scan"""
        return self.do_scan(arg)

    def do_c(self, arg):
        """Shortcut for clear"""
        return self.do_clear(arg)

    def do_EOF(self, arg):
        """Exit on Ctrl-D"""
        self.console.print()
        return self.do_exit(arg)

    # ------------------------------------------------------------------
    # Target management
    # ------------------------------------------------------------------

    def do_add(self, arg):
        """Add a new target: add <alias> <type> <target> (shortcut: a)
        Examples:
          add site1 domain example.com
          add user1 username john_doe
          a work domain company.com"""
        parts = arg.split()
        if len(parts) != 3:
            self.console.print("[red]Error: Please provide <alias> <type> <target>[/red]")
            self.console.print("Example: add site1 domain example.com")
            return

        alias, target_type, target = parts
        if target_type not in TARGET_TYPES:
            self.console.print("[red]Error: Type must be 'domain', 'username', or 'email'[/red]")
            return

        try:
            alias = validate_alias(alias)
            target = validate_target(target_type, target)
        except ValidationError as exc:
            self.console.print(f"[red]Error: {exc}[/red]")
            return

        if alias in self.session.targets:
            self.console.print(f"[red]Error: Alias '{alias}' already exists[/red]")
            return

        self.session.add_target(alias, target_type, target)
        self.session.save()
        self.console.print(f"[green]Added {target_type} '{target}' with alias '{alias}'[/green]")

    def do_del(self, arg):
        """Remove a target: del <alias>"""
        alias = arg.strip()
        if not alias:
            self.console.print("[red]Error: Please provide a target alias[/red]")
            return
        if alias not in self.session.targets:
            self.console.print(f"[red]Error: Alias '{alias}' not found[/red]")
            return

        removed = self.session.targets.pop(alias)
        self.session.save()
        self.console.print(f"[green]Removed {removed['type']} '{removed['value']}' ({alias})[/green]")

    def do_list(self, arg):
        """List all targets (shortcut: l)"""
        if not self.session.targets:
            self.console.print("[yellow]No targets added yet[/yellow]")
            return

        table = Table(title="Targets", box=ROUNDED)
        table.add_column("Alias", style="cyan")
        table.add_column("Type", style="green")
        table.add_column("Target", style="yellow")
        table.add_column("Last Scan", style="blue")

        for alias, info in self.session.targets.items():
            last_scan = info.get("last_scan") or "Never"
            table.add_row(alias, info["type"], info["value"], str(last_scan))

        self.console.print(table)

    def do_reset(self, arg):
        """Remove every target (asks for confirmation)"""
        if not self.session.targets:
            self.console.print("[yellow]No targets to remove[/yellow]")
            return

        count = len(self.session.targets)
        try:
            answer = input(f"Remove all {count} target(s)? [y/N] ").strip().lower()
        except EOFError:
            answer = ""
        if answer not in ("y", "yes"):
            self.console.print("[yellow]Cancelled[/yellow]")
            return

        self.session.targets.clear()
        self.session.save()
        self.console.print(f"[green]Removed {count} target(s)[/green]")

    def do_clear(self, arg):
        """Clear the screen (shortcut: c)"""
        self.console.clear()

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------

    def do_config(self, arg):
        """Show current configuration"""
        table = Table(box=SQUARE)
        table.add_column(f"[{PRIMARY_BLUE}]Option[/{PRIMARY_BLUE}]")
        table.add_column(f"[{PRIMARY_BLUE}]Value[/{PRIMARY_BLUE}]")
        table.add_column(f"[{PRIMARY_BLUE}]Description[/{PRIMARY_BLUE}]")

        for name, (_, _, description) in SETTING_SPECS.items():
            value = self.session.settings.get(name)
            if name == "proxy" and value:
                shown = "<set>"
            elif value is None:
                shown = "not set"
            else:
                shown = str(value)
            table.add_row(
                f"[{SECONDARY_BLUE}]{name}[/{SECONDARY_BLUE}]",
                f"[{WHITE}]{shown}[/{WHITE}]",
                f"[dim]{description}[/dim]"
            )

        self.console.print(Panel(table, title=f"[{WHITE}]Configuration[/{WHITE}]", box=SQUARE))
        self.console.print(f"[dim]Session file: {self.session.session_file}[/dim]")

    def do_set(self, arg):
        """Set a configuration option: set <option> <value>
        Run 'config' to see every option and its current value.
        Example: set formats table,json,csv"""
        parts = arg.split(None, 1)
        if not parts:
            return self.do_config(arg)
        if len(parts) == 1:
            self.console.print("[red]Error: Please provide <option> <value>[/red]")
            self.console.print("Example: set timeout 20")
            return

        name, raw_value = parts[0].strip(), parts[1].strip()
        try:
            self.session.set_setting(name, raw_value)
        except ValidationError as exc:
            self.console.print(f"[red]Error: {exc}[/red]")
            return

        self.session.save()
        value = self.session.settings[name]
        shown = "<set>" if name == "proxy" and value else value
        self.console.print(f"[green]{name} = {shown}[/green]")
        if name == "verify_tls" and not value:
            self.console.print(
                "[yellow]Warning: TLS verification disabled. Responses can be tampered with.[/yellow]"
            )

    def do_save(self, arg):
        """Save targets and settings to disk now"""
        path = self.session.save()
        if path:
            self.console.print(f"[green]Session saved to {path}[/green]")
        else:
            self.console.print("[red]Error: Could not write the session file[/red]")

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def do_scan(self, arg):
        """Scan a target: scan <alias> [scan_type] (shortcut: s)
        Examples:
          scan site1         (runs full scan)
          scan site1 ports   (port scan only)
          scan site1 dns     (DNS scan only)
          s user1            (username scan)

        Domain scan types:
          - dns    : DNS records and enumeration
          - ports  : Port scanning and service detection
          - whois  : WHOIS information
          - all    : Full reconnaissance (default)"""
        parts = arg.split()
        if not parts:
            self.console.print("[red]Error: Please provide target alias[/red]")
            return

        alias = parts[0]
        scan_type = parts[1] if len(parts) > 1 else "all"

        if alias not in self.session.targets:
            self.console.print(
                f"[red]Error: Alias '{alias}' not found. Add it first with 'add' command.[/red]"
            )
            return

        target_info = self.session.targets[alias]
        target = target_info["value"]
        module = target_info["type"]

        if module == "domain":
            if scan_type not in DOMAIN_SCAN_TYPES:
                self.console.print("[red]Error: Invalid scan type for domain[/red]")
                self.console.print(f"Available types: {', '.join(DOMAIN_SCAN_TYPES)}")
                return
            result = self._scan_domain(alias, target, scan_type)
        elif module == "email":
            if scan_type not in EMAIL_SCAN_TYPES:
                self.console.print("[red]Error: Invalid scan type for email[/red]")
                self.console.print(f"Available types: {', '.join(EMAIL_SCAN_TYPES)}")
                return
            result = self._scan_email(target, scan_type)
        else:
            scan_type = "username"
            result = self._scan_username(target)

        if result is None:
            return

        self._save_result(alias, module, scan_type, result)

    def _scan_domain(self, alias, target, scan_type):
        try:
            scanner = DomainScanner(
                timeout=self.session.timeout,
                proxy=self.session.proxy,
                top_ports=self.session.top_ports,
                wordlist=self.session.wordlist,
                dns_server=self.session.dns_server,
                no_axfr=self.session.no_axfr,
                no_scan_ports=self.session.no_scan_ports,
            )
        except ValidationError as exc:
            self.console.print(f"[red]Error: {exc}[/red]")
            return None

        label, method_name = {
            "ports": ("Running port scan", "scan_ports"),
            "dns": ("Gathering DNS records", "scan_dns"),
            "whois": ("Fetching WHOIS information", "scan_whois"),
            "all": ("Running full reconnaissance", "scan"),
        }[scan_type]

        try:
            with self.console.status(
                f"[bold blue]Scanning {target} ({alias})...\n[dim]{label}...[/dim]"
            ):
                return getattr(scanner, method_name)(target)
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Scan interrupted[/yellow]")
            return None

    def _scan_username(self, target):
        scanner = UsernameScanner(
            timeout=self.session.timeout,
            concurrency=self.session.concurrency,
            retries=self.session.retries,
            proxy=self.session.proxy,
            verify_tls=self.session.verify_tls,
        )
        try:
            return scanner.scan(target)
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Scan interrupted[/yellow]")
            return None

    def _scan_email(self, target, scan_type):
        no_platform = self.session.settings.get("no_platform_probe", False)
        hibp_key = self.session.settings.get("hibp_api_key")
        scanner = EmailScanner(
            timeout=self.session.timeout,
            proxy=self.session.proxy,
            verify_tls=self.session.verify_tls,
            hibp_api_key=hibp_key,
            no_platform_probe=no_platform or (scan_type not in ("all", "platforms")),
            no_breach_check=(scan_type not in ("all", "breaches")),
        )
        label = {
            "all": "Running full email reconnaissance",
            "dns": "Checking email DNS records",
            "gravatar": "Looking up Gravatar profile",
            "platforms": "Probing platform registrations",
            "breaches": "Checking breach databases",
        }[scan_type]
        try:
            with self.console.status(
                f"[bold blue]Scanning {target}...\n[dim]{label}...[/dim]"
            ):
                if scan_type == "dns":
                    return {"email": target, "dns": scanner.scan_dns(target)}
                if scan_type == "gravatar":
                    return {"email": target, "gravatar": scanner.scan_gravatar(target)}
                if scan_type == "platforms":
                    return {"email": target, "platforms": scanner.scan_platforms(target)}
                if scan_type == "breaches":
                    return {"email": target, "breaches": scanner.scan_breaches(target)}
                return scanner.scan(target)
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Scan interrupted[/yellow]")
            return None

    def _save_result(self, alias, module, scan_type, result):
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.session.targets[alias]["last_scan"] = ts
        self.session.save()

        meta = {
            "tool": "spylo",
            "version": VERSION,
            "module": module,
            "alias": alias,
            "target": self.session.targets[alias]["value"],
            "scan_type": scan_type,
            "timestamp_utc": ts,
        }

        formats = self.session.formats_list()
        ensure_dir(self.session.output_dir)

        if "table" in formats:
            print_table_summary(meta, result)

        try:
            written = save_reports(meta, result, self.session.output_dir, formats)
        except OSError as exc:
            self.console.print(f"[red]Error: Could not write reports: {exc}[/red]")
            return

        if written:
            self.console.print(f"\n[green]Results saved to: {self.session.output_dir}[/green]")
            for path in written:
                self.console.print(f"[dim]  {path}[/dim]")

    # ------------------------------------------------------------------
    # Exit
    # ------------------------------------------------------------------

    def do_exit(self, arg):
        """Exit the SPYLO shell (shortcut: q)"""
        self.session.save()
        self.console.print("[yellow]Goodbye![/yellow]")
        return True

    # ------------------------------------------------------------------
    # Tab completion
    # ------------------------------------------------------------------

    def _arg_position(self, line: str, endidx: int) -> int:
        """Return the 1-based index of the argument under the cursor."""
        prefix = line[:endidx]
        tokens = prefix.split()
        if prefix.endswith(" "):
            return len(tokens)
        return max(len(tokens) - 1, 1)

    def _aliases(self, text: str) -> list[str]:
        return [a for a in sorted(self.session.targets) if a.startswith(text)]

    def _complete_scan(self, text, line, begidx, endidx):
        position = self._arg_position(line, endidx)
        if position == 1:
            return self._aliases(text)
        if position == 2:
            tokens = line.split()
            alias = tokens[1] if len(tokens) > 1 else ""
            info = self.session.targets.get(alias)
            if info and info["type"] == "domain":
                return [t for t in DOMAIN_SCAN_TYPES if t.startswith(text)]
            if info and info["type"] == "email":
                return [t for t in EMAIL_SCAN_TYPES if t.startswith(text)]
        return []

    complete_scan = _complete_scan
    complete_s = _complete_scan

    def _complete_add(self, text, line, begidx, endidx):
        if self._arg_position(line, endidx) == 2:
            return [t for t in TARGET_TYPES if t.startswith(text)]
        return []

    complete_add = _complete_add
    complete_a = _complete_add

    def complete_del(self, text, line, begidx, endidx):
        if self._arg_position(line, endidx) == 1:
            return self._aliases(text)
        return []

    def complete_set(self, text, line, begidx, endidx):
        position = self._arg_position(line, endidx)
        if position == 1:
            return [name for name in sorted(SETTING_SPECS) if name.startswith(text)]
        if position == 2:
            tokens = line.split()
            name = tokens[1] if len(tokens) > 1 else ""
            parser = SETTING_SPECS.get(name, (None, None, None))[0]
            if parser is _parse_bool:
                return [v for v in ("true", "false") if v.startswith(text)]
            if name == "formats":
                return [f for f in SUPPORTED_FORMATS if f.startswith(text)]
        return []


def main():
    console = Console()
    try:
        shell = SPYLOShell()
        while True:
            try:
                shell.cmdloop()
                break
            except KeyboardInterrupt:
                console.print("\n[yellow]Use 'exit' or 'q' to quit[/yellow]")
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
                console.print("[yellow]Continuing...[/yellow]")
        return 0
    except Exception as e:
        console.print(f"[red]Fatal Error: {e}[/red]")
        return 1


if __name__ == "__main__":
    sys.exit(main())
