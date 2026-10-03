"""Target validation.

Targets reach `dig` argv, HTTP URLs and report filenames, so they are
validated at the point of entry rather than at each use site.
"""

import ipaddress
import re
from typing import Optional

MAX_DOMAIN_LEN = 253
MAX_LABEL_LEN = 63
MAX_USERNAME_LEN = 64

_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
_TLD_RE = re.compile(r"^[a-z]{2,63}$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}[A-Za-z0-9]$|^[A-Za-z0-9]$")
_ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
_UNSAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]")


class ValidationError(ValueError):
    """Raised when a target or alias fails validation."""


def validate_domain(value: str) -> str:
    """Return the normalized domain, or raise ValidationError.

    Accepts a bare registrable name or subdomain. Rejects URLs, ports,
    IP addresses and anything carrying path or shell metacharacters.
    """
    if not isinstance(value, str):
        raise ValidationError("Domain must be a string")

    domain = value.strip().rstrip(".").lower()
    if not domain:
        raise ValidationError("Domain must not be empty")
    if len(domain) > MAX_DOMAIN_LEN:
        raise ValidationError(f"Domain exceeds {MAX_DOMAIN_LEN} characters")
    if "://" in domain:
        raise ValidationError("Pass a bare domain, not a URL (e.g. example.com)")
    if any(ch in domain for ch in "/\\?#@:[] \t\n\r'\"|&;$`<>()*,!{}^~%+="):
        raise ValidationError("Domain contains invalid characters")
    if ".." in domain:
        raise ValidationError("Domain contains an empty label")

    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ValidationError("Expected a domain name, not an IP address")

    labels = domain.split(".")
    if len(labels) < 2:
        raise ValidationError("Domain must include a TLD (e.g. example.com)")
    for label in labels:
        if not label:
            raise ValidationError("Domain contains an empty label")
        if len(label) > MAX_LABEL_LEN:
            raise ValidationError(f"Domain label '{label}' exceeds {MAX_LABEL_LEN} characters")
        if not _LABEL_RE.match(label):
            raise ValidationError(
                f"Invalid domain label '{label}' (letters, digits and inner hyphens only)"
            )
    if not _TLD_RE.match(labels[-1]):
        raise ValidationError(f"Invalid TLD '{labels[-1]}'")

    return domain


def validate_username(value: str) -> str:
    """Return the normalized username, or raise ValidationError.

    The username is substituted into site URL templates, so path
    separators and traversal sequences are rejected outright.
    """
    if not isinstance(value, str):
        raise ValidationError("Username must be a string")

    username = value.strip()
    if not username:
        raise ValidationError("Username must not be empty")
    if len(username) > MAX_USERNAME_LEN:
        raise ValidationError(f"Username exceeds {MAX_USERNAME_LEN} characters")
    if ".." in username:
        raise ValidationError("Username must not contain '..'")
    if not _USERNAME_RE.match(username):
        raise ValidationError(
            "Invalid username (letters, digits, and inner '.', '_', '-' only)"
        )

    return username


def validate_alias(value: str) -> str:
    """Return the alias, or raise ValidationError.

    Aliases are dict keys and tab-completion candidates, so they are kept
    to a short, predictable shape.
    """
    if not isinstance(value, str):
        raise ValidationError("Alias must be a string")

    alias = value.strip()
    if not alias:
        raise ValidationError("Alias must not be empty")
    if not _ALIAS_RE.match(alias):
        raise ValidationError(
            "Invalid alias (start with a letter or digit; then letters, digits, '.', '_', '-'; max 32)"
        )

    return alias


def validate_target(target_type: str, value: str) -> str:
    """Dispatch to the validator for `target_type`."""
    if target_type == "domain":
        return validate_domain(value)
    if target_type == "username":
        return validate_username(value)
    raise ValidationError(f"Unknown target type '{target_type}'")


def validate_dns_server(value: Optional[str]) -> Optional[str]:
    """Return the DNS server IP, or raise ValidationError.

    Restricted to literal IPs because the value is interpolated into
    `dig @<server>` argv.
    """
    if value is None:
        return None
    server = value.strip()
    if not server:
        return None
    try:
        return str(ipaddress.ip_address(server))
    except ValueError:
        raise ValidationError(f"DNS server must be an IP address, got '{server}'")


def parse_ports(value: str) -> list[int]:
    """Parse a comma-separated port list into sorted unique ports."""
    ports = set()
    for chunk in str(value).split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            port = int(chunk)
        except ValueError:
            raise ValidationError(f"Invalid port '{chunk}'")
        if not 1 <= port <= 65535:
            raise ValidationError(f"Port {port} out of range 1-65535")
        ports.add(port)
    if not ports:
        raise ValidationError("Port list must not be empty")
    return sorted(ports)


def safe_filename(value: str, fallback: str = "target") -> str:
    """Reduce `value` to a filename-safe slug.

    Defense in depth for report paths: validation already rejects
    separators, but reports are also written from loaded session files.
    """
    slug = _UNSAFE_FILENAME_RE.sub("_", str(value)).strip("._-")
    return slug[:100] if slug else fallback
