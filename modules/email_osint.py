"""Email reconnaissance module.

Passive checks (DNS, Gravatar) produce no traffic toward the target email
address itself.  Platform probing sends HTTP requests to third-party service
endpoints, which may log the query.  Breach checks query external APIs.

Obtain authorisation before scanning email addresses that are not your own.
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import quote

import dns.resolver
import requests

from core.ratelimit import RateLimiter, rate_limited_get

PLATFORMS_PATH = Path(__file__).resolve().parent.parent / "data" / "email_platforms.json"

DKIM_SELECTORS = [
    "default", "google", "mail", "dkim", "key1", "k1",
    "selector1", "selector2", "s1", "s2",
]

gravatar_limiter = RateLimiter(min_interval=0.5)
platform_limiter = RateLimiter(min_interval=0.3)
hibp_limiter = RateLimiter(min_interval=1.6)


def _normalize_email(email: str) -> str:
    return email.strip().lower()


def _email_domain(email: str) -> str:
    return email.split("@", 1)[1]


def _gravatar_hash(email: str) -> str:
    return hashlib.md5(_normalize_email(email).encode()).hexdigest()


def _resolve_txt(name: str, timeout: float = 5.0) -> list[str]:
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=timeout)
        return [b.decode() for rr in answers for b in rr.strings]
    except Exception:
        return []


def _resolve_mx(domain: str, timeout: float = 5.0) -> list[tuple[int, str]]:
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=timeout)
        return sorted((int(r.preference), str(r.exchange).rstrip(".")) for r in answers)
    except Exception:
        return []


def _load_platforms() -> dict:
    try:
        with open(PLATFORMS_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


@dataclass
class EmailScanner:
    timeout: int = 15
    proxy: Optional[str] = None
    verify_tls: bool = True
    hibp_api_key: Optional[str] = None
    no_platform_probe: bool = False
    no_breach_check: bool = False

    _platforms: dict = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self):
        self._platforms = _load_platforms()

    # ------------------------------------------------------------------
    # Full scan
    # ------------------------------------------------------------------

    def scan(self, email: str) -> dict:
        email = _normalize_email(email)
        domain = _email_domain(email)

        dns_result = self.scan_dns(email)
        gravatar_result = self.scan_gravatar(email)

        platforms_result: dict = {}
        if not self.no_platform_probe:
            platforms_result = self.scan_platforms(email)

        breaches_result: dict = {}
        if not self.no_breach_check and self.hibp_api_key:
            breaches_result = self.scan_breaches(email)

        registered_on = [
            name for name, data in platforms_result.items()
            if data.get("status") == "found"
        ]
        unknown_on = [
            name for name, data in platforms_result.items()
            if data.get("status") == "unknown"
        ]

        result = {
            "email": email,
            "dns": dns_result,
            "gravatar": gravatar_result,
            "platforms": platforms_result,
            "breaches": breaches_result,
            "summary": {
                "email": email,
                "domain": domain,
                "mx_records": len(dns_result.get("mx", [])),
                "spf": dns_result.get("spf_present", False),
                "dmarc": dns_result.get("dmarc_present", False),
                "dkim_selectors_found": dns_result.get("dkim_selectors_found", []),
                "gravatar_found": gravatar_result.get("found", False),
                "platforms_found": registered_on,
                "platforms_checked": len(platforms_result),
                "platforms_unknown": len(unknown_on),
                "breaches_found": len(breaches_result.get("breaches", [])),
            },
        }
        return result

    # ------------------------------------------------------------------
    # DNS checks
    # ------------------------------------------------------------------

    def scan_dns(self, email: str) -> dict:
        domain = _email_domain(_normalize_email(email))
        result: dict = {"domain": domain}

        # MX
        mx = _resolve_mx(domain)
        result["mx"] = [{"priority": p, "host": h} for p, h in mx]

        # SPF
        txt_records = _resolve_txt(domain)
        spf = [r for r in txt_records if r.startswith("v=spf1")]
        result["spf"] = spf[0] if spf else None
        result["spf_present"] = bool(spf)

        # DMARC
        dmarc_records = _resolve_txt(f"_dmarc.{domain}")
        dmarc = [r for r in dmarc_records if r.startswith("v=DMARC1")]
        result["dmarc"] = dmarc[0] if dmarc else None
        result["dmarc_present"] = bool(dmarc)
        if dmarc:
            result["dmarc_policy"] = _parse_dmarc_policy(dmarc[0])

        # DKIM (probe common selectors)
        dkim_found = {}
        for selector in DKIM_SELECTORS:
            records = _resolve_txt(f"{selector}._domainkey.{domain}")
            dkim_vals = [r for r in records if "p=" in r]
            if dkim_vals:
                dkim_found[selector] = dkim_vals[0][:120]
        result["dkim"] = dkim_found
        result["dkim_selectors_found"] = sorted(dkim_found)

        # MTA-STS
        mta_sts = _resolve_txt(f"_mta-sts.{domain}")
        result["mta_sts"] = bool(mta_sts)

        # TLS-RPT
        tls_rpt = _resolve_txt(f"_smtp._tls.{domain}")
        result["tls_rpt"] = bool(tls_rpt)

        # BIMI
        bimi = _resolve_txt(f"default._bimi.{domain}")
        result["bimi"] = bool(bimi)

        return result

    # ------------------------------------------------------------------
    # Gravatar
    # ------------------------------------------------------------------

    def scan_gravatar(self, email: str) -> dict:
        email = _normalize_email(email)
        md5 = _gravatar_hash(email)
        sha256 = hashlib.sha256(email.encode()).hexdigest()
        url = f"https://www.gravatar.com/{md5}.json"
        proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None

        result: dict = {"md5": md5, "sha256": sha256, "found": False}

        resp = rate_limited_get(
            url,
            gravatar_limiter,
            timeout=self.timeout,
            proxies=proxies,
            verify=self.verify_tls,
        )
        if resp is None or resp.status_code == 404:
            return result

        if resp.status_code == 200:
            try:
                data = resp.json()
                entry = data.get("entry", [{}])[0]
                result["found"] = True
                result["display_name"] = entry.get("displayName")
                result["profile_url"] = entry.get("profileUrl")
                result["avatar_url"] = (entry.get("thumbnailUrl") or
                                        f"https://www.gravatar.com/avatar/{md5}")
                if entry.get("name"):
                    name = entry["name"]
                    result["name"] = (
                        name.get("formatted")
                        or f"{name.get('givenName','')} {name.get('familyName','')}".strip()
                    )
                result["about"] = entry.get("aboutMe")
                result["accounts"] = [
                    {"shortname": a.get("shortname"), "url": a.get("url")}
                    for a in entry.get("accounts", [])
                ]
            except (ValueError, KeyError, IndexError):
                pass

        return result

    # ------------------------------------------------------------------
    # Platform probing (holehe-style)
    # ------------------------------------------------------------------

    def scan_platforms(self, email: str) -> dict:
        email = _normalize_email(email)
        results = {}
        for name, cfg in self._platforms.items():
            results[name] = self._probe_platform(email, name, cfg)
        return results

    def _probe_platform(self, email: str, name: str, cfg: dict) -> dict:
        time.sleep(platform_limiter.min_interval)
        proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None

        url = cfg.get("url", "").replace("{email}", quote(email, safe="@"))
        method = cfg.get("method", "GET").upper()
        content_type = cfg.get("content_type", "")
        response_type = cfg.get("response_type", "text")

        headers = {"User-Agent": "Mozilla/5.0 (compatible; OSINT-research/1.0)"}
        if content_type:
            headers["Content-Type"] = content_type

        params = None
        raw_params = cfg.get("params")
        if raw_params:
            params = {k: v.replace("{email}", email) for k, v in raw_params.items()}

        data = None
        raw_data = cfg.get("data")
        if raw_data:
            raw_str = json.dumps(raw_data) if content_type == "application/json" else None
            if raw_str:
                data = raw_str.replace("{email}", email)
            else:
                data = {k: v.replace("{email}", email) for k, v in raw_data.items()}

        try:
            if method == "GET":
                resp = requests.get(
                    url,
                    params=params,
                    headers=headers,
                    timeout=self.timeout,
                    proxies=proxies,
                    verify=self.verify_tls,
                    allow_redirects=True,
                )
            else:
                kwargs: dict = {"headers": headers, "timeout": self.timeout,
                                "proxies": proxies, "verify": self.verify_tls,
                                "allow_redirects": True}
                if isinstance(data, str):
                    kwargs["data"] = data
                elif isinstance(data, dict):
                    kwargs["data"] = data
                resp = requests.post(url, **kwargs)

        except requests.RequestException as exc:
            return {"status": "error", "error": str(exc)[:120]}

        body = ""
        try:
            if response_type == "json":
                body_json = resp.json()
                body = json.dumps(body_json)
            else:
                body = resp.text
        except Exception:
            body = resp.text

        # JSON path checks take priority
        hit_json = cfg.get("hit_json")
        if hit_json:
            status = _check_json_path(resp, hit_json)
            if status is not None:
                return {"status": "found" if status else "not_found",
                        "http_status": resp.status_code}

        hit = cfg.get("hit")
        miss = cfg.get("miss")

        if hit and hit.lower() in body.lower():
            return {"status": "found", "http_status": resp.status_code}
        if miss and miss.lower() in body.lower():
            return {"status": "not_found", "http_status": resp.status_code}

        return {"status": "unknown", "http_status": resp.status_code}

    # ------------------------------------------------------------------
    # Breach check (HaveIBeenPwned)
    # ------------------------------------------------------------------

    def scan_breaches(self, email: str) -> dict:
        if not self.hibp_api_key:
            return {"error": "HIBP API key required (set hibp_api_key)"}

        email = _normalize_email(email)
        proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
        headers = {
            "hibp-api-key": self.hibp_api_key,
            "User-Agent": "Spylo-OSINT/1.0",
        }

        result: dict = {"breaches": [], "pastes": []}

        # Breached accounts
        breaches_url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}"
        resp = rate_limited_get(
            breaches_url,
            hibp_limiter,
            headers=headers,
            timeout=self.timeout,
            proxies=proxies,
            verify=self.verify_tls,
        )
        if resp is not None:
            if resp.status_code == 200:
                try:
                    result["breaches"] = [
                        {
                            "name": b.get("Name"),
                            "domain": b.get("Domain"),
                            "date": b.get("BreachDate"),
                            "pwn_count": b.get("PwnCount"),
                            "data_classes": b.get("DataClasses", []),
                        }
                        for b in resp.json()
                    ]
                except ValueError:
                    pass
            elif resp.status_code == 404:
                pass  # Not found = no breaches
            else:
                result["breaches_error"] = f"HTTP {resp.status_code}"

        # Pastes
        pastes_url = f"https://haveibeenpwned.com/api/v3/pasteaccount/{quote(email)}"
        resp2 = rate_limited_get(
            pastes_url,
            hibp_limiter,
            headers=headers,
            timeout=self.timeout,
            proxies=proxies,
            verify=self.verify_tls,
        )
        if resp2 is not None:
            if resp2.status_code == 200:
                try:
                    result["pastes"] = [
                        {
                            "source": p.get("Source"),
                            "id": p.get("Id"),
                            "date": p.get("Date"),
                            "email_count": p.get("EmailCount"),
                        }
                        for p in resp2.json()
                    ]
                except ValueError:
                    pass
            elif resp2.status_code == 404:
                pass
            else:
                result["pastes_error"] = f"HTTP {resp2.status_code}"

        result["summary"] = {
            "breach_count": len(result["breaches"]),
            "paste_count": len(result["pastes"]),
        }
        return result


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _parse_dmarc_policy(record: str) -> Optional[str]:
    for tag in record.split(";"):
        tag = tag.strip()
        if tag.startswith("p="):
            return tag[2:].strip()
    return None


def _check_json_path(resp: requests.Response, spec: dict) -> Optional[bool]:
    """Return True if the JSON path indicates a hit, False for miss, None if unclear."""
    try:
        data = resp.json()
    except Exception:
        return None

    path = spec.get("path", "")
    check = spec.get("check", "")
    parts = path.split(".")

    node = data
    for part in parts:
        if isinstance(node, dict):
            node = node.get(part)
        else:
            return None
        if node is None:
            return None

    if check == "non_empty":
        return bool(node) if isinstance(node, (list, dict, str)) else (node is not None)
    if check == "empty":
        if isinstance(node, (list, dict, str)):
            return not bool(node)
        return node is None
    if check == "true":
        return node is True or str(node).lower() == "true"
    if check == "false":
        return node is False or str(node).lower() == "false"

    return None
