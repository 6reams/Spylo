
import pytest

from core.validation import ValidationError, validate_email
from modules import email_osint
from modules.email_osint import (
    EmailScanner,
    _classify_provider,
    _gravatar_hash,
    _parse_dmarc_policy,
    _spoofability_verdict,
)


# ------------------------------------------------------------------
# validate_email
# ------------------------------------------------------------------

@pytest.mark.parametrize("addr,normalized", [
    ("user@example.com", "user@example.com"),
    ("  User@Example.COM  ", "user@example.com"),
    ("a+tag@sub.domain.io", "a+tag@sub.domain.io"),
])
def test_validate_email_accepts_valid(addr, normalized):
    assert validate_email(addr) == normalized


@pytest.mark.parametrize("bad", [
    "",
    "not-an-email",
    "@example.com",
    "user@",
    "user @example.com",
    "user@example",
    "a" * 65 + "@example.com",
])
def test_validate_email_rejects_invalid(bad):
    with pytest.raises(ValidationError):
        validate_email(bad)


# ------------------------------------------------------------------
# _gravatar_hash
# ------------------------------------------------------------------

def test_gravatar_hash_is_md5_of_lowercase():
    assert _gravatar_hash("User@Example.COM") == _gravatar_hash("user@example.com")


def test_gravatar_hash_known_value():
    # md5("test@example.com") == 55502f40dc8b7c769880b10874abc9d0
    assert _gravatar_hash("test@example.com") == "55502f40dc8b7c769880b10874abc9d0"


# ------------------------------------------------------------------
# _parse_dmarc_policy
# ------------------------------------------------------------------

@pytest.mark.parametrize("record,expected", [
    ("v=DMARC1; p=reject; rua=mailto:dmarc@example.com", "reject"),
    ("v=DMARC1; p=none", "none"),
    ("v=DMARC1; p=quarantine; pct=100", "quarantine"),
    ("v=DMARC1", None),
])
def test_parse_dmarc_policy(record, expected):
    assert _parse_dmarc_policy(record) == expected


# ------------------------------------------------------------------
# scan_dns (all DNS calls monkeypatched)
# ------------------------------------------------------------------

@pytest.fixture
def dns_scanner(monkeypatch):
    scanner = EmailScanner(no_platform_probe=True, no_breach_check=True)

    def fake_txt(name, timeout=5.0):
        fixtures = {
            "example.com": ["v=spf1 include:_spf.google.com ~all"],
            "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
            "default._domainkey.example.com": ["v=DKIM1; k=rsa; p=ABCDEF"],
            "_mta-sts.example.com": ["v=STSv1; id=20220101"],
            "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:tlsrpt@example.com"],
            "default._bimi.example.com": ["v=BIMI1; l=https://example.com/logo.svg"],
        }
        return fixtures.get(name, [])

    def fake_mx(domain, timeout=5.0):
        return [(10, "mail.example.com")]

    monkeypatch.setattr(email_osint, "_resolve_txt", fake_txt)
    monkeypatch.setattr(email_osint, "_resolve_mx", fake_mx)
    return scanner


def test_scan_dns_spf(dns_scanner):
    result = dns_scanner.scan_dns("user@example.com")
    assert result["spf_present"] is True
    assert result["spf"].startswith("v=spf1")


def test_scan_dns_dmarc(dns_scanner):
    result = dns_scanner.scan_dns("user@example.com")
    assert result["dmarc_present"] is True
    assert result["dmarc_policy"] == "reject"


def test_scan_dns_dkim(dns_scanner):
    result = dns_scanner.scan_dns("user@example.com")
    assert "default" in result["dkim_selectors_found"]


def test_scan_dns_mx(dns_scanner):
    result = dns_scanner.scan_dns("user@example.com")
    assert result["mx"] == [{"priority": 10, "host": "mail.example.com"}]


def test_scan_dns_mta_sts(dns_scanner):
    result = dns_scanner.scan_dns("user@example.com")
    assert result["mta_sts"] is True


def test_scan_dns_bimi(dns_scanner):
    result = dns_scanner.scan_dns("user@example.com")
    assert result["bimi"] is True


def test_scan_dns_no_records(monkeypatch):
    scanner = EmailScanner(no_platform_probe=True, no_breach_check=True)
    monkeypatch.setattr(email_osint, "_resolve_txt", lambda *a, **kw: [])
    monkeypatch.setattr(email_osint, "_resolve_mx", lambda *a, **kw: [])
    result = scanner.scan_dns("user@empty.example")
    assert result["spf_present"] is False
    assert result["dmarc_present"] is False
    assert result["mx"] == []
    assert result["dkim_selectors_found"] == []


# ------------------------------------------------------------------
# scan_gravatar
# ------------------------------------------------------------------

class FakeGravatarResponse:
    status_code = 200

    @staticmethod
    def json():
        return {
            "entry": [{
                "displayName": "John Doe",
                "profileUrl": "https://gravatar.com/johndoe",
                "thumbnailUrl": "https://gravatar.com/avatar/abc",
                "aboutMe": "Test user",
                "accounts": [{"shortname": "twitter", "url": "https://twitter.com/johndoe"}],
                "name": {"formatted": "John Doe"},
            }]
        }


def test_gravatar_found(monkeypatch):
    scanner = EmailScanner(no_platform_probe=True, no_breach_check=True)
    monkeypatch.setattr(email_osint, "rate_limited_get",
                        lambda url, limiter, **kw: FakeGravatarResponse())
    result = scanner.scan_gravatar("test@example.com")
    assert result["found"] is True
    assert result["display_name"] == "John Doe"
    assert result["name"] == "John Doe"
    assert result["accounts"][0]["shortname"] == "twitter"


def test_gravatar_not_found(monkeypatch):
    class Miss:
        status_code = 404
    scanner = EmailScanner(no_platform_probe=True, no_breach_check=True)
    monkeypatch.setattr(email_osint, "rate_limited_get", lambda *a, **kw: Miss())
    result = scanner.scan_gravatar("nobody@example.com")
    assert result["found"] is False


def test_gravatar_request_failure(monkeypatch):
    scanner = EmailScanner(no_platform_probe=True, no_breach_check=True)
    monkeypatch.setattr(email_osint, "rate_limited_get", lambda *a, **kw: None)
    result = scanner.scan_gravatar("test@example.com")
    assert result["found"] is False


def test_gravatar_hashes_are_included(monkeypatch):
    scanner = EmailScanner(no_platform_probe=True, no_breach_check=True)
    monkeypatch.setattr(email_osint, "rate_limited_get", lambda *a, **kw: None)
    result = scanner.scan_gravatar("test@example.com")
    assert len(result["md5"]) == 32
    assert len(result["sha256"]) == 64


# ------------------------------------------------------------------
# scan_platforms
# ------------------------------------------------------------------

def test_platform_hit(monkeypatch):
    scanner = EmailScanner(no_breach_check=True)
    scanner._platforms = {
        "FakeSite": {
            "url": "https://fake.example/check",
            "method": "GET",
            "params": {"email": "{email}"},
            "hit": "already registered",
            "miss": None,
            "response_type": "text",
        }
    }

    class HitResp:
        status_code = 200
        text = "This email is already registered on our site."
        def json(self): return {}

    import requests as _requests
    monkeypatch.setattr(_requests, "get", lambda *a, **kw: HitResp())
    result = scanner.scan_platforms("user@example.com")
    assert result["FakeSite"]["status"] == "found"


def test_platform_miss(monkeypatch):
    scanner = EmailScanner(no_breach_check=True)
    scanner._platforms = {
        "FakeSite": {
            "url": "https://fake.example/check",
            "method": "GET",
            "params": {"email": "{email}"},
            "hit": "already registered",
            "miss": "no account found",
            "response_type": "text",
        }
    }

    class MissResp:
        status_code = 200
        text = "no account found for that email"
        def json(self): return {}

    import requests as _requests
    monkeypatch.setattr(_requests, "get", lambda *a, **kw: MissResp())
    result = scanner.scan_platforms("user@example.com")
    assert result["FakeSite"]["status"] == "not_found"


def test_platform_network_error(monkeypatch):
    import requests as _requests
    scanner = EmailScanner(no_breach_check=True)
    scanner._platforms = {
        "FakeSite": {
            "url": "https://fake.example/check",
            "method": "GET",
            "hit": "registered",
            "response_type": "text",
        }
    }
    monkeypatch.setattr(
        _requests, "get",
        lambda *a, **kw: (_ for _ in ()).throw(_requests.exceptions.ConnectionError("down"))
    )
    result = scanner.scan_platforms("user@example.com")
    assert result["FakeSite"]["status"] == "error"


def test_platform_json_path_hit(monkeypatch):
    import requests as _requests
    scanner = EmailScanner(no_breach_check=True)
    scanner._platforms = {
        "Duolingo": {
            "url": "https://www.duolingo.com/2017-06-30/users",
            "method": "GET",
            "params": {"email": "{email}"},
            "hit_json": {"path": "users", "check": "non_empty"},
            "response_type": "json",
        }
    }

    class DuoResp:
        status_code = 200
        text = '{"users": [{"id": 123}]}'
        def json(self): return {"users": [{"id": 123}]}

    monkeypatch.setattr(_requests, "get", lambda *a, **kw: DuoResp())
    result = scanner.scan_platforms("user@example.com")
    assert result["Duolingo"]["status"] == "found"


def test_platform_json_path_miss(monkeypatch):
    import requests as _requests
    scanner = EmailScanner(no_breach_check=True)
    scanner._platforms = {
        "Duolingo": {
            "url": "https://www.duolingo.com/2017-06-30/users",
            "method": "GET",
            "params": {"email": "{email}"},
            "hit_json": {"path": "users", "check": "non_empty"},
            "response_type": "json",
        }
    }

    class DuoResp:
        status_code = 200
        text = '{"users": []}'
        def json(self): return {"users": []}

    monkeypatch.setattr(_requests, "get", lambda *a, **kw: DuoResp())
    result = scanner.scan_platforms("user@example.com")
    assert result["Duolingo"]["status"] == "not_found"


def test_no_platform_probe_skips_platforms(monkeypatch):
    scanner = EmailScanner(no_platform_probe=True, no_breach_check=True)
    monkeypatch.setattr(email_osint, "_resolve_txt", lambda *a, **kw: [])
    monkeypatch.setattr(email_osint, "_resolve_mx", lambda *a, **kw: [])
    monkeypatch.setattr(email_osint, "rate_limited_get", lambda *a, **kw: None)
    result = scanner.scan("user@example.com")
    assert result["platforms"] == {}


# ------------------------------------------------------------------
# scan_breaches
# ------------------------------------------------------------------

def test_breach_check_requires_api_key():
    scanner = EmailScanner(no_platform_probe=True, hibp_api_key=None)
    result = scanner.scan_breaches("user@example.com")
    assert "error" in result


def test_breach_found(monkeypatch):
    scanner = EmailScanner(no_platform_probe=True, hibp_api_key="test-key-123")

    class BreachResp:
        status_code = 200
        def json(self):
            return [{"Name": "Adobe", "Domain": "adobe.com",
                     "BreachDate": "2013-10-04", "PwnCount": 153000000,
                     "DataClasses": ["Email addresses", "Passwords"]}]

    class PasteResp:
        status_code = 404

    calls = iter([BreachResp(), PasteResp()])
    monkeypatch.setattr(email_osint, "rate_limited_get", lambda *a, **kw: next(calls))
    result = scanner.scan_breaches("user@example.com")
    assert len(result["breaches"]) == 1
    assert result["breaches"][0]["name"] == "Adobe"
    assert result["summary"]["breach_count"] == 1


def test_no_breach_check_skips_hibp(monkeypatch):
    scanner = EmailScanner(
        no_platform_probe=True,
        no_breach_check=True,
        hibp_api_key="key",
    )
    called = []
    monkeypatch.setattr(email_osint, "rate_limited_get",
                        lambda *a, **kw: called.append(a) or None)
    monkeypatch.setattr(email_osint, "_resolve_txt", lambda *a, **kw: [])
    monkeypatch.setattr(email_osint, "_resolve_mx", lambda *a, **kw: [])
    scanner.scan("user@example.com")
    # Only gravatar should have called rate_limited_get (or none if missed)
    hibp_calls = [c for c in called if c and "haveibeenpwned" in str(c[0])]
    assert hibp_calls == []


# ------------------------------------------------------------------
# full scan
# ------------------------------------------------------------------

def test_full_scan_structure(monkeypatch):
    scanner = EmailScanner(no_platform_probe=True, no_breach_check=True)
    monkeypatch.setattr(email_osint, "_resolve_txt", lambda *a, **kw: [])
    monkeypatch.setattr(email_osint, "_resolve_mx", lambda *a, **kw: [])
    monkeypatch.setattr(email_osint, "rate_limited_get", lambda *a, **kw: None)

    result = scanner.scan("user@example.com")
    for key in ("email", "dns", "gravatar", "platforms", "breaches", "summary"):
        assert key in result
    assert result["email"] == "user@example.com"
    assert result["summary"]["domain"] == "example.com"


def test_full_scan_summary_counts(monkeypatch):
    scanner = EmailScanner(no_platform_probe=True, no_breach_check=True)
    monkeypatch.setattr(email_osint, "_resolve_txt", lambda *a, **kw: [])
    monkeypatch.setattr(email_osint, "_resolve_mx", lambda *a, **kw: [(10, "mx.example.com")])
    monkeypatch.setattr(email_osint, "rate_limited_get", lambda *a, **kw: None)

    result = scanner.scan("user@example.com")
    assert result["summary"]["mx_records"] == 1
    assert result["summary"]["gravatar_found"] is False
    assert result["summary"]["platforms_found"] == []


# ------------------------------------------------------------------
# _classify_provider
# ------------------------------------------------------------------

@pytest.mark.parametrize("email,expected_cat,expected_provider", [
    ("user@gmail.com", "free", "Gmail"),
    ("user@yahoo.com", "free", "Yahoo"),
    ("user@outlook.com", "free", "Outlook"),
    ("user@protonmail.com", "free", "ProtonMail"),
    ("user@proton.me", "free", "ProtonMail"),
    ("user@icloud.com", "free", "iCloud"),
    ("user@yandex.com", "free", "Yandex"),
    ("user@mail.ru", "free", "Mail.ru"),
    ("user@companyxyz.com", "corporate", None),
])
def test_classify_provider_free_and_corporate(email, expected_cat, expected_provider):
    result = _classify_provider(email)
    assert result["category"] == expected_cat
    assert result["provider"] == expected_provider


@pytest.mark.parametrize("email", [
    "user@mailinator.com",
    "user@guerrillamail.com",
    "user@10minutemail.com",
    "user@yopmail.com",
    "user@trashmail.com",
    "user@maildrop.cc",
])
def test_classify_provider_disposable(email):
    result = _classify_provider(email)
    assert result["category"] == "disposable"
    assert result["provider"] is None


def test_classify_provider_case_insensitive():
    result = _classify_provider("USER@GMAIL.COM")
    assert result["category"] == "free"
    assert result["provider"] == "Gmail"


# ------------------------------------------------------------------
# _spoofability_verdict
# ------------------------------------------------------------------

@pytest.mark.parametrize("dns_data,expected_risk,expected_spoofable", [
    ({"spf_present": False, "dmarc_present": False}, "high", True),
    ({"spf_present": True, "dmarc_present": False}, "medium", True),
    ({"spf_present": True, "dmarc_present": True, "dmarc_policy": "none"}, "medium", True),
    ({"spf_present": True, "dmarc_present": True, "dmarc_policy": "quarantine"}, "low", False),
    ({"spf_present": True, "dmarc_present": True, "dmarc_policy": "reject"}, "none", False),
])
def test_spoofability_verdict(dns_data, expected_risk, expected_spoofable):
    verdict = _spoofability_verdict(dns_data)
    assert verdict["risk"] == expected_risk
    assert verdict["spoofable"] is expected_spoofable
    assert "reason" in verdict


def test_spoofability_verdict_unknown_policy():
    verdict = _spoofability_verdict({"spf_present": True, "dmarc_present": True, "dmarc_policy": "bogus"})
    assert verdict["risk"] == "medium"
    assert verdict["spoofable"] is True


def test_scan_dns_includes_spoofability(dns_scanner):
    result = dns_scanner.scan_dns("user@example.com")
    assert "spoofability" in result
    assert result["spoofability"]["risk"] == "none"
    assert result["spoofability"]["spoofable"] is False


# ------------------------------------------------------------------
# Full scan classification
# ------------------------------------------------------------------

def test_full_scan_includes_classification(monkeypatch):
    scanner = EmailScanner(no_platform_probe=True, no_breach_check=True)
    monkeypatch.setattr(email_osint, "_resolve_txt", lambda *a, **kw: [])
    monkeypatch.setattr(email_osint, "_resolve_mx", lambda *a, **kw: [])
    monkeypatch.setattr(email_osint, "rate_limited_get", lambda *a, **kw: None)

    result = scanner.scan("user@gmail.com")
    assert result["classification"]["category"] == "free"
    assert result["classification"]["provider"] == "Gmail"
    assert result["summary"]["provider_category"] == "free"
    assert result["summary"]["provider"] == "Gmail"


def test_full_scan_includes_spoofability_summary(monkeypatch):
    scanner = EmailScanner(no_platform_probe=True, no_breach_check=True)
    monkeypatch.setattr(email_osint, "_resolve_txt", lambda *a, **kw: [])
    monkeypatch.setattr(email_osint, "_resolve_mx", lambda *a, **kw: [])
    monkeypatch.setattr(email_osint, "rate_limited_get", lambda *a, **kw: None)

    result = scanner.scan("user@example.com")
    assert "spoofable" in result["summary"]
    assert "spoofability_risk" in result["summary"]


# ------------------------------------------------------------------
# scan_pivot
# ------------------------------------------------------------------

def test_scan_pivot_calls_username_and_domain_scanners(monkeypatch):
    scanner = EmailScanner(no_platform_probe=True, no_breach_check=True)

    username_called = []
    domain_called = []

    class FakeUsernameScanner:
        def __init__(self, **kwargs):
            pass

        def scan(self, target):
            username_called.append(target)
            return {"accounts": [{"status": "found", "site": "GitHub"}]}

    class FakeDomainScanner:
        def __init__(self, **kwargs):
            pass

        def scan_dns(self, target):
            domain_called.append(target)
            return {"domain": target, "mx": []}

    monkeypatch.setattr(email_osint, "_make_username_scanner", lambda **kw: FakeUsernameScanner(**kw))
    monkeypatch.setattr(email_osint, "_make_domain_scanner", lambda **kw: FakeDomainScanner(**kw))

    result = scanner.scan_pivot("john@example.com")

    assert username_called == ["john"]
    assert domain_called == ["example.com"]
    assert result["local_part"] == "john"
    assert result["domain"] == "example.com"
    assert result["summary"]["username_accounts_found"] == 1


def test_scan_pivot_normalises_email(monkeypatch):
    scanner = EmailScanner(no_platform_probe=True, no_breach_check=True)

    class FakeUS:
        def __init__(self, **kw): pass
        def scan(self, t): return {"accounts": []}

    class FakeDS:
        def __init__(self, **kw): pass
        def scan_dns(self, t): return {"domain": t, "mx": []}

    monkeypatch.setattr(email_osint, "_make_username_scanner", lambda **kw: FakeUS(**kw))
    monkeypatch.setattr(email_osint, "_make_domain_scanner", lambda **kw: FakeDS(**kw))

    result = scanner.scan_pivot("  JOHN@EXAMPLE.COM  ")
    assert result["email"] == "john@example.com"
    assert result["domain"] == "example.com"
