import ssl

import pytest

from modules.username_osint import UsernameScanner


def test_tls_verification_is_on_by_default():
    scanner = UsernameScanner()
    assert scanner.verify_tls is True

    option = scanner._ssl_option()
    assert isinstance(option, ssl.SSLContext)
    assert option.verify_mode == ssl.CERT_REQUIRED
    assert option.check_hostname is True


# Regression: the connector hardcoded ssl=False, silently disabling
# certificate verification for every username lookup.
def test_verification_is_only_disabled_on_explicit_opt_out():
    assert UsernameScanner(verify_tls=False)._ssl_option() is False


def test_default_context_trusts_a_real_ca_bundle():
    context = UsernameScanner()._ssl_option()
    assert context.get_ca_certs(), "expected a populated CA bundle"


def test_sites_are_loaded():
    scanner = UsernameScanner()
    assert scanner.sites
    assert all("url" in cfg for cfg in scanner.sites.values())


def test_scanner_records_settings():
    scanner = UsernameScanner(timeout=5, concurrency=10, retries=1, proxy="http://p:1")
    assert (scanner.timeout, scanner.concurrency, scanner.retries) == (5, 10, 1)
    assert scanner.proxy == "http://p:1"


class FakeResponse:
    def __init__(self, status=200, text="", url="https://example.com/u", request_url=None):
        self.status = status
        self._text = text
        self.url = url
        self.request_info = type("RI", (), {"url": request_url or url})()

    async def text(self, errors="ignore"):
        return self._text


@pytest.mark.parametrize("status,expected", [(200, True), (404, False), (301, False)])
def test_status_code_detection(status, expected):
    import asyncio

    scanner = UsernameScanner()
    hit = asyncio.run(scanner._is_hit(FakeResponse(status), "status_code", None))
    assert hit is expected


def test_message_detection_treats_absent_error_as_a_hit():
    import asyncio

    scanner = UsernameScanner()
    assert asyncio.run(scanner._is_hit(FakeResponse(200, "welcome"), "message", "Not Found")) is True
    assert asyncio.run(scanner._is_hit(FakeResponse(200, "Not Found"), "message", "Not Found")) is False


def test_message_detection_without_a_pattern_is_not_a_hit():
    import asyncio

    scanner = UsernameScanner()
    assert asyncio.run(scanner._is_hit(FakeResponse(200, "x"), "message", None)) is False


def test_regex_detection():
    import asyncio

    scanner = UsernameScanner()
    assert asyncio.run(scanner._is_hit(FakeResponse(200, "User: bob"), "regex", r"user:\s*bob")) is True
    assert asyncio.run(scanner._is_hit(FakeResponse(200, "nope"), "regex", r"user:\s*bob")) is False


def test_regex_detection_falls_back_to_status_without_a_pattern():
    import asyncio

    scanner = UsernameScanner()
    assert asyncio.run(scanner._is_hit(FakeResponse(200, ""), "regex", None)) is True
    assert asyncio.run(scanner._is_hit(FakeResponse(404, ""), "regex", None)) is False


def test_response_url_detection_compares_final_and_requested_url():
    import asyncio

    scanner = UsernameScanner()
    same = FakeResponse(200, url="https://x/u", request_url="https://x/u")
    moved = FakeResponse(200, url="https://x/login", request_url="https://x/u")
    assert asyncio.run(scanner._is_hit(same, "response_url", None)) is True
    assert asyncio.run(scanner._is_hit(moved, "response_url", None)) is False


def test_unknown_error_type_falls_back_to_status():
    import asyncio

    scanner = UsernameScanner()
    assert asyncio.run(scanner._is_hit(FakeResponse(200), "mystery", None)) is True


def test_summary_handles_an_empty_site_list(monkeypatch):
    scanner = UsernameScanner()
    scanner.sites = {}
    result = scanner.scan("nobody")
    assert result["summary"]["success_rate"] == "0.0%"
    assert result["accounts"] == []
