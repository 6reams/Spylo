import pytest

from core.validation import (
    ValidationError,
    parse_ports,
    safe_filename,
    validate_alias,
    validate_dns_server,
    validate_domain,
    validate_target,
    validate_username,
)


@pytest.mark.parametrize("value,expected", [
    ("example.com", "example.com"),
    ("EXAMPLE.COM", "example.com"),
    ("  example.com  ", "example.com"),
    ("example.com.", "example.com"),
    ("sub.example.com", "sub.example.com"),
    ("a-b.example.co.uk", "a-b.example.co.uk"),
    ("xn--80ak6aa92e.com", "xn--80ak6aa92e.com"),
])
def test_validate_domain_accepts(value, expected):
    assert validate_domain(value) == expected


@pytest.mark.parametrize("value", [
    "",
    "   ",
    "localhost",
    "http://example.com",
    "https://example.com",
    "example.com/path",
    "example.com:8080",
    "example .com",
    "exa mple.com",
    "../../etc/passwd",
    "example..com",
    "-bad.example.com",
    "bad-.example.com",
    "example.c0m",
    "example.1",
    "1.2.3.4",
    "::1",
    "exam;ple.com",
    "example.com|whoami",
    "$(whoami).com",
    "`id`.com",
    "a" * 64 + ".com",
    ("a." * 130) + "com",
])
def test_validate_domain_rejects(value):
    with pytest.raises(ValidationError):
        validate_domain(value)


@pytest.mark.parametrize("value,expected", [
    ("john_doe", "john_doe"),
    ("  john  ", "john"),
    ("a", "a"),
    ("a.b-c_d", "a.b-c_d"),
    ("User123", "User123"),
])
def test_validate_username_accepts(value, expected):
    assert validate_username(value) == expected


@pytest.mark.parametrize("value", [
    "",
    "   ",
    "../../etc/passwd",
    "a/b",
    "a\\b",
    "a b",
    "..",
    "a..b",
    ".leading",
    "trailing.",
    "a" * 65,
    "user?q=1",
    "user#frag",
    "<script>",
])
def test_validate_username_rejects(value):
    with pytest.raises(ValidationError):
        validate_username(value)


@pytest.mark.parametrize("value", ["site1", "a", "my-target", "my_target.2"])
def test_validate_alias_accepts(value):
    assert validate_alias(value) == value


@pytest.mark.parametrize("value", ["", "   ", "-leading", ".leading", "has space", "a" * 33, "a/b"])
def test_validate_alias_rejects(value):
    with pytest.raises(ValidationError):
        validate_alias(value)


def test_validate_target_dispatches():
    assert validate_target("domain", "Example.com") == "example.com"
    assert validate_target("username", " bob ") == "bob"
    assert validate_target("email", "Bob@Example.COM") == "bob@example.com"
    with pytest.raises(ValidationError):
        validate_target("unknown_type", "anything")


@pytest.mark.parametrize("value,expected", [
    (None, None),
    ("", None),
    ("   ", None),
    ("8.8.8.8", "8.8.8.8"),
    ("1.1.1.1", "1.1.1.1"),
    ("2001:4860:4860::8888", "2001:4860:4860::8888"),
])
def test_validate_dns_server_accepts(value, expected):
    assert validate_dns_server(value) == expected


@pytest.mark.parametrize("value", [
    "dns.google",
    "8.8.8.8; rm -rf /",
    "8.8.8.8 -x",
    "$(id)",
    "999.999.999.999",
])
def test_validate_dns_server_rejects(value):
    with pytest.raises(ValidationError):
        validate_dns_server(value)


def test_parse_ports_sorts_and_dedups():
    assert parse_ports("443,80,443, 22 ,80") == [22, 80, 443]


def test_parse_ports_tolerates_trailing_separators():
    assert parse_ports("80,,443,") == [80, 443]


@pytest.mark.parametrize("value", ["", "   ", ",", "80,abc", "0", "-1", "65536", "80,99999"])
def test_parse_ports_rejects(value):
    with pytest.raises(ValidationError):
        parse_ports(value)


@pytest.mark.parametrize("value,expected", [
    ("example.com", "example.com"),
    ("../../etc/passwd", "etc_passwd"),
    ("a/b\\c", "a_b_c"),
    ("with space", "with_space"),
    ("....", "target"),
    ("", "target"),
])
def test_safe_filename(value, expected):
    assert safe_filename(value) == expected


def test_safe_filename_has_no_separators():
    assert "/" not in safe_filename("a/b/../c")
    assert "\\" not in safe_filename("a\\b")


def test_safe_filename_truncates():
    assert len(safe_filename("a" * 500)) == 100
