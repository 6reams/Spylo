import json
from pathlib import Path
from urllib.parse import urlparse

import pytest

SITES_PATH = Path(__file__).resolve().parent.parent / "data" / "sites.json"
VALID_ERROR_TYPES = {"status_code", "message", "response_url", "regex"}

RAW = SITES_PATH.read_text(encoding="utf-8")
SITES = json.loads(RAW)
PAIRS = json.loads(RAW, object_pairs_hook=lambda kv: kv)


def test_file_is_valid_json_object():
    assert isinstance(SITES, dict)
    assert SITES


def test_no_duplicate_keys():
    # json.load silently keeps the last of a repeated key, so the raw pair
    # list is the only way to catch duplicates.
    keys = [k for k, _ in PAIRS]
    duplicates = sorted({k for k in keys if keys.count(k) > 1})
    assert duplicates == []


def test_no_duplicate_urls():
    seen = {}
    collisions = []
    for name, cfg in SITES.items():
        url = cfg["url"]
        if url in seen:
            collisions.append(f"{seen[url]} and {name} share {url}")
        seen[url] = name
    assert collisions == []


@pytest.mark.parametrize("name", sorted(SITES))
def test_entry_shape(name):
    cfg = SITES[name]
    assert isinstance(cfg, dict), name
    assert "url" in cfg, name

    unknown = set(cfg) - {"url", "errorType", "errorMsg", "request_head_only", "headers"}
    assert not unknown, f"{name} has unknown keys: {unknown}"


@pytest.mark.parametrize("name", sorted(SITES))
def test_url_is_a_usable_template(name):
    url = SITES[name]["url"]
    assert "{account}" in url, f"{name} is missing the {{account}} placeholder"

    parsed = urlparse(url)
    assert parsed.scheme == "https", f"{name} should use https, got {parsed.scheme!r}"
    assert parsed.netloc, f"{name} has no host"
    assert " " not in url, f"{name} url contains a space"


@pytest.mark.parametrize("name", sorted(SITES))
def test_error_type_is_known(name):
    error_type = SITES[name].get("errorType", "status_code")
    assert error_type in VALID_ERROR_TYPES, f"{name} has errorType {error_type!r}"


@pytest.mark.parametrize("name", sorted(SITES))
def test_message_and_regex_entries_carry_a_pattern(name):
    cfg = SITES[name]
    if cfg.get("errorType") in {"message", "regex"}:
        assert cfg.get("errorMsg"), f"{name} uses {cfg['errorType']} but has no errorMsg"


def test_scanner_loads_the_same_entries():
    from modules.username_osint import UsernameScanner

    assert UsernameScanner().sites == SITES
