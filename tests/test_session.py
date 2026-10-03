import json
import os
import stat

import pytest

from core.validation import ValidationError
from main import DEFAULT_SETTINGS, SETTING_SPECS, Session


@pytest.fixture
def session(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return Session(session_file=tmp_path / "session.json")


def test_defaults(session):
    assert session.settings == DEFAULT_SETTINGS
    assert session.output_dir == "out"
    assert session.timeout == 15
    assert session.verify_tls is True


def test_settings_readable_as_attributes(session):
    for name in DEFAULT_SETTINGS:
        assert getattr(session, name) == session.settings[name]


def test_unknown_attribute_still_raises(session):
    with pytest.raises(AttributeError):
        session.not_a_setting


def test_output_dir_created(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Session(session_file=tmp_path / "session.json")
    assert (tmp_path / "out").is_dir()


def test_formats_list(session):
    assert session.formats_list() == ["table", "json"]
    session.set_setting("formats", "json, csv ,md")
    assert session.formats_list() == ["json", "csv", "md"]


def test_set_setting_coerces_types(session):
    session.set_setting("timeout", "30")
    session.set_setting("verify_tls", "false")
    session.set_setting("no_axfr", "yes")
    assert session.settings["timeout"] == 30
    assert session.settings["verify_tls"] is False
    assert session.settings["no_axfr"] is True


def test_set_setting_dedups_ports(session):
    session.set_setting("top_ports", "443,80,443,22")
    assert session.settings["top_ports"] == "22,80,443"


def test_set_setting_clears_optional_values(session):
    session.set_setting("dns_server", "8.8.8.8")
    assert session.settings["dns_server"] == "8.8.8.8"
    session.set_setting("dns_server", "none")
    assert session.settings["dns_server"] is None


@pytest.mark.parametrize("name,value", [
    ("timeout", "zero"),
    ("timeout", "0"),
    ("retries", "-1"),
    ("formats", "pdf"),
    ("formats", ""),
    ("top_ports", "80,abc"),
    ("dns_server", "dns.google"),
    ("verify_tls", "maybe"),
    ("wordlist", "/does/not/exist.txt"),
    ("output_dir", ""),
    ("nope", "x"),
])
def test_set_setting_rejects_bad_values(session, name, value):
    with pytest.raises(ValidationError):
        session.set_setting(name, value)


def test_set_output_dir_creates_it(session, tmp_path):
    session.set_setting("output_dir", str(tmp_path / "reports"))
    assert (tmp_path / "reports").is_dir()


def test_save_load_roundtrip(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "session.json"

    first = Session(session_file=path)
    first.add_target("site1", "domain", "example.com")
    first.add_target("user1", "username", "john_doe")
    first.set_setting("timeout", "42")
    first.set_setting("formats", "json,md")
    assert first.save() == path

    second = Session(session_file=path)
    loaded, warnings = second.load()
    assert loaded == 2
    assert warnings == []
    assert second.targets["site1"] == {"type": "domain", "value": "example.com", "last_scan": None}
    assert second.targets["user1"]["value"] == "john_doe"
    assert second.settings["timeout"] == 42
    assert second.settings["formats"] == "json,md"


def test_last_scan_is_persisted(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "session.json"
    first = Session(session_file=path)
    first.add_target("site1", "domain", "example.com")
    first.targets["site1"]["last_scan"] = "20260101T000000Z"
    first.save()

    second = Session(session_file=path)
    second.load()
    assert second.targets["site1"]["last_scan"] == "20260101T000000Z"


def test_proxy_is_never_written_to_disk(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "session.json"
    session = Session(session_file=path)
    session.set_setting("proxy", "http://user:secret@proxy.local:8080")
    session.save()

    raw = path.read_text()
    assert "secret" not in raw
    assert "proxy" not in json.loads(raw)["settings"]

    reloaded = Session(session_file=path)
    reloaded.load()
    assert reloaded.settings["proxy"] is None


def test_session_file_is_owner_only(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "session.json"
    Session(session_file=path).save()
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600


def test_load_missing_file_is_noop(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    session = Session(session_file=tmp_path / "absent.json")
    assert session.load() == (0, [])
    assert session.targets == {}


def test_load_corrupt_file_warns(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "session.json"
    path.write_text("{not json")
    session = Session(session_file=path)
    loaded, warnings = session.load()
    assert loaded == 0
    assert len(warnings) == 1


def test_load_skips_invalid_targets(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "session.json"
    path.write_text(json.dumps({
        "targets": {
            "good": {"type": "domain", "value": "example.com"},
            "bad-domain": {"type": "domain", "value": "../../etc/passwd"},
            "bad-type": {"type": "phone", "value": "555-1234"},
            "bad alias": {"type": "domain", "value": "example.com"},
            "not-a-dict": "nope",
        },
        "settings": {},
    }))

    session = Session(session_file=path)
    loaded, warnings = session.load()
    assert loaded == 1
    assert list(session.targets) == ["good"]
    assert len(warnings) == 3


def test_load_ignores_unknown_and_invalid_settings(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "session.json"
    path.write_text(json.dumps({
        "targets": {},
        "settings": {"timeout": 25, "formats": "pdf", "made_up": 1},
    }))

    session = Session(session_file=path)
    _, warnings = session.load()
    assert session.settings["timeout"] == 25
    assert session.settings["formats"] == DEFAULT_SETTINGS["formats"]
    assert "made_up" not in session.settings
    assert len(warnings) == 1


def test_save_returns_none_when_path_unwritable(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    session = Session(session_file=blocker / "session.json")
    assert session.save() is None


def test_every_setting_has_a_default():
    assert set(SETTING_SPECS) == set(DEFAULT_SETTINGS)
