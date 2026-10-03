import json

import pytest

import main
from main import DOMAIN_SCAN_TYPES, SPYLOShell, Session


@pytest.fixture
def shell(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    session = Session(session_file=tmp_path / "session.json")
    session.set_setting("output_dir", str(tmp_path / "out"))
    return SPYLOShell(session=session, show_banner=False)


# ----------------------------------------------------------------------
# Target management
# ----------------------------------------------------------------------

def test_add_target(shell):
    shell.do_add("site1 domain Example.com")
    assert shell.session.targets["site1"] == {
        "type": "domain", "value": "example.com", "last_scan": None
    }


def test_add_persists_immediately(shell):
    shell.do_add("site1 domain example.com")
    saved = json.loads(shell.session.session_file.read_text())
    assert "site1" in saved["targets"]


@pytest.mark.parametrize("args", [
    "",
    "site1",
    "site1 domain",
    "site1 domain example.com extra",
    "site1 domain ../../etc/passwd",
    "site1 domain http://example.com",
    "site1 username a/b",
    "bad alias domain example.com",
])
def test_add_rejects_bad_input(shell, args):
    shell.do_add(args)
    assert shell.session.targets == {}


def test_add_rejects_duplicate_alias(shell):
    shell.do_add("site1 domain example.com")
    shell.do_add("site1 domain other.com")
    assert shell.session.targets["site1"]["value"] == "example.com"


def test_del_removes_target(shell):
    shell.do_add("site1 domain example.com")
    shell.do_del("site1")
    assert shell.session.targets == {}
    assert json.loads(shell.session.session_file.read_text())["targets"] == {}


@pytest.mark.parametrize("args", ["", "   ", "missing"])
def test_del_rejects_bad_input(shell, args):
    shell.do_add("site1 domain example.com")
    shell.do_del(args)
    assert "site1" in shell.session.targets


def test_list_runs_with_and_without_targets(shell):
    shell.do_list("")
    shell.do_add("site1 domain example.com")
    shell.do_list("")


# Regression: `clear` was documented as clearing the screen but wiped every
# target instead.
def test_clear_does_not_remove_targets(shell):
    shell.do_add("site1 domain example.com")
    shell.do_clear("")
    shell.do_c("")
    assert "site1" in shell.session.targets


def test_reset_cancels_without_confirmation(shell, monkeypatch):
    shell.do_add("site1 domain example.com")
    monkeypatch.setattr("builtins.input", lambda *a: "n")
    shell.do_reset("")
    assert "site1" in shell.session.targets


def test_reset_removes_all_on_confirmation(shell, monkeypatch):
    shell.do_add("site1 domain example.com")
    monkeypatch.setattr("builtins.input", lambda *a: "y")
    shell.do_reset("")
    assert shell.session.targets == {}


def test_reset_treats_closed_stdin_as_no(shell, monkeypatch):
    shell.do_add("site1 domain example.com")

    def raise_eof(*args):
        raise EOFError

    monkeypatch.setattr("builtins.input", raise_eof)
    shell.do_reset("")
    assert "site1" in shell.session.targets


# ----------------------------------------------------------------------
# Settings
# ----------------------------------------------------------------------

def test_config_and_set_exist():
    for name in ("do_del", "do_set", "do_config", "do_save", "do_reset"):
        assert callable(getattr(SPYLOShell, name))


def test_set_updates_setting(shell):
    shell.do_set("timeout 30")
    assert shell.session.settings["timeout"] == 30


def test_set_rejects_bad_value(shell):
    shell.do_set("timeout nope")
    assert shell.session.settings["timeout"] == 15


def test_set_rejects_unknown_option(shell):
    shell.do_set("bogus 1")
    assert "bogus" not in shell.session.settings


def test_set_without_value_warns(shell):
    shell.do_set("timeout")
    assert shell.session.settings["timeout"] == 15


def test_set_with_no_args_shows_config(shell):
    shell.do_set("")


def test_set_persists(shell):
    shell.do_set("formats json,csv")
    saved = json.loads(shell.session.session_file.read_text())
    assert saved["settings"]["formats"] == "json,csv"


def test_config_runs(shell):
    shell.do_config("")


def test_save_command(shell):
    shell.do_save("")
    assert shell.session.session_file.is_file()


def test_exit_saves_and_stops(shell):
    shell.do_add("site1 domain example.com")
    assert shell.do_exit("") is True
    assert json.loads(shell.session.session_file.read_text())["targets"]


# ----------------------------------------------------------------------
# Scanning
# ----------------------------------------------------------------------

# Regression: _save_result indexed session.targets by the target value
# instead of the alias, so any aliased target raised KeyError.
def test_save_result_keyed_by_alias(shell):
    shell.do_add("site1 domain example.com")
    shell._save_result("site1", "domain", "all", {"summary": {"a_records": 1}})
    assert shell.session.targets["site1"]["last_scan"] is not None


def test_save_result_writes_requested_formats(shell, tmp_path):
    shell.do_add("site1 domain example.com")
    shell.do_set("formats json,csv,md")
    shell._save_result("site1", "domain", "dns", {"summary": {"a_records": 1}})

    produced = sorted(p.suffix for p in (tmp_path / "out").iterdir())
    assert produced == [".csv", ".json", ".md"]


def test_save_result_report_contains_alias_and_target(shell, tmp_path):
    shell.do_add("site1 domain example.com")
    shell.do_set("formats json")
    shell._save_result("site1", "domain", "all", {})

    report = next((tmp_path / "out").glob("*.json"))
    meta = json.loads(report.read_text())["meta"]
    assert meta["alias"] == "site1"
    assert meta["target"] == "example.com"
    assert meta["module"] == "domain"
    assert meta["scan_type"] == "all"


def test_scan_unknown_alias_does_nothing(shell):
    shell.do_scan("nope")


def test_scan_rejects_invalid_domain_scan_type(shell, monkeypatch):
    shell.do_add("site1 domain example.com")
    monkeypatch.setattr(main, "DomainScanner", _unexpected_call)
    shell.do_scan("site1 bogus")
    assert shell.session.targets["site1"]["last_scan"] is None


def _unexpected_call(*args, **kwargs):
    raise AssertionError("scanner should not have been constructed")


@pytest.mark.parametrize("scan_type,method", [
    ("all", "scan"),
    ("dns", "scan_dns"),
    ("ports", "scan_ports"),
    ("whois", "scan_whois"),
])
def test_scan_dispatches_to_the_right_method(shell, monkeypatch, scan_type, method):
    called = []

    class FakeScanner:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def __getattr__(self, name):
            def run(target):
                called.append((name, target))
                return {"summary": {}}
            return run

    monkeypatch.setattr(main, "DomainScanner", FakeScanner)
    shell.do_add("site1 domain example.com")
    shell.do_scan(f"site1 {scan_type}")
    assert called == [(method, "example.com")]


def test_username_scan_passes_verify_tls(shell, monkeypatch):
    captured = {}

    class FakeScanner:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def scan(self, target):
            return {"accounts": [], "summary": {}}

    monkeypatch.setattr(main, "UsernameScanner", FakeScanner)
    shell.do_add("user1 username john_doe")
    shell.do_set("verify_tls false")
    shell.do_scan("user1")
    assert captured["verify_tls"] is False
    assert shell.session.targets["user1"]["last_scan"] is not None


def test_username_scan_records_scan_type(shell, monkeypatch, tmp_path):
    class FakeScanner:
        def __init__(self, **kwargs):
            pass

        def scan(self, target):
            return {"accounts": [{"site": "GitHub", "url": "https://github.com/x"}]}

    monkeypatch.setattr(main, "UsernameScanner", FakeScanner)
    shell.do_set("formats json")
    shell.do_add("user1 username john_doe")
    shell.do_scan("user1 ignored")

    report = next((tmp_path / "out").glob("*.json"))
    assert json.loads(report.read_text())["meta"]["scan_type"] == "username"


def test_interrupted_scan_is_not_saved(shell, monkeypatch):
    class FakeScanner:
        def __init__(self, **kwargs):
            pass

        def scan(self, target):
            raise KeyboardInterrupt

    monkeypatch.setattr(main, "DomainScanner", FakeScanner)
    shell.do_add("site1 domain example.com")
    shell.do_scan("site1 all")
    assert shell.session.targets["site1"]["last_scan"] is None


def test_invalid_dns_server_surfaces_as_error(shell, monkeypatch):
    shell.do_add("site1 domain example.com")
    shell.session.settings["dns_server"] = "not-an-ip"
    shell.do_scan("site1 dns")
    assert shell.session.targets["site1"]["last_scan"] is None


# ----------------------------------------------------------------------
# Tab completion
# ----------------------------------------------------------------------

@pytest.mark.parametrize("line,endidx,expected", [
    ("scan ", 5, 1),
    ("scan si", 7, 1),
    ("scan site1 ", 11, 2),
    ("scan site1 dn", 13, 2),
    ("scan", 4, 1),
])
def test_arg_position(shell, line, endidx, expected):
    assert shell._arg_position(line, endidx) == expected


def test_complete_scan_suggests_aliases(shell):
    shell.do_add("site1 domain example.com")
    shell.do_add("site2 domain other.com")
    shell.do_add("user1 username bob")
    assert shell.complete_scan("", "scan ", 5, 5) == ["site1", "site2", "user1"]
    assert shell.complete_scan("si", "scan si", 5, 7) == ["site1", "site2"]


def test_complete_scan_suggests_domain_scan_types(shell):
    shell.do_add("site1 domain example.com")
    assert shell.complete_scan("", "scan site1 ", 11, 11) == list(DOMAIN_SCAN_TYPES)
    assert shell.complete_scan("d", "scan site1 d", 11, 12) == ["dns"]


def test_complete_scan_offers_no_types_for_usernames(shell):
    shell.do_add("user1 username bob")
    assert shell.complete_scan("", "scan user1 ", 11, 11) == []


def test_complete_s_shortcut_matches_scan(shell):
    shell.do_add("site1 domain example.com")
    assert shell.complete_s("", "s ", 2, 2) == ["site1"]


def test_complete_del_suggests_aliases(shell):
    shell.do_add("site1 domain example.com")
    assert shell.complete_del("", "del ", 4, 4) == ["site1"]
    assert shell.complete_del("", "del site1 ", 10, 10) == []


def test_complete_add_suggests_types(shell):
    assert shell.complete_add("", "add site1 ", 10, 10) == ["domain", "username", "email"]
    assert shell.complete_add("u", "add site1 u", 10, 11) == ["username"]
    assert shell.complete_add("e", "add site1 e", 10, 11) == ["email"]
    assert shell.complete_add("", "add ", 4, 4) == []


def test_complete_set_suggests_options_and_values(shell):
    assert "timeout" in shell.complete_set("", "set ", 4, 4)
    assert shell.complete_set("verify", "set verify", 4, 10) == ["verify_tls"]
    assert shell.complete_set("", "set verify_tls ", 15, 15) == ["true", "false"]
    assert shell.complete_set("", "set formats ", 12, 12) == list(main.SUPPORTED_FORMATS)
    assert shell.complete_set("", "set timeout ", 12, 12) == []


def test_restores_previous_session(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "session.json"

    first = SPYLOShell(session=Session(session_file=path), show_banner=False)
    first.do_add("site1 domain example.com")
    first.do_set("timeout 44")
    first.do_exit("")

    second = SPYLOShell(session=Session(session_file=path), show_banner=False)
    assert second.session.targets["site1"]["value"] == "example.com"
    assert second.session.settings["timeout"] == 44
