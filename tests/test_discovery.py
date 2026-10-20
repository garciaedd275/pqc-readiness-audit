import json

import pytest
from click.testing import CliRunner

from pqc_audit import discovery
from pqc_audit.cli import cli
from pqc_audit.targets_io import load_targets_csv


def test_normalize_domain():
    assert discovery.normalize_domain(" Example.COM. ") == "example.com"
    assert discovery.normalize_domain("*.example.com") == "example.com"


@pytest.mark.parametrize("bad", ["", "localhost", "exa mple.com", "example.com/path", "-bad.example.com"])
def test_normalize_domain_rejects_invalid(bad):
    with pytest.raises(ValueError):
        discovery.normalize_domain(bad)


def test_parse_ct_names_filters_and_dedupes():
    records = [
        {"name_value": "example.com\nwww.example.com"},
        {"name_value": "*.example.com\nvpn.example.com"},
        {"name_value": "Mail.Example.com.\nunrelated.org\nevilexample.com"},
        {"name_value": "bad name.example.com"},
    ]
    names = discovery.parse_ct_names(records, "example.com")
    assert names == {"example.com", "www.example.com", "vpn.example.com", "mail.example.com"}


def test_write_targets_csv_roundtrips_through_loader(tmp_path):
    resolved = {"a.example.com": ["192.0.2.1"], "dead.example.com": []}
    path = tmp_path / "t.csv"
    assert discovery.write_targets_csv(path, resolved, retention_years=5) == 1
    targets = load_targets_csv(path)
    assert [t.hostname for t in targets] == ["a.example.com"]
    assert targets[0].retention_years == 5

    assert discovery.write_targets_csv(path, resolved, include_unresolved=True) == 2


def test_fetch_ct_names_uses_crtsh(monkeypatch):
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return json.dumps([{"name_value": "www.example.com"}]).encode()

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        return FakeResponse()

    monkeypatch.setattr(discovery.urllib.request, "urlopen", fake_urlopen)
    assert discovery.fetch_ct_names("example.com") == {"www.example.com"}
    assert captured["url"].startswith("https://crt.sh/?q=%25.example.com")


def test_discover_command_writes_csv(tmp_path, monkeypatch):
    monkeypatch.setattr("pqc_audit.cli.fetch_ct_names", lambda d, timeout: {"a.example.com", "b.example.com"})
    monkeypatch.setattr(
        "pqc_audit.cli.resolve_names", lambda names: {"a.example.com": ["192.0.2.1"], "b.example.com": []}
    )
    out = tmp_path / "targets.csv"
    result = CliRunner().invoke(cli, ["discover", "example.com", "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert [t.hostname for t in load_targets_csv(out)] == ["a.example.com"]


def test_discover_command_rejects_bad_domain(tmp_path):
    result = CliRunner().invoke(cli, ["discover", "not a domain", "-o", str(tmp_path / "t.csv")])
    assert result.exit_code != 0


def test_discover_command_reports_lookup_failure(tmp_path, monkeypatch):
    def boom(domain, timeout):
        raise OSError("timed out")

    monkeypatch.setattr("pqc_audit.cli.fetch_ct_names", boom)
    result = CliRunner().invoke(cli, ["discover", "example.com", "-o", str(tmp_path / "t.csv")])
    assert result.exit_code == 1


def test_fetch_ct_names_retries_on_5xx(monkeypatch):
    calls = {"n": 0}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return json.dumps([{"name_value": "www.example.com"}]).encode()

    def flaky_urlopen(request, timeout):
        calls["n"] += 1
        if calls["n"] < 3:
            raise discovery.urllib.error.HTTPError(request.full_url, 502, "Bad Gateway", None, None)
        return FakeResponse()

    monkeypatch.setattr(discovery.urllib.request, "urlopen", flaky_urlopen)
    assert discovery.fetch_ct_names("example.com", backoff=0) == {"www.example.com"}
    assert calls["n"] == 3


def test_fetch_ct_names_gives_up_after_attempts(monkeypatch):
    def always_502(request, timeout):
        raise discovery.urllib.error.HTTPError(request.full_url, 502, "Bad Gateway", None, None)

    monkeypatch.setattr(discovery.urllib.request, "urlopen", always_502)
    with pytest.raises(RuntimeError):
        discovery.fetch_ct_names("example.com", attempts=2, backoff=0)
