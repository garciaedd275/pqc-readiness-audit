import pytest

from pqc_audit.models import Exposure
from pqc_audit.targets_io import load_targets_csv


def test_load_targets_csv_full(tmp_path):
    csv_path = tmp_path / "targets.csv"
    csv_path.write_text(
        "hostname,port,exposure,retention_years,asset_name,notes\n"
        "example.com,443,internet,10,Example Site,Public marketing site\n"
        "internal-vpn.corp,8443,internal,25,VPN Gateway,Handles customer PII\n"
    )
    targets = load_targets_csv(csv_path)
    assert len(targets) == 2
    assert targets[0].hostname == "example.com"
    assert targets[0].exposure == Exposure.INTERNET
    assert targets[0].retention_years == 10
    assert targets[1].exposure == Exposure.INTERNAL
    assert targets[1].asset_name == "VPN Gateway"


def test_load_targets_csv_defaults(tmp_path):
    csv_path = tmp_path / "targets.csv"
    csv_path.write_text("hostname\nexample.com\n")
    targets = load_targets_csv(csv_path)
    assert targets[0].port == 443
    assert targets[0].exposure == Exposure.INTERNET
    assert targets[0].retention_years == 1
    assert targets[0].asset_name is None


def test_load_targets_csv_rejects_bad_exposure(tmp_path):
    csv_path = tmp_path / "targets.csv"
    csv_path.write_text("hostname,exposure\nexample.com,cloud\n")
    with pytest.raises(ValueError):
        load_targets_csv(csv_path)


def test_load_targets_csv_skips_blank_hostname_rows(tmp_path):
    csv_path = tmp_path / "targets.csv"
    csv_path.write_text("hostname,notes\nexample.com,ok\n,skip me\n")
    targets = load_targets_csv(csv_path)
    assert len(targets) == 1
