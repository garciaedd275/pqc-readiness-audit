from click.testing import CliRunner

from pqc_audit.cli import cli
from pqc_audit.models import CryptoObservation, Exposure, Mechanism, TargetSpec
from pqc_audit.scan_io import save_scan_results


def _write_fixture_scan(path):
    targets = [
        TargetSpec(hostname="example.com", port=443, exposure=Exposure.INTERNET, retention_years=5, asset_name="Example Site")
    ]
    observations = [
        CryptoObservation(target="Example Site", mechanism=Mechanism.KEY_EXCHANGE, algorithm="RSA", key_size=2048, protocol_version="TLS 1.2"),
        CryptoObservation(target="Example Site", mechanism=Mechanism.SYMMETRIC, algorithm="AES_256_GCM", key_size=256, protocol_version="TLS 1.3"),
    ]
    save_scan_results(targets, observations, [], path)


def test_report_command_generates_markdown(tmp_path):
    scan_json = tmp_path / "scan.json"
    _write_fixture_scan(scan_json)
    output_md = tmp_path / "report.md"

    runner = CliRunner()
    result = runner.invoke(cli, ["report", str(scan_json), "-o", str(output_md)])

    assert result.exit_code == 0, result.output
    assert output_md.exists()
    content = output_md.read_text()
    assert "Post-Quantum Cryptography (PQC) Readiness Report" in content


def test_report_command_generates_html_from_extension(tmp_path):
    scan_json = tmp_path / "scan.json"
    _write_fixture_scan(scan_json)
    output_html = tmp_path / "report.html"

    runner = CliRunner()
    result = runner.invoke(cli, ["report", str(scan_json), "-o", str(output_html)])

    assert result.exit_code == 0, result.output
    assert "<table>" in output_html.read_text()


def test_report_command_with_custom_threat_horizon(tmp_path):
    scan_json = tmp_path / "scan.json"
    _write_fixture_scan(scan_json)
    output_md = tmp_path / "report.md"

    runner = CliRunner()
    result = runner.invoke(
        cli, ["report", str(scan_json), "-o", str(output_md), "--threat-horizon-years", "20"]
    )
    assert result.exit_code == 0, result.output
    assert "20 years" in output_md.read_text()


def test_scan_command_rejects_empty_targets_file(tmp_path):
    empty_csv = tmp_path / "empty.csv"
    empty_csv.write_text("hostname\n")
    output_json = tmp_path / "scan.json"

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(empty_csv), "-o", str(output_json)])
    assert result.exit_code != 0
