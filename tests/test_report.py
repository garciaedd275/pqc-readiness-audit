from pqc_audit.models import (
    Classification,
    CryptoObservation,
    Exposure,
    Finding,
    Mechanism,
    ScanError,
    TargetSpec,
)
from pqc_audit.report import build_context, render_report
from pqc_audit.risk import prioritize


def _sample_data():
    target = TargetSpec(hostname="example.com", port=443, exposure=Exposure.INTERNET, retention_years=15, asset_name="example.com:443")
    vulnerable_obs = CryptoObservation(
        target="example.com:443", mechanism=Mechanism.KEY_EXCHANGE, algorithm="RSA", key_size=2048, protocol_version="TLS 1.2"
    )
    safe_obs = CryptoObservation(
        target="example.com:443", mechanism=Mechanism.SYMMETRIC, algorithm="AES_256_GCM", key_size=256, protocol_version="TLS 1.3"
    )
    findings = [
        Finding(vulnerable_obs, Classification.VULNERABLE, "RSA is Shor-broken", "migrate to ML-KEM", "shor"),
        Finding(safe_obs, Classification.SAFE, "AES-256 retains margin", "no action needed", "grover"),
    ]
    targets_by_name = {target.display_name(): target}
    scored = prioritize(findings, targets_by_name)
    return findings, scored, [target], []


def test_build_context_summary_counts():
    findings, scored, targets, errors = _sample_data()
    ctx = build_context(findings, scored, targets, errors, threat_horizon_years=10)
    assert ctx["summary"]["total_findings"] == 2
    assert ctx["summary"]["vulnerable_count"] == 1
    assert ctx["summary"]["safe_count"] == 1
    assert ctx["summary"]["internet_facing_hndl_count"] == 1


def test_render_markdown_contains_key_sections():
    findings, scored, targets, errors = _sample_data()
    text = render_report(findings, scored, targets, errors, fmt="markdown")
    assert "# Post-Quantum Cryptography (PQC) Readiness Report" in text
    assert "## Executive Summary" in text
    assert "## Prioritized Remediation Roadmap" in text
    assert "## Migration Timeline" in text
    # Rows must be on their own lines, not smashed together.
    assert "| example.com:443 |" in text
    lines_with_pipe = [l for l in text.splitlines() if l.startswith("|")]
    assert len(lines_with_pipe) >= 4


def test_render_html_contains_table_and_badges():
    findings, scored, targets, errors = _sample_data()
    html = render_report(findings, scored, targets, errors, fmt="html")
    assert "<table>" in html
    assert "badge vulnerable" in html
    assert "example.com:443" in html


def test_scan_errors_appear_in_report():
    findings, scored, targets, _ = _sample_data()
    errors = [ScanError(target="broken.example.com:443", reason="Connection timed out")]
    text = render_report(findings, scored, targets, errors, fmt="markdown")
    assert "broken.example.com:443" in text
    assert "Connection timed out" in text
