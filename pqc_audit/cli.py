"""Command-line interface for the PQC readiness audit tool.

Three subcommands:

  pqc-audit scan    TARGETS.csv -o scan_results.json
  pqc-audit report  scan_results.json -o report.md
  pqc-audit audit    TARGETS.csv -o report.md   (scan + classify + score + report in one step)
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from pqc_audit.models import Finding, TargetSpec
from pqc_audit.report import write_report
from pqc_audit.risk import ThreatModel, prioritize
from pqc_audit.rules import RuleEngine
from pqc_audit.scan_io import load_scan_results, save_scan_results
from pqc_audit.scanner import scan_targets
from pqc_audit.targets_io import load_targets_csv


def _classify_and_score(targets, observations, rules_path, threat_horizon_years):
    engine = RuleEngine.load(rules_path)
    findings: list[Finding] = engine.classify_all(observations)
    targets_by_name = {t.display_name(): t for t in targets}
    scored = prioritize(findings, targets_by_name, ThreatModel(threat_horizon_years=threat_horizon_years))
    return findings, scored


@click.group()
@click.version_option()
def cli():
    """PQC readiness audit: scan TLS/certificate crypto, classify quantum risk, prioritize, report."""


@cli.command()
@click.argument("targets_csv", type=click.Path(exists=True, dir_okay=False))
@click.option("-o", "--output", "output_path", required=True, type=click.Path(dir_okay=False), help="Where to write scan_results.json")
@click.option("--include-legacy-ssl", is_flag=True, default=False, help="Also probe SSLv2/SSLv3 (slower; rarely offered by modern servers).")
def scan(targets_csv, output_path, include_legacy_ssl):
    """Scan targets in TARGETS_CSV and save raw crypto observations to JSON."""
    targets = load_targets_csv(targets_csv)
    if not targets:
        click.secho(f"No targets found in {targets_csv}", fg="red", err=True)
        sys.exit(1)

    click.echo(f"Scanning {len(targets)} target(s)...")
    observations, errors = scan_targets(targets, include_legacy_ssl=include_legacy_ssl)

    for e in errors:
        click.secho(f"  [error] {e.target}: {e.reason}", fg="yellow", err=True)

    scanned_hosts = {o.target for o in observations}
    click.echo(f"Collected {len(observations)} crypto observation(s) from {len(scanned_hosts)} asset(s).")

    out = save_scan_results(targets, observations, errors, output_path)
    click.secho(f"Wrote {out}", fg="green")


@cli.command()
@click.argument("scan_results_json", type=click.Path(exists=True, dir_okay=False))
@click.option("-o", "--output", "output_path", required=True, type=click.Path(dir_okay=False), help="Report output path (.md or .html)")
@click.option("--format", "fmt", type=click.Choice(["markdown", "html"]), default=None, help="Defaults based on output file extension.")
@click.option("--threat-horizon-years", type=int, default=10, show_default=True, help="Assumed years until a cryptographically relevant quantum computer exists.")
@click.option("--rules", "rules_path", type=click.Path(exists=True, dir_okay=False), default=None, help="Custom rules.yaml (defaults to the packaged rule table).")
def report(scan_results_json, output_path, fmt, threat_horizon_years, rules_path):
    """Classify, prioritize, and render a report from a previous `scan`."""
    targets, observations, errors = load_scan_results(scan_results_json)
    findings, scored = _classify_and_score(targets, observations, rules_path, threat_horizon_years)

    out = write_report(findings, scored, targets, errors, output_path, threat_horizon_years, fmt)
    click.secho(f"Wrote {out}", fg="green")

    critical = sum(1 for r in scored if r.priority_tier == "Critical")
    high = sum(1 for r in scored if r.priority_tier == "High")
    click.echo(f"{critical} Critical, {high} High priority finding(s).")


@cli.command()
@click.argument("targets_csv", type=click.Path(exists=True, dir_okay=False))
@click.option("-o", "--output", "output_path", required=True, type=click.Path(dir_okay=False), help="Report output path (.md or .html)")
@click.option("--format", "fmt", type=click.Choice(["markdown", "html"]), default=None, help="Defaults based on output file extension.")
@click.option("--save-scan-results", "scan_results_out", type=click.Path(dir_okay=False), default=None, help="Also save the raw scan JSON here.")
@click.option("--threat-horizon-years", type=int, default=10, show_default=True, help="Assumed years until a cryptographically relevant quantum computer exists.")
@click.option("--rules", "rules_path", type=click.Path(exists=True, dir_okay=False), default=None, help="Custom rules.yaml (defaults to the packaged rule table).")
@click.option("--include-legacy-ssl", is_flag=True, default=False, help="Also probe SSLv2/SSLv3.")
def audit(targets_csv, output_path, fmt, scan_results_out, threat_horizon_years, rules_path, include_legacy_ssl):
    """Scan, classify, prioritize, and report in one step."""
    targets = load_targets_csv(targets_csv)
    if not targets:
        click.secho(f"No targets found in {targets_csv}", fg="red", err=True)
        sys.exit(1)

    click.echo(f"Scanning {len(targets)} target(s)...")
    observations, errors = scan_targets(targets, include_legacy_ssl=include_legacy_ssl)
    for e in errors:
        click.secho(f"  [error] {e.target}: {e.reason}", fg="yellow", err=True)

    if scan_results_out:
        save_scan_results(targets, observations, errors, scan_results_out)

    findings, scored = _classify_and_score(targets, observations, rules_path, threat_horizon_years)
    out = write_report(findings, scored, targets, errors, output_path, threat_horizon_years, fmt)

    critical = sum(1 for r in scored if r.priority_tier == "Critical")
    high = sum(1 for r in scored if r.priority_tier == "High")
    click.secho(f"Wrote {out}", fg="green")
    click.echo(f"{critical} Critical, {high} High priority finding(s) across {len(targets)} asset(s).")


if __name__ == "__main__":
    cli()
