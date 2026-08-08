"""Report generation: turns findings + risk scores into a Markdown or HTML
audit report, anchored to public NIST/CNSA 2.0 transition guidance.

The timeline dates below are drawn from public sources (cited in the
generated report and the README) current as of this tool's last update:

- NIST IR 8547 (Nov 2024, initial public draft): deprecates ~112-bit-security
  algorithms (RSA-2048, ECC P-256) by 2030; disallows them by 2035.
- NSA CNSA 2.0 transition timetable (2022, reaffirmed 2025): CNSA 2.0-only
  for new National Security Systems acquisitions from Jan 1 2027; software
  signing exclusively CNSA 2.0 by 2030; web/cloud/OS by 2033.
- OMB M-26-15: directs federal agencies to align migration plans with NIST
  IR 8547 and sets 2035 as the full-migration deadline for remaining
  systems, per National Security Memorandum 10.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Literal

from jinja2 import Environment, FileSystemLoader, select_autoescape

from pqc_audit.models import Classification, Finding, RiskScoredFinding, ScanError, TargetSpec

TIMELINE = [
    {
        "date": "Aug 2024",
        "description": (
            "NIST finalizes the first PQC standards: FIPS 203 (ML-KEM / Kyber, key "
            "encapsulation), FIPS 204 (ML-DSA / Dilithium, signatures), and FIPS 205 "
            "(SLH-DSA / SPHINCS+, signatures)."
        ),
    },
    {
        "date": "Nov 2024",
        "description": (
            "NIST IR 8547 (initial public draft) proposes deprecating ~112-bit-security "
            "classical algorithms (RSA-2048, ECC P-256/secp256r1) by 2030."
        ),
    },
    {
        "date": "Jan 1, 2027",
        "description": (
            "CNSA 2.0: new National Security System equipment acquisitions are expected "
            "to be CNSA 2.0-compliant by default."
        ),
    },
    {
        "date": "2030",
        "description": (
            "NIST target deprecation date for RSA-2048/ECC P-256-class algorithms. "
            "CNSA 2.0 target for exclusive use on software/firmware signing and "
            "networking equipment."
        ),
    },
    {
        "date": "2033",
        "description": "CNSA 2.0 target for exclusive use on web, cloud, and operating systems.",
    },
    {
        "date": "2035",
        "description": (
            "NIST target date after which RSA/ECC (at any key size) are disallowed. "
            "OMB M-26-15 sets this as the full-migration deadline for remaining federal "
            "systems, consistent with National Security Memorandum 10."
        ),
    },
]

_TEMPLATE_DIR = resources.files("pqc_audit").joinpath("templates")


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _quantum_vulnerable_label(finding: Finding) -> str:
    if finding.classification == Classification.VULNERABLE:
        if finding.quantum_attack == "shor":
            return "Yes"
        if finding.quantum_attack == "grover":
            return "Yes (classically broken, also quantum-weakened)"
        return "Yes (classical)"
    if finding.classification == Classification.WEAKENED:
        return "Partially (Grover)"
    if finding.classification in (Classification.SAFE, Classification.PQC):
        return "No"
    return "Unknown"


def _build_findings_table(findings: list[Finding]) -> list[dict]:
    rows = []
    for f in findings:
        obs = f.observation
        rows.append(
            {
                "asset": obs.target,
                "protocol_version": obs.protocol_version,
                "mechanism": obs.mechanism.value.replace("_", " "),
                "algorithm": obs.algorithm,
                "key_size": obs.key_size,
                "expiry": obs.not_valid_after.strftime("%Y-%m-%d") if obs.not_valid_after else None,
                "quantum_vulnerable": _quantum_vulnerable_label(f),
                "classification": f.classification.value.capitalize(),
            }
        )
    return rows


def _build_roadmap(scored: list[RiskScoredFinding]) -> dict[str, list[dict]]:
    roadmap: dict[str, list[dict]] = {"Critical": [], "High": [], "Medium": [], "Low": []}
    for rsf in scored:
        if rsf.priority_tier not in roadmap:
            continue  # Informational (Safe/PQC) findings don't belong on a remediation roadmap.
        obs = rsf.finding.observation
        roadmap[rsf.priority_tier].append(
            {
                "asset": rsf.asset,
                "protocol_version": obs.protocol_version,
                "algorithm": obs.algorithm,
                "classification": rsf.finding.classification.value.capitalize(),
                "quantum_attack": rsf.finding.quantum_attack,
                "rationale": rsf.finding.rationale,
                "recommended_replacement": rsf.finding.recommended_replacement,
                "remediation_complexity": rsf.remediation_complexity,
                "exposure": rsf.target.exposure.value,
                "retention_years": rsf.target.retention_years,
                "priority_score": rsf.priority_score,
            }
        )
    for tier_rows in roadmap.values():
        tier_rows.sort(key=lambda r: r["priority_score"], reverse=True)
    return roadmap


def build_context(
    findings: list[Finding],
    scored: list[RiskScoredFinding],
    targets: list[TargetSpec],
    scan_errors: list[ScanError],
    threat_horizon_years: int,
) -> dict:
    vulnerable = [f for f in findings if f.classification == Classification.VULNERABLE]
    weakened = [f for f in findings if f.classification == Classification.WEAKENED]
    safe = [f for f in findings if f.classification == Classification.SAFE]
    pqc = [f for f in findings if f.classification == Classification.PQC]
    unknown = [f for f in findings if f.classification == Classification.UNKNOWN]

    internet_facing_hndl = [
        rsf for rsf in scored if rsf.hndl_relevant and rsf.target.exposure.value == "internet"
    ]

    summary = {
        "total_assets": len(targets),
        "total_findings": len(findings),
        "vulnerable_count": len(vulnerable),
        "weakened_count": len(weakened),
        "safe_count": len(safe),
        "pqc_count": len(pqc),
        "unknown_count": len(unknown),
        "critical_count": sum(1 for r in scored if r.priority_tier == "Critical"),
        "high_count": sum(1 for r in scored if r.priority_tier == "High"),
        "internet_facing_hndl_count": len(internet_facing_hndl),
    }

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "threat_horizon_years": threat_horizon_years,
        "summary": summary,
        "scan_errors": [asdict(e) for e in scan_errors],
        "findings_table": _build_findings_table(findings),
        "roadmap": _build_roadmap(scored),
        "timeline": TIMELINE,
    }


def render_report(
    findings: list[Finding],
    scored: list[RiskScoredFinding],
    targets: list[TargetSpec],
    scan_errors: list[ScanError],
    threat_horizon_years: int = 10,
    fmt: Literal["markdown", "html"] = "markdown",
) -> str:
    context = build_context(findings, scored, targets, scan_errors, threat_horizon_years)
    template_name = "report.md.j2" if fmt == "markdown" else "report.html.j2"
    template = _env().get_template(template_name)
    return template.render(**context)


def write_report(
    findings: list[Finding],
    scored: list[RiskScoredFinding],
    targets: list[TargetSpec],
    scan_errors: list[ScanError],
    output_path: str | Path,
    threat_horizon_years: int = 10,
    fmt: Literal["markdown", "html"] | None = None,
) -> Path:
    output_path = Path(output_path)
    if fmt is None:
        fmt = "html" if output_path.suffix.lower() in (".html", ".htm") else "markdown"
    content = render_report(findings, scored, targets, scan_errors, threat_horizon_years, fmt)
    output_path.write_text(content)
    return output_path
