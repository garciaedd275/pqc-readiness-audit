"""Risk-prioritization model.

Turns a flat list of classified findings into a ranked remediation list by
combining three inputs an auditor actually cares about:

1. Severity of the crypto weakness itself (a broken key exchange is worse
   than a slightly-thin symmetric cipher).
2. Whether "harvest now, decrypt later" (HNDL) applies at all, and if so,
   whether the data's required secrecy lifetime (`retention_years`) extends
   past the point a cryptographically relevant quantum computer (CRQC) is
   plausibly expected to exist (`threat_horizon_years`). HNDL is a
   confidentiality attack: it only applies to key-exchange algorithms,
   because those are what protect the encrypted payload an eavesdropper
   would have recorded. A broken *signature* algorithm doesn't let an
   attacker retroactively decrypt anything they captured today — it's a
   forward-looking integrity/spoofing risk instead — so it does not get the
   HNDL retention multiplier.
3. Exposure: internet-facing assets are reachable by any attacker who wants
   to record traffic today; internal-only assets still matter (insider
   threat, lateral movement) but less urgently.

Remediation complexity is scored separately (low/medium/high) so the report
can call out fast, no-regrets wins (disable a legacy protocol) versus work
that genuinely has to wait on the PQC ecosystem maturing (hybrid KEM
deployment for a healthy, modern ECDHE configuration).
"""

from __future__ import annotations

from dataclasses import dataclass

from pqc_audit.models import (
    Classification,
    Finding,
    Mechanism,
    RiskScoredFinding,
    TargetSpec,
)

_LEGACY_PROTOCOLS = {"SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"}

_SEVERITY_BY_CLASSIFICATION_AND_MECHANISM = {
    (Classification.VULNERABLE, Mechanism.KEY_EXCHANGE): 10.0,
    (Classification.VULNERABLE, Mechanism.SIGNATURE): 7.0,
    (Classification.VULNERABLE, Mechanism.SYMMETRIC): 8.0,
    (Classification.VULNERABLE, Mechanism.HASH): 5.0,
    (Classification.WEAKENED, Mechanism.KEY_EXCHANGE): 5.0,
    (Classification.WEAKENED, Mechanism.SYMMETRIC): 4.0,
    (Classification.WEAKENED, Mechanism.SIGNATURE): 4.0,
    (Classification.WEAKENED, Mechanism.HASH): 3.0,
    (Classification.UNKNOWN, Mechanism.KEY_EXCHANGE): 3.0,
    (Classification.UNKNOWN, Mechanism.SIGNATURE): 3.0,
    (Classification.UNKNOWN, Mechanism.SYMMETRIC): 2.0,
    (Classification.UNKNOWN, Mechanism.HASH): 2.0,
}

_EXPOSURE_MULTIPLIER = {"internet": 1.4, "internal": 1.0}

_COMPLEXITY_PENALTY = {"low": 0.0, "medium": 1.0, "high": 2.0}


@dataclass
class ThreatModel:
    """Assumptions the risk score is computed against.

    `threat_horizon_years` is the auditor's working estimate of "years until
    a CRQC plausibly exists that can run Shor's algorithm at scale." There
    is no consensus date; NIST/NSA guidance (see the report's timeline
    section) treats the early-to-mid 2030s as the point classical
    algorithms must be fully retired, which implies harvested traffic
    protected only by those algorithms is already at risk today for
    anything that must stay confidential past that point. 10 years is a
    reasonable default working assumption for a 2026 audit; override it if
    your organization has a different quantum-risk position.
    """

    threat_horizon_years: int = 10


def _severity_score(finding: Finding) -> float:
    key = (finding.classification, finding.observation.mechanism)
    return _SEVERITY_BY_CLASSIFICATION_AND_MECHANISM.get(key, 0.0)


def _hndl_relevant(finding: Finding) -> bool:
    return (
        finding.classification == Classification.VULNERABLE
        and finding.observation.mechanism == Mechanism.KEY_EXCHANGE
        and finding.quantum_attack == "shor"
    )


def _hndl_multiplier(finding: Finding, target: TargetSpec, threat_horizon_years: int) -> float:
    if not _hndl_relevant(finding):
        return 1.0
    if target.retention_years >= threat_horizon_years:
        return 1.5
    if target.retention_years >= threat_horizon_years / 2:
        return 1.2
    return 0.9


def _remediation_complexity(finding: Finding) -> str:
    obs = finding.observation
    is_legacy_protocol = obs.protocol_version in _LEGACY_PROTOCOLS
    is_static_kex = "static key exchange" in obs.detail

    if finding.classification in (Classification.SAFE, Classification.PQC):
        return "low"

    if is_legacy_protocol or is_static_kex:
        # Disabling a legacy protocol or a static (non-forward-secret) key
        # exchange is a server/load-balancer TLS config change — no code,
        # no new certificates, testable in a maintenance window.
        return "low"

    if obs.mechanism == Mechanism.SYMMETRIC and finding.classification == Classification.WEAKENED:
        # Raising the minimum negotiable cipher to AES-256 is a config change.
        return "low"

    if obs.mechanism == Mechanism.SYMMETRIC and finding.classification == Classification.VULNERABLE:
        # RC4/3DES/NULL: also just a cipher-suite policy change.
        return "low"

    if obs.mechanism == Mechanism.SIGNATURE:
        # Requires reissuing a certificate (new key or new CA product),
        # coordinating with a CA, and testing client compatibility.
        return "medium"

    if obs.mechanism == Mechanism.KEY_EXCHANGE and finding.quantum_attack == "shor":
        # A modern ECDHE/DHE key exchange isn't broken today — the fix is a
        # hybrid PQC KEM (e.g. X25519+ML-KEM), which depends on the PQC
        # ecosystem (TLS libraries, load balancers, HSMs) maturing.
        return "high"

    return "medium"


def _priority_tier(score: float) -> str:
    if score <= 0:
        return "Informational"
    if score >= 15:
        return "Critical"
    if score >= 9:
        return "High"
    if score >= 4:
        return "Medium"
    return "Low"


def score_finding(
    finding: Finding, target: TargetSpec, threat_model: ThreatModel | None = None
) -> RiskScoredFinding:
    threat_model = threat_model or ThreatModel()

    severity = _severity_score(finding)
    hndl_relevant = _hndl_relevant(finding)
    hndl_mult = _hndl_multiplier(finding, target, threat_model.threat_horizon_years)
    exposure_mult = _EXPOSURE_MULTIPLIER.get(target.exposure.value, 1.0)
    complexity = _remediation_complexity(finding)
    complexity_penalty = _COMPLEXITY_PENALTY[complexity]

    priority_score = max(0.0, round(severity * hndl_mult * exposure_mult - complexity_penalty, 2))

    return RiskScoredFinding(
        finding=finding,
        target=target,
        severity_score=severity,
        hndl_relevant=hndl_relevant,
        exposure_multiplier=exposure_mult,
        hndl_multiplier=hndl_mult,
        remediation_complexity=complexity,
        priority_score=priority_score,
        priority_tier=_priority_tier(priority_score),
    )


def prioritize(
    findings: list[Finding],
    targets_by_name: dict[str, TargetSpec],
    threat_model: ThreatModel | None = None,
) -> list[RiskScoredFinding]:
    """Score every finding and return them sorted highest-priority first."""
    threat_model = threat_model or ThreatModel()
    scored = [
        score_finding(f, targets_by_name[f.observation.target], threat_model) for f in findings
    ]
    scored.sort(key=lambda rsf: rsf.priority_score, reverse=True)
    return scored
