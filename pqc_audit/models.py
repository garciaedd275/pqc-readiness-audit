"""Core data structures shared across the scanner, classifier, risk model,
and report generator.

Keeping these as plain dataclasses (rather than passing dicts around) means
every stage of the pipeline has a typed contract, and the whole pipeline can
be exercised in tests without a network connection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Exposure(str, Enum):
    INTERNET = "internet"
    INTERNAL = "internal"


class Mechanism(str, Enum):
    """Which cryptographic job the algorithm is doing.

    This matters because Shor's algorithm and "harvest now, decrypt later"
    apply very differently to key exchange (breaks confidentiality of
    recorded traffic) versus digital signatures (breaks authenticity going
    forward, but does not let an attacker retroactively decrypt captured
    traffic).
    """

    KEY_EXCHANGE = "key_exchange"
    SIGNATURE = "signature"
    SYMMETRIC = "symmetric"
    HASH = "hash"


class Classification(str, Enum):
    VULNERABLE = "vulnerable"      # broken by Shor's algorithm on a CRQC
    WEAKENED = "weakened"          # margin reduced by Grover's algorithm, not broken
    SAFE = "safe"                  # believed quantum-resistant at adequate strength
    PQC = "pqc"                    # a standardized post-quantum algorithm
    UNKNOWN = "unknown"            # not recognized by the rule table


@dataclass
class TargetSpec:
    """One scan target plus the audit metadata needed to prioritize it.

    The crypto scanner only needs hostname/port. `exposure` and
    `retention_years` are supplied by the auditor (or a CSV column) because
    no scanner can infer them from the wire.
    """

    hostname: str
    port: int = 443
    exposure: Exposure = Exposure.INTERNET
    retention_years: int = 1
    asset_name: Optional[str] = None
    notes: str = ""

    def display_name(self) -> str:
        return self.asset_name or f"{self.hostname}:{self.port}"


@dataclass
class CryptoObservation:
    """One distinct cryptographic algorithm observed in use on a target.

    A single TLS endpoint typically yields several of these: one per
    certificate signature algorithm in the chain, and one per unique
    (protocol, key-exchange, symmetric-cipher) combination the server is
    willing to negotiate.
    """

    target: str
    mechanism: Mechanism
    algorithm: str
    key_size: Optional[int]
    protocol_version: Optional[str] = None
    detail: str = ""
    not_valid_after: Optional[datetime] = None


@dataclass
class ScanError:
    target: str
    reason: str


@dataclass
class Finding:
    """A CryptoObservation after the rule engine has judged it."""

    observation: CryptoObservation
    classification: Classification
    rationale: str
    recommended_replacement: str
    quantum_attack: str  # "shor", "grover", or "none"


@dataclass
class RiskScoredFinding:
    """A Finding after the risk-prioritization model has scored it."""

    finding: Finding
    target: TargetSpec
    severity_score: float
    hndl_relevant: bool
    exposure_multiplier: float
    hndl_multiplier: float
    remediation_complexity: str  # "low", "medium", "high"
    priority_score: float
    priority_tier: str  # "Critical", "High", "Medium", "Low", "Informational"

    @property
    def asset(self) -> str:
        return self.target.display_name()
