"""Rule-based PQC vulnerability classifier.

Deliberately not machine learning: the judgment calls here ("RSA is
Shor-broken regardless of key size", "AES-128 is weakened but not broken by
Grover's algorithm") are stable, well-established cryptographic facts, not
statistical inferences. A plain, auditable, editable rule table is the right
tool — anyone reviewing this in an interview or an audit workpaper can read
`rules.yaml` top to bottom and see exactly why each verdict was reached.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Optional

import yaml

from pqc_audit.models import Classification, CryptoObservation, Finding


@dataclass
class Rule:
    id: str
    mechanism: str
    match: list[str]
    classification: Classification
    quantum_attack: str
    rationale: str
    recommended_replacement: str
    key_size_below: Optional[int] = None
    key_size_at_least: Optional[int] = None

    def applies_to(self, observation: CryptoObservation) -> bool:
        if self.mechanism != "any" and self.mechanism != observation.mechanism.value:
            return False
        if self.key_size_below is not None:
            if observation.key_size is None or observation.key_size >= self.key_size_below:
                return False
        if self.key_size_at_least is not None:
            if observation.key_size is None or observation.key_size < self.key_size_at_least:
                return False
        algo_upper = observation.algorithm.upper()
        return any(pattern.upper() in algo_upper for pattern in self.match)


class RuleEngine:
    def __init__(self, rules: list[Rule]):
        self.rules = rules

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "RuleEngine":
        """Load the rule table from a YAML file.

        Defaults to the packaged `rules.yaml`, but any path can be supplied
        so an auditor can maintain an org-specific rule set (e.g. to add a
        newly standardized PQC algorithm) without touching this module.
        """
        if path is not None:
            raw = Path(path).read_text()
        else:
            raw = resources.files("pqc_audit").joinpath("rules.yaml").read_text()
        data = yaml.safe_load(raw)
        rules = []
        for rule in data["rules"]:
            rule = dict(rule)
            rule["classification"] = Classification(rule["classification"])
            rules.append(Rule(**rule))
        return cls(rules)

    def classify(self, observation: CryptoObservation) -> Finding:
        for rule in self.rules:
            if rule.applies_to(observation):
                return Finding(
                    observation=observation,
                    classification=rule.classification,
                    rationale=" ".join(rule.rationale.split()),
                    recommended_replacement=" ".join(rule.recommended_replacement.split()),
                    quantum_attack=rule.quantum_attack,
                )
        return Finding(
            observation=observation,
            classification=Classification.UNKNOWN,
            rationale=(
                f"No rule matched algorithm '{observation.algorithm}' for "
                f"mechanism '{observation.mechanism.value}'. Extend rules.yaml."
            ),
            recommended_replacement="Manually review; add a rule to rules.yaml once assessed.",
            quantum_attack="unknown",
        )

    def classify_all(self, observations: list[CryptoObservation]) -> list[Finding]:
        return [self.classify(obs) for obs in observations]
