from pqc_audit.models import (
    Classification,
    CryptoObservation,
    Exposure,
    Finding,
    Mechanism,
    TargetSpec,
)
from pqc_audit.risk import ThreatModel, prioritize, score_finding


def _vulnerable_kex_finding(target_name="host:443", protocol="TLS 1.2"):
    obs = CryptoObservation(
        target=target_name,
        mechanism=Mechanism.KEY_EXCHANGE,
        algorithm="ECDHE",
        key_size=256,
        protocol_version=protocol,
    )
    return Finding(
        observation=obs,
        classification=Classification.VULNERABLE,
        rationale="test",
        recommended_replacement="migrate to ML-KEM",
        quantum_attack="shor",
    )


def _safe_finding(target_name="host:443"):
    obs = CryptoObservation(
        target=target_name, mechanism=Mechanism.SYMMETRIC, algorithm="AES_256_GCM", key_size=256
    )
    return Finding(
        observation=obs,
        classification=Classification.SAFE,
        rationale="test",
        recommended_replacement="none",
        quantum_attack="grover",
    )


def test_internet_facing_long_retention_scores_higher_than_internal_short_retention():
    finding = _vulnerable_kex_finding()

    internet_long = TargetSpec(
        hostname="host", exposure=Exposure.INTERNET, retention_years=20, asset_name="host:443"
    )
    internal_short = TargetSpec(
        hostname="host", exposure=Exposure.INTERNAL, retention_years=1, asset_name="host:443"
    )

    high = score_finding(finding, internet_long, ThreatModel(threat_horizon_years=10))
    low = score_finding(finding, internal_short, ThreatModel(threat_horizon_years=10))

    assert high.priority_score > low.priority_score
    assert high.hndl_relevant is True


def test_safe_finding_scores_zero_and_is_informational():
    finding = _safe_finding()
    target = TargetSpec(hostname="host", exposure=Exposure.INTERNET, retention_years=10, asset_name="host:443")
    scored = score_finding(finding, target)
    assert scored.priority_score == 0
    assert scored.priority_tier == "Informational"


def test_hndl_multiplier_not_applied_to_signature_findings():
    obs = CryptoObservation(
        target="host:443", mechanism=Mechanism.SIGNATURE, algorithm="RSA", key_size=2048
    )
    finding = Finding(
        observation=obs,
        classification=Classification.VULNERABLE,
        rationale="test",
        recommended_replacement="migrate to ML-DSA",
        quantum_attack="shor",
    )
    target = TargetSpec(hostname="host", exposure=Exposure.INTERNET, retention_years=50, asset_name="host:443")
    scored = score_finding(finding, target)
    assert scored.hndl_relevant is False
    assert scored.hndl_multiplier == 1.0


def test_legacy_protocol_is_low_complexity_quick_win():
    obs = CryptoObservation(
        target="host:443",
        mechanism=Mechanism.KEY_EXCHANGE,
        algorithm="RSA",
        key_size=2048,
        protocol_version="TLS 1.0",
        detail="static key exchange, no forward secrecy",
    )
    finding = Finding(
        observation=obs,
        classification=Classification.VULNERABLE,
        rationale="test",
        recommended_replacement="disable TLS 1.0",
        quantum_attack="shor",
    )
    target = TargetSpec(hostname="host", exposure=Exposure.INTERNET, retention_years=1, asset_name="host:443")
    scored = score_finding(finding, target)
    assert scored.remediation_complexity == "low"


def test_modern_ecdhe_key_exchange_is_high_complexity_pqc_migration():
    obs = CryptoObservation(
        target="host:443",
        mechanism=Mechanism.KEY_EXCHANGE,
        algorithm="ECDHE",
        key_size=256,
        protocol_version="TLS 1.3",
        detail="Negotiated in TLS_AES_256_GCM_SHA384",
    )
    finding = Finding(
        observation=obs,
        classification=Classification.VULNERABLE,
        rationale="test",
        recommended_replacement="hybrid PQC KEM",
        quantum_attack="shor",
    )
    target = TargetSpec(hostname="host", exposure=Exposure.INTERNET, retention_years=1, asset_name="host:443")
    scored = score_finding(finding, target)
    assert scored.remediation_complexity == "high"


def test_prioritize_sorts_descending_by_score():
    findings = [_safe_finding("a:443"), _vulnerable_kex_finding("b:443")]
    targets_by_name = {
        "a:443": TargetSpec(hostname="a", exposure=Exposure.INTERNET, retention_years=1, asset_name="a:443"),
        "b:443": TargetSpec(hostname="b", exposure=Exposure.INTERNET, retention_years=20, asset_name="b:443"),
    }
    scored = prioritize(findings, targets_by_name)
    assert scored[0].finding.observation.target == "b:443"
    assert scored[0].priority_score >= scored[1].priority_score
