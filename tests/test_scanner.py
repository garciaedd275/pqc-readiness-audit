"""Scanner unit tests using in-memory certificates — no network required.

Live-network scans against real hosts are exercised separately by
`scripts/run_sample_scan.py` and are not part of the default test suite,
since CI/sandbox environments may not have outbound network access.
"""

from pqc_audit.models import Mechanism
from pqc_audit.scanner import (
    _cert_observations,
    _dedupe,
    _kex_family_from_suite_name,
    _public_key_algorithm,
)


def test_kex_family_parsing():
    assert _kex_family_from_suite_name("ECDHE_RSA") == "ECDHE"
    assert _kex_family_from_suite_name("DHE_RSA") == "DHE"
    assert _kex_family_from_suite_name("RSA") == "RSA"
    assert _kex_family_from_suite_name("ECDH_ECDSA") == "ECDH"
    assert _kex_family_from_suite_name("PSK") == "PSK"


def test_public_key_algorithm_rsa(rsa_certificate):
    algo, size = _public_key_algorithm(rsa_certificate.public_key())
    assert algo == "RSA"
    assert size == 2048


def test_public_key_algorithm_ec(ec_certificate):
    algo, size = _public_key_algorithm(ec_certificate.public_key())
    assert algo.startswith("ECDSA")
    assert size == 256


def test_cert_observations_extracts_pubkey_and_signature(cert_deployment):
    observations, pubkey_size = _cert_observations("host:443", cert_deployment)
    assert pubkey_size == 2048

    mechanisms = {obs.mechanism for obs in observations}
    assert Mechanism.SIGNATURE in mechanisms
    assert Mechanism.HASH in mechanisms

    pubkey_obs = next(o for o in observations if "public key" in o.detail)
    assert pubkey_obs.algorithm == "RSA"
    assert pubkey_obs.key_size == 2048
    assert pubkey_obs.not_valid_after is not None


def test_dedupe_collapses_repeated_algorithm_key_size_protocol():
    from pqc_audit.models import CryptoObservation

    obs_list = [
        CryptoObservation(target="h", mechanism=Mechanism.SYMMETRIC, algorithm="AES_256_GCM", key_size=256, protocol_version="TLS 1.2", detail="suite A"),
        CryptoObservation(target="h", mechanism=Mechanism.SYMMETRIC, algorithm="AES_256_GCM", key_size=256, protocol_version="TLS 1.2", detail="suite B"),
        CryptoObservation(target="h", mechanism=Mechanism.SYMMETRIC, algorithm="AES_128_GCM", key_size=128, protocol_version="TLS 1.2", detail="suite C"),
    ]
    deduped = _dedupe(obs_list)
    assert len(deduped) == 2
