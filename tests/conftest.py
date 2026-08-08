"""Shared test fixtures.

Certificate fixtures build real, in-memory self-signed certificates with
the `cryptography` library so scanner-parsing tests exercise real x509
objects without touching the network.
"""

from __future__ import annotations

import datetime
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


def _self_signed_cert(private_key, public_key, hash_algorithm, common_name: str, days_valid: int = 365):
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
    )
    return builder.sign(private_key, hash_algorithm)


@pytest.fixture
def rsa_certificate():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _self_signed_cert(key, key.public_key(), hashes.SHA256(), "rsa.example.com")


@pytest.fixture
def ec_certificate():
    key = ec.generate_private_key(ec.SECP256R1())
    return _self_signed_cert(key, key.public_key(), hashes.SHA256(), "ec.example.com")


@pytest.fixture
def cert_deployment(rsa_certificate):
    """A duck-typed stand-in for sslyze's CertificateDeploymentAnalysisResult —
    the scanner only reads `.received_certificate_chain` off it."""
    return SimpleNamespace(received_certificate_chain=[rsa_certificate])
