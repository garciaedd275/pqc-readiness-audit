"""Crypto inventory scanner.

Walks each target's TLS handshake surface (protocol versions, negotiable
cipher suites, certificate chain) using sslyze, and normalizes what it finds
into a flat list of `CryptoObservation` records — one per distinct
algorithm doing a distinct job (key exchange, signature, or symmetric
cipher). The rule engine in `rules.py` then judges each observation
independently.

sslyze does the actual network protocol work; this module's job is only to
translate its (fairly deep) result objects into the flatter shape the rest
of this tool wants, and to do it without duplicate rows — a modern TLS 1.2
server will happily offer a dozen cipher suites that all boil down to the
same (ECDHE, AES-256) story, and an audit report should say that once, not
twelve times.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509 import Certificate

import sslyze

from pqc_audit.models import CryptoObservation, Mechanism, ScanError, TargetSpec

# Cipher suite scan commands, keyed by their human-readable protocol label.
_PROTOCOL_SCAN_COMMANDS = {
    "TLS 1.0": sslyze.ScanCommand.TLS_1_0_CIPHER_SUITES,
    "TLS 1.1": sslyze.ScanCommand.TLS_1_1_CIPHER_SUITES,
    "TLS 1.2": sslyze.ScanCommand.TLS_1_2_CIPHER_SUITES,
    "TLS 1.3": sslyze.ScanCommand.TLS_1_3_CIPHER_SUITES,
}
_LEGACY_SCAN_COMMANDS = {
    "SSL 2.0": sslyze.ScanCommand.SSL_2_0_CIPHER_SUITES,
    "SSL 3.0": sslyze.ScanCommand.SSL_3_0_CIPHER_SUITES,
}

_ATTEMPT_FIELD_BY_COMMAND = {
    sslyze.ScanCommand.SSL_2_0_CIPHER_SUITES: "ssl_2_0_cipher_suites",
    sslyze.ScanCommand.SSL_3_0_CIPHER_SUITES: "ssl_3_0_cipher_suites",
    sslyze.ScanCommand.TLS_1_0_CIPHER_SUITES: "tls_1_0_cipher_suites",
    sslyze.ScanCommand.TLS_1_1_CIPHER_SUITES: "tls_1_1_cipher_suites",
    sslyze.ScanCommand.TLS_1_2_CIPHER_SUITES: "tls_1_2_cipher_suites",
    sslyze.ScanCommand.TLS_1_3_CIPHER_SUITES: "tls_1_3_cipher_suites",
}


def _public_key_algorithm(public_key) -> tuple[str, int | None]:
    """Map a cryptography public key object to (family name, size in bits)."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"ECDSA ({public_key.curve.name})", public_key.curve.key_size
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", 448
    return type(public_key).__name__, None


def _kex_family_from_suite_name(kex_auth_part: str) -> str:
    """Classify the key-exchange side of a pre-TLS1.3 cipher suite name.

    `kex_auth_part` is the segment of the IANA cipher suite name before
    "_WITH_", e.g. "ECDHE_RSA", "DHE_RSA", "RSA", "ECDHE_PSK".
    """
    upper = kex_auth_part.upper()
    if "ECDHE" in upper:
        return "ECDHE"
    if "DHE" in upper:
        return "DHE"
    if "RSA" in upper:
        return "RSA"  # static RSA key transport, e.g. plain TLS_RSA_WITH_*
    if "ECDH" in upper:
        return "ECDH"  # static ECDH
    if "PSK" in upper:
        return "PSK"
    return upper


def _cert_observations(target_name: str, deployment) -> tuple[list[CryptoObservation], int | None]:
    """Extract cert-chain findings for one certificate deployment.

    Returns the observations plus the leaf public key size, so callers can
    reuse that size for static (non-ephemeral) key exchange suites, whose
    effective key-exchange strength is the certificate's own key.
    """
    observations: list[CryptoObservation] = []
    chain: list[Certificate] = deployment.received_certificate_chain
    if not chain:
        return observations, None

    leaf = chain[0]
    pubkey_algo, pubkey_size = _public_key_algorithm(leaf.public_key())
    expiry = leaf.not_valid_after_utc

    observations.append(
        CryptoObservation(
            target=target_name,
            mechanism=Mechanism.SIGNATURE,
            algorithm=pubkey_algo,
            key_size=pubkey_size,
            protocol_version=None,
            detail="Leaf certificate public key (server authentication)",
            not_valid_after=expiry,
        )
    )

    issuer_sig_name = leaf.signature_algorithm_oid._name  # e.g. "sha256WithRSAEncryption"
    observations.append(
        CryptoObservation(
            target=target_name,
            mechanism=Mechanism.SIGNATURE,
            algorithm=issuer_sig_name,
            key_size=None,
            protocol_version=None,
            detail="Leaf certificate issuer signature algorithm",
            not_valid_after=expiry,
        )
    )

    hash_algo = leaf.signature_hash_algorithm
    if hash_algo is not None:
        observations.append(
            CryptoObservation(
                target=target_name,
                mechanism=Mechanism.HASH,
                algorithm=hash_algo.name.upper(),
                key_size=getattr(hash_algo, "digest_size", None),
                protocol_version=None,
                detail="Certificate signature hash algorithm",
                not_valid_after=expiry,
            )
        )

    # Any intermediate signed with a legacy algorithm is worth flagging too,
    # even though the leaf is what a browser/client validates day-to-day.
    for intermediate in chain[1:]:
        algo, _size = _public_key_algorithm(intermediate.public_key())
        sig_name = intermediate.signature_algorithm_oid._name
        observations.append(
            CryptoObservation(
                target=target_name,
                mechanism=Mechanism.SIGNATURE,
                algorithm=sig_name,
                key_size=None,
                protocol_version=None,
                detail=f"Chain certificate ({intermediate.subject.rfc4514_string()}) issuer signature algorithm",
                not_valid_after=intermediate.not_valid_after_utc,
            )
        )

    return observations, pubkey_size


def _cipher_suite_observations(
    target_name: str,
    protocol_label: str,
    cipher_result,
    fallback_static_kex_key_size: int | None,
) -> list[CryptoObservation]:
    observations: list[CryptoObservation] = []
    for accepted in cipher_result.accepted_cipher_suites:
        suite = accepted.cipher_suite
        name = suite.name  # e.g. "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        body = name[len("TLS_"):] if name.startswith("TLS_") else name

        if "_WITH_" in body:
            kex_auth_part, cipher_part = body.split("_WITH_", 1)
            kex_family = _kex_family_from_suite_name(kex_auth_part)
        else:
            # TLS 1.3 suite names carry only the symmetric cipher; key
            # exchange is negotiated separately and reported via the
            # ephemeral key info sslyze captures per accepted suite.
            cipher_part = body
            kex_family = "ECDHE"

        if accepted.ephemeral_key is not None:
            kex_key_size = accepted.ephemeral_key.size
        else:
            kex_key_size = fallback_static_kex_key_size

        observations.append(
            CryptoObservation(
                target=target_name,
                mechanism=Mechanism.KEY_EXCHANGE,
                algorithm=kex_family,
                key_size=kex_key_size,
                protocol_version=protocol_label,
                detail=f"Negotiated in {name}"
                + ("" if accepted.ephemeral_key is not None else " (static key exchange, no forward secrecy)"),
            )
        )

        observations.append(
            CryptoObservation(
                target=target_name,
                mechanism=Mechanism.SYMMETRIC,
                algorithm=cipher_part,
                key_size=suite.key_size,
                protocol_version=protocol_label,
                detail=f"Negotiated in {name}",
            )
        )
    return observations


def _dedupe(observations: list[CryptoObservation]) -> list[CryptoObservation]:
    seen: set[tuple] = set()
    deduped: list[CryptoObservation] = []
    for obs in observations:
        # Collapse repeat cipher suites that boil down to the same
        # algorithm/key-size/protocol story into a single row.
        key = (obs.target, obs.mechanism, obs.algorithm, obs.key_size, obs.protocol_version)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(obs)
    return deduped


def scan_target(target: TargetSpec, include_legacy_ssl: bool = False) -> tuple[list[CryptoObservation], ScanError | None]:
    """Scan one target and return its observations, or a ScanError."""
    observations, errors = scan_targets([target], include_legacy_ssl=include_legacy_ssl)
    return observations, (errors[0] if errors else None)


def scan_targets(
    targets: list[TargetSpec], include_legacy_ssl: bool = False
) -> tuple[list[CryptoObservation], list[ScanError]]:
    """Scan multiple targets concurrently and return (observations, errors)."""
    protocol_commands = dict(_PROTOCOL_SCAN_COMMANDS)
    if include_legacy_ssl:
        protocol_commands.update(_LEGACY_SCAN_COMMANDS)

    scan_commands = {sslyze.ScanCommand.CERTIFICATE_INFO, *protocol_commands.values()}

    requests_by_target: dict[str, TargetSpec] = {}
    scan_requests = []
    for target in targets:
        location = sslyze.ServerNetworkLocation(hostname=target.hostname, port=target.port)
        request = sslyze.ServerScanRequest(server_location=location, scan_commands=scan_commands)
        requests_by_target[str(request.uuid)] = target
        scan_requests.append(request)

    scanner = sslyze.Scanner()
    scanner.queue_scans(scan_requests)

    all_observations: list[CryptoObservation] = []
    scan_errors: list[ScanError] = []

    for result in scanner.get_results():
        target = requests_by_target[str(result.uuid)]
        target_name = target.display_name()

        if result.scan_status == sslyze.ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            reason = "Could not establish a TLS connection"
            if result.connectivity_error_trace is not None:
                reason = str(result.connectivity_error_trace.exc_value) or reason
            scan_errors.append(ScanError(target=target_name, reason=reason))
            continue

        scan_result = result.scan_result
        target_observations: list[CryptoObservation] = []
        fallback_static_kex_key_size: int | None = None

        cert_attempt = scan_result.certificate_info
        if cert_attempt.status == sslyze.ScanCommandAttemptStatusEnum.COMPLETED and cert_attempt.result:
            for deployment in cert_attempt.result.certificate_deployments:
                cert_obs, pubkey_size = _cert_observations(target_name, deployment)
                target_observations.extend(cert_obs)
                if fallback_static_kex_key_size is None:
                    fallback_static_kex_key_size = pubkey_size

        for protocol_label, command in protocol_commands.items():
            field_name = _ATTEMPT_FIELD_BY_COMMAND[command]
            attempt = getattr(scan_result, field_name)
            if attempt.status == sslyze.ScanCommandAttemptStatusEnum.COMPLETED and attempt.result:
                target_observations.extend(
                    _cipher_suite_observations(
                        target_name, protocol_label, attempt.result, fallback_static_kex_key_size
                    )
                )

        if not target_observations:
            scan_errors.append(
                ScanError(target=target_name, reason="Scan completed but no certificate or cipher data was returned")
            )
            continue

        all_observations.extend(_dedupe(target_observations))

    return all_observations, scan_errors
