from pqc_audit.models import Classification, CryptoObservation, Mechanism
from pqc_audit.rules import RuleEngine


def _obs(mechanism, algorithm, key_size=None):
    return CryptoObservation(target="host:443", mechanism=mechanism, algorithm=algorithm, key_size=key_size)


def test_loads_default_rules():
    engine = RuleEngine.load()
    assert len(engine.rules) > 0


def test_rsa_key_exchange_is_shor_vulnerable():
    engine = RuleEngine.load()
    finding = engine.classify(_obs(Mechanism.KEY_EXCHANGE, "RSA", 2048))
    assert finding.classification == Classification.VULNERABLE
    assert finding.quantum_attack == "shor"


def test_rsa_vulnerability_independent_of_key_size():
    engine = RuleEngine.load()
    small = engine.classify(_obs(Mechanism.SIGNATURE, "sha256WithRSAEncryption", 1024))
    large = engine.classify(_obs(Mechanism.SIGNATURE, "sha256WithRSAEncryption", 15360))
    assert small.classification == large.classification == Classification.VULNERABLE


def test_ecdhe_key_exchange_is_shor_vulnerable():
    engine = RuleEngine.load()
    finding = engine.classify(_obs(Mechanism.KEY_EXCHANGE, "ECDHE", 256))
    assert finding.classification == Classification.VULNERABLE
    assert finding.quantum_attack == "shor"


def test_aes_256_is_safe():
    engine = RuleEngine.load()
    finding = engine.classify(_obs(Mechanism.SYMMETRIC, "AES_256_GCM_SHA384", 256))
    assert finding.classification == Classification.SAFE


def test_aes_128_is_weakened_not_broken():
    engine = RuleEngine.load()
    finding = engine.classify(_obs(Mechanism.SYMMETRIC, "AES_128_GCM_SHA256", 128))
    assert finding.classification == Classification.WEAKENED
    assert finding.quantum_attack == "grover"


def test_ml_kem_is_pqc():
    engine = RuleEngine.load()
    finding = engine.classify(_obs(Mechanism.KEY_EXCHANGE, "X25519MLKEM768", 4096))
    assert finding.classification == Classification.PQC


def test_ml_dsa_is_pqc():
    engine = RuleEngine.load()
    finding = engine.classify(_obs(Mechanism.SIGNATURE, "ML-DSA-87", None))
    assert finding.classification == Classification.PQC


def test_rc4_is_vulnerable_classically():
    engine = RuleEngine.load()
    finding = engine.classify(_obs(Mechanism.SYMMETRIC, "RC4_128_SHA", 128))
    assert finding.classification == Classification.VULNERABLE
    assert finding.quantum_attack == "none"


def test_sha1_hash_is_vulnerable():
    engine = RuleEngine.load()
    finding = engine.classify(_obs(Mechanism.HASH, "SHA1", None))
    assert finding.classification == Classification.VULNERABLE


def test_sha256_hash_is_safe():
    engine = RuleEngine.load()
    finding = engine.classify(_obs(Mechanism.HASH, "SHA256", None))
    assert finding.classification == Classification.SAFE


def test_unrecognized_algorithm_is_unknown():
    engine = RuleEngine.load()
    finding = engine.classify(_obs(Mechanism.SYMMETRIC, "CAMELLIA_256_CBC_SHA", 256))
    assert finding.classification == Classification.UNKNOWN


def test_first_matching_rule_wins_rsa_before_generic():
    # A rule table is order-sensitive; make sure the loader preserves order
    # from the YAML file rather than e.g. sorting rules alphabetically.
    engine = RuleEngine.load()
    ids = [rule.id for rule in engine.rules]
    assert ids.index("pqc-ml-kem") < ids.index("shor-rsa")
