from datetime import datetime, timezone

from pqc_audit.models import CryptoObservation, Exposure, Mechanism, ScanError, TargetSpec
from pqc_audit.scan_io import load_scan_results, save_scan_results


def test_save_and_load_roundtrip(tmp_path):
    targets = [
        TargetSpec(hostname="example.com", port=443, exposure=Exposure.INTERNET, retention_years=5, asset_name="Example", notes="test")
    ]
    observations = [
        CryptoObservation(
            target="Example",
            mechanism=Mechanism.SIGNATURE,
            algorithm="RSA",
            key_size=2048,
            protocol_version=None,
            detail="Leaf certificate public key",
            not_valid_after=datetime(2030, 1, 1, tzinfo=timezone.utc),
        )
    ]
    errors = [ScanError(target="down.example.com:443", reason="timeout")]

    path = save_scan_results(targets, observations, errors, tmp_path / "scan.json")
    loaded_targets, loaded_obs, loaded_errors = load_scan_results(path)

    assert loaded_targets == targets
    assert len(loaded_obs) == 1
    assert loaded_obs[0].algorithm == "RSA"
    assert loaded_obs[0].not_valid_after == datetime(2030, 1, 1, tzinfo=timezone.utc)
    assert loaded_errors == errors
