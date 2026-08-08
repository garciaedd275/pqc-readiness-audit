"""Serialize/deserialize scan results to JSON so `scan` and `report` can be
run as separate steps (e.g. scan once, then iterate on report formatting).
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from pqc_audit.models import CryptoObservation, Exposure, Mechanism, ScanError, TargetSpec


def save_scan_results(
    targets: list[TargetSpec],
    observations: list[CryptoObservation],
    errors: list[ScanError],
    path: str | Path,
) -> Path:
    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "targets": [
            {
                "hostname": t.hostname,
                "port": t.port,
                "exposure": t.exposure.value,
                "retention_years": t.retention_years,
                "asset_name": t.asset_name,
                "notes": t.notes,
            }
            for t in targets
        ],
        "observations": [
            {
                "target": o.target,
                "mechanism": o.mechanism.value,
                "algorithm": o.algorithm,
                "key_size": o.key_size,
                "protocol_version": o.protocol_version,
                "detail": o.detail,
                "not_valid_after": o.not_valid_after.isoformat() if o.not_valid_after else None,
            }
            for o in observations
        ],
        "errors": [asdict(e) for e in errors],
    }
    path = Path(path)
    path.write_text(json.dumps(data, indent=2))
    return path


def load_scan_results(
    path: str | Path,
) -> tuple[list[TargetSpec], list[CryptoObservation], list[ScanError]]:
    data = json.loads(Path(path).read_text())

    targets = [
        TargetSpec(
            hostname=t["hostname"],
            port=t["port"],
            exposure=Exposure(t["exposure"]),
            retention_years=t["retention_years"],
            asset_name=t.get("asset_name"),
            notes=t.get("notes", ""),
        )
        for t in data["targets"]
    ]

    observations = [
        CryptoObservation(
            target=o["target"],
            mechanism=Mechanism(o["mechanism"]),
            algorithm=o["algorithm"],
            key_size=o["key_size"],
            protocol_version=o.get("protocol_version"),
            detail=o.get("detail", ""),
            not_valid_after=datetime.fromisoformat(o["not_valid_after"]) if o.get("not_valid_after") else None,
        )
        for o in data["observations"]
    ]

    errors = [ScanError(target=e["target"], reason=e["reason"]) for e in data["errors"]]

    return targets, observations, errors
