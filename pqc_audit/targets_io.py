"""Load target definitions from a CSV file.

Expected columns (header row required): hostname, port, exposure,
retention_years, asset_name, notes. Only `hostname` is mandatory — every
other column has a default. See examples/targets.csv for a worked example.
"""

from __future__ import annotations

import csv
from pathlib import Path

from pqc_audit.models import Exposure, TargetSpec


def load_targets_csv(path: str | Path) -> list[TargetSpec]:
    targets: list[TargetSpec] = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None or "hostname" not in reader.fieldnames:
            raise ValueError(f"{path}: CSV must have a 'hostname' column header")
        for line_num, row in enumerate(reader, start=2):
            hostname = (row.get("hostname") or "").strip()
            if not hostname:
                continue
            port_raw = (row.get("port") or "").strip()
            exposure_raw = (row.get("exposure") or "internet").strip().lower()
            retention_raw = (row.get("retention_years") or "1").strip()
            try:
                exposure = Exposure(exposure_raw)
            except ValueError as exc:
                raise ValueError(
                    f"{path}:{line_num}: invalid exposure '{exposure_raw}' "
                    f"(expected 'internet' or 'internal')"
                ) from exc
            targets.append(
                TargetSpec(
                    hostname=hostname,
                    port=int(port_raw) if port_raw else 443,
                    exposure=exposure,
                    retention_years=int(retention_raw) if retention_raw else 1,
                    asset_name=(row.get("asset_name") or "").strip() or None,
                    notes=(row.get("notes") or "").strip(),
                )
            )
    return targets
