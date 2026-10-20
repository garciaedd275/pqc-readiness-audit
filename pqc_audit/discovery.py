"""Asset discovery: find hostnames for a domain from certificate
transparency (CT) logs via crt.sh, optionally resolve them via DNS, and
emit a targets CSV the scanner can consume.

Discovery is passive: it queries a public CT search service and your local
resolver. It never connects to the discovered hosts. Scanning them (the
`scan`/`audit` commands) is a separate, active step that needs authorization.
"""

from __future__ import annotations

import csv
import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

CRTSH_URL = "https://crt.sh/?q={query}&output=json"
USER_AGENT = "pqc-readiness-audit/0.1 (+asset discovery)"

_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_HOSTNAME_RE = re.compile(rf"^(?:{_LABEL}\.)+{_LABEL}$")


def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower().rstrip(".")
    if domain.startswith("*."):
        domain = domain[2:]
    if not _HOSTNAME_RE.match(domain):
        raise ValueError(f"'{domain}' is not a valid domain name")
    return domain


def parse_ct_names(records: list[dict], domain: str) -> set[str]:
    """Extract in-scope hostnames from crt.sh JSON records.

    Wildcard entries ("*.example.com") collapse to their base name, and
    anything outside `domain` (crt.sh can return unrelated SAN entries from
    shared certificates) is dropped.
    """
    names: set[str] = set()
    for record in records:
        for raw in str(record.get("name_value", "")).splitlines():
            name = raw.strip().lower().rstrip(".")
            if name.startswith("*."):
                name = name[2:]
            if not _HOSTNAME_RE.match(name):
                continue
            if name == domain or name.endswith("." + domain):
                names.add(name)
    return names


def fetch_ct_names(domain: str, timeout: float = 60.0, attempts: int = 3, backoff: float = 3.0) -> set[str]:
    """Query crt.sh, retrying on the transient 5xx/timeout errors it is known for."""
    url = CRTSH_URL.format(query=urllib.parse.quote(f"%.{domain}"))
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last_error: Exception | None = None
    for attempt in range(attempts):
        if attempt:
            time.sleep(backoff * attempt)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed https URL
                body = response.read().decode("utf-8")
            records = json.loads(body) if body.strip() else []
            return parse_ct_names(records, domain)
        except urllib.error.HTTPError as exc:
            if exc.code < 500:
                raise
            last_error = exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = exc
    raise RuntimeError(f"crt.sh failed after {attempts} attempts: {last_error}")


def resolve_names(names: set[str], workers: int = 20) -> dict[str, list[str]]:
    """Resolve each name to its A/AAAA addresses; unresolved names map to []."""

    def lookup(name: str) -> tuple[str, list[str]]:
        try:
            infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
        except OSError:
            return name, []
        return name, sorted({info[4][0] for info in infos})

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return dict(pool.map(lookup, sorted(names)))


def write_targets_csv(
    path: str | Path,
    resolved: dict[str, list[str]],
    exposure: str = "internet",
    retention_years: int = 1,
    port: int = 443,
    include_unresolved: bool = False,
) -> int:
    """Write discovered hosts as a targets CSV. Returns the number of rows."""
    rows = 0
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["hostname", "port", "exposure", "retention_years", "asset_name", "notes"])
        for name in sorted(resolved):
            ips = resolved[name]
            if not ips and not include_unresolved:
                continue
            note = "Discovered via crt.sh; " + (f"resolves to {', '.join(ips[:3])}" if ips else "does not resolve")
            writer.writerow([name, port, exposure, retention_years, name, note])
            rows += 1
    return rows
