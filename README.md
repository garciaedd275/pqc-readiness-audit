# PQC Readiness Audit

A Post-Quantum Cryptography (PQC) readiness assessment tool: it scans an
organization's public-facing TLS/certificate footprint, tells you which
cryptography will stop being safe once quantum computers catch up, and
produces a prioritized, audit-ready report — the kind of artifact you'd
hand to a CISO or bring to a client engagement.

This is a portfolio project built to demonstrate IT risk / GRC audit
methodology (control assessment logic, risk scoring, report writing)
applied to a topic almost nobody has productized yet: most "post-quantum"
vendor activity is on the crypto-library side (build me a PQC-capable TLS
stack); very little of it is on the assessment side (tell me what's
actually exposed and what to fix first). This tool is the second thing.

## The problem, in plain English

Most of the encryption protecting web traffic today (RSA, Diffie-Hellman,
elliptic-curve/ECDSA) is secure because certain math problems — factoring
large numbers, computing discrete logarithms — are practically impossible
for ordinary computers to solve. A sufficiently powerful quantum computer
running **Shor's algorithm** would solve those same problems in a
reasonable amount of time, breaking that encryption outright. No such
computer exists yet at the scale needed. But two things make this an
active risk today, not a someday risk:

1. **"Harvest now, decrypt later" (HNDL).** An adversary can record
   encrypted traffic today and decrypt it retroactively once a
   cryptographically relevant quantum computer (CRQC) exists. If the data
   inside that traffic needs to stay confidential for 10+ years — health
   records, trade secrets, long-lived credentials — it is already at risk,
   even though nothing can decrypt it *yet*.
2. **Migration takes years.** Reissuing certificates, upgrading libraries,
   and coordinating with vendors and CAs across an estate is a multi-year
   program, not a patch. Federal guidance (below) is already treating the
   mid-2030s as the deadline for having this done — which means the
   planning has to start now.

This tool answers the first question any such program needs answered:
**what have we got, and what's most urgent?**

## What it does

Four stages, each independently runnable:

1. **Scan** — connects to each target over TLS and inventories every
   protocol version, cipher suite, and certificate in its chain (via
   [sslyze](https://github.com/nabla-c0d3/sslyze) and the `cryptography`
   library).
2. **Classify** — runs each observed algorithm through an editable,
   rule-based lookup table (not machine learning — this is settled
   cryptographic fact, not a statistical judgment call) that says: is this
   broken by Shor's algorithm, weakened by Grover's algorithm, already
   post-quantum, or fine as-is?
3. **Prioritize** — scores each finding on quantum-attack severity, whether
   "harvest now, decrypt later" actually applies (and how badly, given the
   asset's declared data retention period), internet vs. internal
   exposure, and how hard the fix is.
4. **Report** — renders an executive summary, a full findings table, and a
   tiered remediation roadmap as Markdown or HTML.

```
targets.csv → [scan] → scan_results.json → [classify + prioritize] → report.md / report.html
```

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# One-shot: scan, classify, prioritize, and report
pqc-audit audit examples/targets.csv -o report.md

# Or as separate steps (useful for iterating on report formatting
# without re-scanning):
pqc-audit scan examples/targets.csv -o scan_results.json
pqc-audit report scan_results.json -o report.md
pqc-audit report scan_results.json -o report.html --format html
```

**Installing on macOS (as a command on your PATH, no venv to activate):**

```bash
brew install pipx && pipx ensurepath      # then open a new terminal
git clone https://github.com/garciaedd275/pqc-readiness-audit.git
cd pqc-readiness-audit
pipx install --python python3.13 .    # use Python 3.10-3.13; see note below

pqc-audit --version                       # verify
pqc-audit audit examples/targets.csv -o ~/pqc_report.md
```

Upgrade after a `git pull` with `pipx reinstall pqc-readiness-audit`;
remove with `pipx uninstall pqc-readiness-audit`. If `pipx install` fails with
"ResolutionImpossible", your default `python3` is too new for `sslyze` (Homebrew
moved to 3.15); keep the `--python python3.13` flag (`brew install python@3.13`
if needed). No `sudo` is needed, and
there is no `nmap` dependency. If you're developing the tool itself, use
the venv + `pip install -e ".[dev]"` flow above instead.

**Installing on Kali Linux (or any PEP 668 / "externally managed"
distro)?** Plain `pip install` will refuse to run there by design — see
[`KALI.md`](KALI.md) for a `pipx`-based install that puts `pqc-audit`
straight on your `PATH`, no venv activation required.

**Don't have a target list? Discover one.** `pqc-audit discover` pulls
hostnames for a domain from certificate transparency logs
([crt.sh](https://crt.sh)) and DNS, and writes a `targets.csv` the scanner
can consume. This surfaces forgotten internet-facing assets, which carry the
highest "harvest now, decrypt later" risk:

```bash
pqc-audit discover yourdomain.com -o targets.csv    # passive: crt.sh + your DNS resolver
# review targets.csv, set exposure/retention_years per asset, then:
pqc-audit audit targets.csv -o report.md            # active scan: authorized targets only
```

Discovery never connects to the discovered hosts; the `scan`/`audit` step
does, so only run that on assets you own or are authorized to assess.
Options: `--no-resolve`, `--include-unresolved`, `--exposure`,
`--retention-years`, `--port`. crt.sh is a free public service that
sometimes returns 502s; the tool retries three times before giving up.

`targets.csv` needs a `hostname` column; everything else is optional
(defaults shown):

| column | default | meaning |
|---|---|---|
| `hostname` | *(required)* | DNS name or IP to scan |
| `port` | `443` | TCP port |
| `exposure` | `internet` | `internet` or `internal` — drives the exposure multiplier in scoring |
| `retention_years` | `1` | How long data crossing this asset needs to stay confidential — drives the "harvest now, decrypt later" multiplier |
| `asset_name` | *(hostname:port)* | Friendly name for the report |
| `notes` | *(blank)* | Free text, carried through to no particular output field today — useful for your own workpaper trail |

See [`examples/targets.csv`](examples/targets.csv) for a worked example and
[`examples/sample_report.md`](examples/sample_report.md) /
[`examples/sample_report.html`](examples/sample_report.html) for the report
it produces (a real scan of `example.com`, `www.google.com`, and four
[badssl.com](https://badssl.com) test endpoints that deliberately run weak
configurations).

## How classification works

The judgment layer lives entirely in [`pqc_audit/rules.yaml`](pqc_audit/rules.yaml)
— a flat, commented, editable table, not buried in Python logic. Every rule
says: *if you see this algorithm doing this job, classify it this way,
because of this attack, and recommend this fix.* The reasoning behind it:

- **RSA, Diffie-Hellman, and all elliptic-curve cryptography (ECDSA, ECDH,
  even modern curves like X25519/Ed25519) are classified `Vulnerable`,
  regardless of key size.** Shor's algorithm solves the underlying math
  problem in polynomial time on a CRQC. A bigger RSA key raises the
  *classical* difficulty (harder for today's computers) but does not
  change the *quantum* verdict — RSA-2048 and RSA-15360 are equally broken
  once a large enough quantum computer exists.
- **AES-128 is classified `Weakened`, not `Vulnerable`.** Grover's
  algorithm gives only a quadratic speedup against symmetric ciphers,
  cutting AES-128's effective security from 128 bits to roughly 64 —
  weaker than ideal, but not an outright break. AES-256 keeps roughly
  128-bit effective security under the same attack, which is why it's
  classified `Safe`.
- **RC4, 3DES, and NULL/anonymous ciphers are classified `Vulnerable` for
  classical reasons, independent of the quantum question.** An audit tool
  should surface these regardless — they're broken (or never were secure)
  today.
- **ML-KEM (Kyber), ML-DSA (Dilithium), Falcon, and SLH-DSA (SPHINCS+) are
  classified `Pqc`.** These are the algorithms NIST standardized in FIPS
  203/204/205 in August 2024 — no further action needed.
- **Signatures vs. key exchange are scored differently downstream** (see
  below) even though both can be `Vulnerable` — a broken signature
  algorithm is a forward-looking spoofing/integrity risk, not a
  retroactive-decryption risk.

Anything the table doesn't recognize (a proprietary or obscure cipher, or a
new PQC scheme not yet added) is classified `Unknown` rather than silently
guessed at — the sample report actually hits this case (CAMELLIA, a real
but less common cipher) and flags it for manual review instead of pretending
to know. Adding support for a newly standardized algorithm, or your
organization's own risk position on something, is a YAML edit — no code
changes.

## How prioritization works

Implemented in [`pqc_audit/risk.py`](pqc_audit/risk.py). Each finding gets:

- **A severity score**, driven by classification *and* what job the
  algorithm is doing — a broken key exchange (10) outranks a broken
  signature (7), which outranks a merely-weakened symmetric cipher (4).
- **A "harvest now, decrypt later" multiplier — applied only to key
  exchange findings.** This is the one nuance auditors reviewing this tool
  tend to ask about: HNDL is a *confidentiality* attack against traffic an
  eavesdropper recorded. Only the key-exchange algorithm protects that
  traffic's confidentiality. A broken *signature* algorithm doesn't let
  anyone retroactively decrypt anything they captured today — it lets a
  future attacker impersonate the server or tamper with the handshake,
  which matters, but on a different timeline. So the multiplier compares
  the asset's declared `retention_years` against a configurable
  `threat_horizon_years` (default: 10) and only kicks in for key exchange.
- **An exposure multiplier** — internet-facing assets score 1.4x; internal
  assets score 1.0x (still relevant — insider threat, lateral movement —
  just less urgent than something reachable by anyone recording traffic
  today).
- **A remediation-complexity tag** (`low`/`medium`/`high`) so the roadmap
  can separate quick wins from real program work:
  - *Low:* disabling a legacy protocol (TLS 1.0/1.1), a static
    (non-forward-secret) key exchange, or a weak cipher policy — a
    server/load-balancer config change, testable in a maintenance window.
  - *Medium:* certificate signature findings — reissuing a cert and
    coordinating with a CA takes longer than a config change.
  - *High:* a *modern, healthy* ECDHE/DHE key exchange that is nonetheless
    Shor-vulnerable in the future. This isn't broken today — the fix is a
    hybrid PQC key exchange (e.g. X25519+ML-KEM), and that depends on the
    broader PQC ecosystem (TLS libraries, load balancers, HSMs, client
    support) maturing. Correctly labeling this `high` rather than
    demanding an immediate fix is the whole point of a *readiness*
    assessment rather than a vulnerability scan.

Findings are ranked `Critical` / `High` / `Medium` / `Low` /
`Informational` by the resulting score, and the report groups the
remediation roadmap by tier.

## Scope (v1) and what's deliberately out

- **In scope:** network-facing TLS and X.509 certificate configuration —
  what you'd see scanning an organization's external attack surface.
- **Out of scope for v1** (candidates for a v2): data-at-rest encryption,
  VPN/IPsec, SSH host keys, code-signing, and HSM-embedded keys. These all
  matter for a full PQC readiness posture; they just need different
  collection methods than a TLS handshake scan.
- **No cryptographic primitives are implemented in this repo.** All crypto
  operations are delegated to `sslyze` and the `cryptography` library. If
  a future version needs to *generate* or *validate* PQC key material
  directly (rather than just classify what a TLS scan observes), the
  [Open Quantum Safe project (liboqs)](https://openquantumsafe.org/) is the
  reference implementation to bind against — not a reason to hand-roll
  anything.
- **Known detection limitation:** this scan reports whatever key exchange
  the scanning client (sslyze, via its bundled OpenSSL) actually
  negotiates. As of this writing, that client does not request PQC hybrid
  key-exchange groups (e.g. `X25519MLKEM768`) in its ClientHello. A server
  that only offers a PQC hybrid to clients that ask for it — which is how
  Chrome and some other modern clients already behave — will show up here
  as plain classical ECDHE, even though it may already be partially
  PQC-ready for compliant clients. Treat "no PQC key exchange observed" as
  *not confirmed*, not *confirmed absent*. A v2 using a PQC-aware TLS
  client (OpenSSL 3.2+ with `oqs-provider`, for instance) would close this
  gap.

## Project structure

```
pqc_audit/
  models.py       Typed data structures shared by every stage
  scanner.py       TLS/certificate crypto inventory (sslyze + cryptography)
  rules.py        Rule-engine loader/evaluator
  rules.yaml      The editable classification rule table (the judgment layer)
  risk.py         Risk-prioritization scoring
  report.py       Report context-building and rendering
  templates/      Jinja2 templates (Markdown + HTML)
  targets_io.py   CSV target loading
  scan_io.py      Scan-result JSON serialization (so scan/report can run separately)
  cli.py          `pqc-audit scan|report|audit`
examples/
  targets.csv            Sample target list (mix of modern + deliberately weak endpoints)
  sample_scan_results.json  Raw scan output from a real run against those targets
  sample_report.md / .html  The generated report, checked in as a worked example
tests/            pytest suite (37 tests, no network required)
```

## Testing

```bash
pip install -e ".[dev]"
pytest                                    # 37 tests, all offline
pytest --cov=pqc_audit --cov-report=term-missing   # coverage report
```

The test suite covers the rule engine, risk scoring, report rendering, CSV
loading, and scan-result serialization entirely offline — certificate
parsing is tested against real (self-signed, in-memory) X.509 certificates
generated on the fly, not against the network. Live scanning against real
hosts is exercised by the sample run in `examples/`, not by the default
test suite, since CI/sandboxed environments can't assume outbound network
access.

## Migration timeline this tool is anchored to

- **Aug 2024** — NIST finalizes FIPS 203 (ML-KEM/Kyber), FIPS 204
  (ML-DSA/Dilithium), and FIPS 205 (SLH-DSA/SPHINCS+).
- **Nov 2024** — NIST IR 8547 proposes deprecating ~112-bit-security
  algorithms (RSA-2048, ECC P-256) by 2030.
- **Jan 1, 2027** — CNSA 2.0: new National Security System acquisitions
  expected to be CNSA 2.0-compliant by default.
- **2030** — NIST target deprecation date for RSA-2048/P-256-class
  algorithms; CNSA 2.0 target for exclusive use on software/firmware
  signing and networking equipment.
- **2033** — CNSA 2.0 target for exclusive use on web, cloud, and
  operating systems.
- **2035** — NIST disallowance date for RSA/ECC at any key size; OMB
  M-26-15's full-migration deadline for remaining federal systems, per
  National Security Memorandum 10.

Sources: NIST IR 8547 (*Transition to Post-Quantum Cryptography
Standards*), the NSA's CNSA 2.0 transition timetable (2022, reaffirmed
2025), OMB M-26-15, and National Security Memorandum 10. These same dates
are reproduced in every generated report so the urgency framing is always
traceable back to public guidance, not an arbitrary internal number.

## Roadmap (v2 ideas)

- Data-at-rest and key-management system coverage (databases, object
  storage, HSMs).
- SSH host key and VPN/IPsec configuration scanning.
- PQC-hybrid-aware scanning client to close the detection gap noted above.
- A machine-readable (JSON/CSV) findings export alongside the human report,
  for feeding into a GRC platform.
