# Installing on Kali Linux

Kali (like all current Debian/Ubuntu derivatives) enforces
[PEP 668](https://peps.python.org/pep-0668/) — the system Python is
"externally managed," so a plain `pip install pqc-readiness-audit` at the
system level will refuse to run. The correct, Kali-native way to install a
standalone Python CLI tool is [`pipx`](https://pipx.pypa.io/): it builds an
isolated virtual environment per app and only exposes that app's entry
point script on your `PATH`, which is exactly the `apt`/tool-drawer
experience you're after — no venv to remember to `source` every session.

This repo's `pyproject.toml` already declares a proper console entry point
(`pqc-audit = "pqc_audit.cli:cli"`) and packages its non-Python resources
(`rules.yaml`, the report templates) as package data, so no packaging
changes were needed to make it pipx-installable — that was verified by
building a wheel and installing it into a clean, isolated virtualenv (the
same mechanism pipx uses under the hood) and confirming the CLI runs and
correctly loads `rules.yaml`/templates from the installed package rather
than the source tree.

**Caveat:** the steps below were verified on macOS using the equivalent
isolated-venv install path (see previous paragraph) — I did not have a
live Kali box to test on directly. The commands are standard `apt`/`pipx`
usage and should work as-is, but if anything doesn't match Kali's current
package names or pipx version, that's the first thing to check.

## 1. Get the repo onto the Kali machine

Pick whichever fits your setup:

**A. You've pushed it to a git remote you control (GitHub/GitLab/etc.):**

```bash
git clone <your-remote-url> pqc-readiness-audit
cd pqc-readiness-audit
```

**B. It's only on your Mac — copy it over directly:**

```bash
# from your Mac, replace <kali-host> with the Kali box's hostname/IP
rsync -avz --exclude .venv --exclude .git ~/pqc-readiness-audit/ <user>@<kali-host>:~/pqc-readiness-audit/
```

(Either works; pipx doesn't care whether the source directory came from
git or scp.)

## 2. Install pipx (if not already present)

```bash
sudo apt update
sudo apt install -y pipx
pipx ensurepath
```

`pipx ensurepath` adds `~/.local/bin` to your `PATH` (in `~/.bashrc` or
`~/.zshrc` depending on your shell) — **open a new terminal** (or `source
~/.bashrc`) after running it so the updated `PATH` takes effect.

If `apt install pipx` isn't available on your Kali version for some
reason, fall back to:

```bash
python3 -m pip install --user pipx --break-system-packages
python3 -m pipx ensurepath
```

(`--break-system-packages` is safe specifically for `pipx` itself, since
pipx's whole job is to then keep everything *else* out of the system
environment.)

## 3. Install the tool

From inside the `pqc-readiness-audit` directory:

```bash
pipx install .
```

This builds the package, creates an isolated venv at
`~/.local/pipx/venvs/pqc-readiness-audit/`, pulls in `sslyze`,
`cryptography`, `click`, `jinja2`, and `PyYAML` from PyPI into that venv,
and symlinks the `pqc-audit` command into `~/.local/bin`.

**If you'd rather not `pip`-install from GitHub-hosted source directly on
a fresh box:** build a wheel once (on your Mac or on Kali) and copy just
that file over instead —

```bash
# on the Mac / source machine
pip install build
python -m build --wheel        # produces dist/pqc_readiness_audit-0.1.0-py3-none-any.whl
```

then `scp` that single `.whl` to Kali and:

```bash
pipx install ./pqc_readiness_audit-0.1.0-py3-none-any.whl
```

Either approach ends up in the same place.

## 4. Verify

```bash
command -v pqc-audit        # should print ~/.local/bin/pqc-audit
pqc-audit --version
pqc-audit --help
```

Run it from any directory, in any new terminal, without activating
anything:

```bash
pqc-audit audit ~/pqc-readiness-audit/examples/targets.csv -o ~/pqc_report.md
```

## 5. Upgrading / uninstalling later

```bash
cd ~/pqc-readiness-audit && git pull   # if installed from a git clone
pipx upgrade pqc-readiness-audit       # or: pipx reinstall pqc-readiness-audit

pipx uninstall pqc-readiness-audit     # clean removal, no leftover files
```

---

## Kali-specific gotchas

- **No root/sudo needed to run scans.** This tool does ordinary outbound
  TCP + TLS handshakes (`sslyze` behaves like a regular HTTPS client, the
  same as `curl`) — it never opens raw sockets, so it's nothing like an
  `nmap -sS` SYN scan that needs `CAP_NET_RAW`/root. Run it as your normal
  non-root user. If you find yourself reaching for `sudo pqc-audit ...`,
  something else is wrong (and running it as root would also make pipx
  install into *root's* isolated venv instead of yours, which you don't
  want).
- **No `nmap` dependency.** The original spec floated `nmap --script
  ssl-enum-ciphers` as a possible fallback scanner, but the implementation
  here is 100% `sslyze` + `cryptography` — there's no `nmap` subprocess
  call anywhere in this codebase. Kali ships `nmap` by default anyway, but
  this tool doesn't need it, so nothing to install there.
- **`sslyze`'s C extension (`nassl`) ships prebuilt manylinux wheels** for
  the architectures Kali actually runs on (x86_64, and generally aarch64
  for Kali on Apple Silicon VMs / Raspberry Pi images), for the Python
  versions Kali currently ships (3.11/3.12). `pipx install .` should just
  pull a binary wheel and not compile anything. If pip ever does fall back
  to a source build for your specific Python/arch combo, you'll see
  compiler errors instead of a clean install — fix with:
  ```bash
  sudo apt install -y build-essential libssl-dev python3-dev
  ```
  then re-run `pipx install .`.
- **Name collision check.** Nothing in Kali's default toolset is named
  `pqc-audit` as of this writing, but Kali's package set changes over
  time and pipx-installed scripts in `~/.local/bin` take PATH precedence
  over `/usr/bin` by default — so a same-named apt package would be
  silently shadowed rather than erroring. Cheap gut-check before (and
  after) installing:
  ```bash
  command -v pqc-audit          # should be empty before install
  apt-cache search pqc-audit    # should return nothing
  ```
- **Network access required.** `pipx install .` needs to reach PyPI to
  pull `sslyze`/`cryptography`/etc. If your Kali box is on a restricted or
  air-gapped network, you'll need `pip download` the dependency wheels
  somewhere with internet access first and point pipx at a local index —
  not covered here since it's an unusual setup, but flag it if it applies
  to you.
- **The scan itself still touches the network like any TLS client** — no
  different from opening the target site in a browser, but if you're
  scanning anything other than public reference/test endpoints, use the
  same authorization discipline you'd apply to any other Kali tool: only
  point this at hosts you own or are explicitly engaged to assess.
