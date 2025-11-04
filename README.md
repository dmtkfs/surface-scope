# SurfaceScope: Attack-Surface & Exposure Mapping (CLI)

***SurfaceScope** is a no-frills CLI that discovers assets, probes exposure and summarizes cloud risks. It can run in a deterministic **demo** mode (for screenshots and walkthroughs) or a **real** mode using your inputs (targets JSON, domain and optional cloud data). Outputs include a plain-text report, a lightweight **single-file HTML** dashboard and an optional **JSON** context dump.*

- **Zero mandatory deps** (stdlib only).
- **Optional**: DNS bruteforce via `dnspython` and live AWS snapshot via `boto3`.
- **Windows-friendly**: Ships with `docs/demo_suite.ps1` for quick demos.

## Features

- **Shadow Discovery**  
  - Demo mode: Synthetic but realistic findings (A/CNAME/NXDOMAIN, dangling CNAMEs).
  - Real mode: Apex + common subdomains (`www, api, dev, staging, test`) via `socket`/`nslookup`.  
  - Optional **wordlist bruteforce** when `dnspython` is installed (`--dns-wordlist`).
- **Exposure Grading**  
  - Quick port probes for a host list with simple policy-based grade (**LOW / MED / HIGH ⚠**).  
  - Fetches minimal HTTP/HTTPS server banners when 80/443 open.  
  - Supports **async** probing (`--async-probe`) for faster sweeps.
- **Cloud Footprint Summary**  
  - Offline JSON summary (`--cloud-json`) or **live AWS snapshot** (`--aws-live` with `boto3`).  
  - Flags public S3 buckets and wide-open SGs (0.0.0.0/0 → 22/3389).  
  - Counts buckets, instances, IAM roles and shows top flags in HTML.
- **Artifacts**  
  - Plain text report (`surface-scope-reports/*.txt`).
  - Single-file **HTML** dashboard (cards + full text).
  - **JSON** with module contexts (machine-readable).
- **Safety & CI**  
  - `--no-write` dry run (prints output paths but writes **nothing**).  
  - `--quiet` to suppress console output **except errors**.  
  - Deterministic demo via `--demo-seed`.

## Installation

No installation required for base usage (stdlib only).

Optional extras:
```bash
# DNS bruteforce (optional)
pip install dnspython

# Live AWS snapshot (optional)
pip install boto3
````

> *For `--aws-live`, ensure your AWS creds are available (env vars, shared config or an instance profile).*

## Quick Start

### 1) Demo (safe & deterministic)

```bash
# all-in-one demo scan with HTML + JSON artifacts
python surface_scope.py run --demo -d acme.corp \
  --policy paranoid --demo-seed 1337 \
  --html-out surface-scope-reports/demo.html \
  --json-out surface-scope-reports/demo.json
```

### 2) Real mode from local inputs

```bash
# probe a fixed list of hosts and summarize cloud JSON
python surface_scope.py run \
  --targets docs/targets.json \
  --cloud-json docs/aws_demo.json \
  --timeout 1.5 \
  --html-out surface-scope-reports/run.html \
  --json-out surface-scope-reports/run.json
```

### 3) Real mode with domain discovery (+ optional wordlist)

```bash
# basic real discovery (apex + common subdomains) then grade
python surface_scope.py run -d yourcorp.com \
  --html-out surface-scope-reports/yourcorp.html

# add bruteforce if dnspython is installed
python surface_scope.py run -d yourcorp.com \
  --dns-wordlist wordlists/common.txt --dns-workers 50 \
  --html-out surface-scope-reports/yourcorp-brute.html
```

### 4) Live AWS snapshot

```bash
# requires boto3 and valid AWS credentials
python surface_scope.py run --aws-live \
  --html-out surface-scope-reports/aws.html
```

## CLI

Run `-h` for the latest help:

```
usage: surface-scope [-h] {discover,grade,cloud,run,scan,selftest} ...

SurfaceScope: Attack-surface & exposure mapping

positional arguments:
  {discover,grade,cloud,run,scan,selftest}
    discover   Discover shadow assets via DNS and simple heuristics
    grade      Probe discovered hosts and compute exposure scores
    cloud      Summarize offline IaC or AWS JSON assets
    run        Run all modules and export a combined report
    scan       Alias of 'run' - execute all modules
    selftest   Run a minimal self test

options:
  -h, --help
```

### `run` / `scan` (scan is an alias of run)

```
usage: surface-scope run [-h] [--domain DOMAIN] [--cloud-json CLOUD_JSON]
                         [--targets TARGETS] [--ports PORTS] [--timeout TIMEOUT]
                         [--limit LIMIT] [--out OUT] [--json-out JSON_OUT]
                         [--policy {minimal,balanced,paranoid}] [--demo]
                         [--demo-seed DEMO_SEED] [--policy-json POLICY_JSON]
                         [--html-out HTML_OUT] [--quiet] [--no-write]
                         [--dns-wordlist DNS_WORDLIST] [--dns-workers DNS_WORKERS]
                         [--dns-timeout DNS_TIMEOUT] [--aws-live] [--async-probe]
```

**Key arguments:**

* `--domain, -d`: Domain for discovery (demo or real).
* `--targets`: JSON file of `{"host": "..."}` objects (used by `grade`).
* `--cloud-json`: Offline cloud snapshot JSON (S3/EC2/IAM/SGs).
* `--aws-live`: Live AWS account snapshot via `boto3` (*optional dep*).
* `--ports`: Comma list of ports to probe (default `22,80,443,445,3389`).
* `--timeout`: Per-probe timeout seconds (default `1.0`).
* `--limit`: Discovery cap (default `100`).
* `--policy`: Grading thresholds: `minimal | balanced | paranoid`.
  * *To **override** thresholds, use `--policy-json` (see below).*
* `--policy-json`: Custom JSON thresholds. Label becomes `custom(filename)`.
* `--demo` / `--demo-seed`: Synthetic, repeatable results for demos.
* `--dns-wordlist` / `--dns-workers` / `--dns-timeout`: Enable bruteforce (requires `dnspython`).
* `--async-probe`: Faster port scanning via asyncio.
* `--html-out`: Write a single-file HTML dashboard.
* `--json-out`: Write machine-readable JSON context.
* `--out`: Write the plain-text report. Default path is auto-generated.
* `--quiet`: **Suppresses all console output except errors**.
* `--no-write` **(dry run)**: Prints results but **does not** write files.

> ***Note on custom policies**: `--policy` only accepts `minimal|balanced|paranoid`.*
> *To supply your own thresholds, keep `--policy balanced` (or any built-in) **and** add `--policy-json docs/policy.json`. The report label will show `custom(policy.json)`.*

### `discover`

```
--domain -d  (required)
--limit
--demo
--dns-wordlist (requires dnspython)
--dns-workers
--dns-timeout
--out
```

### `grade`

```
--targets (required)
--ports
--timeout
--demo
--async-probe
--out
```

### `cloud`

```
--cloud-json           # offline JSON
--aws-live             # live AWS via boto3
--demo
--out
```

### `selftest`

Quick smoke test: `python surface_scope.py selftest`

## Policies & Grading

Built-in:

* `minimal`: `high_any = {22,3389,445}`, `med_num_open = 3`
* `balanced`: `high_any = {22,3389,445}`, `med_num_open = 2`
* `paranoid`: `high_any = {22,3389,445,21,23}`, `med_num_open = 1`

A host is **HIGH** if it exposes any `high_any` port **and** also exposes web or multiple services.
Otherwise, **MED** if `open_port_count >= med_num_open`. Else **LOW**.

Custom thresholds file (example `docs/policy.json`):

```json
{
  "high_any": [22, 3389, 445, 21],
  "med_num_open": 1
}
```

Use it with:

```bash
python surface_scope.py run --demo -d acme.corp \
  --policy balanced --policy-json docs/policy.json
```

## Outputs

* **Text**: `surface-scope-reports/surface-scope-YYYYMMDD-HHMMSS.txt` (or `--out` path)
  * *Includes discovery, exposure table, banners, cloud summary, “What this means” and a **Risk Summary**.*
* **HTML**: `--html-out <path>`
  * *Single file with four KPI cards (LOW/MED/HIGH/Cloud Flags), Top Flags list and the full text report.*
* **JSON**: `--json-out <path>`
  * *Machine-readable module contexts + metadata (e.g., `probes`, `flags`, effective policy label, etc.).*

## Demo Suite (PowerShell)

On Windows (PowerShell 7+ recommended):

```powershell
pwsh .\docs\demo_suite.ps1
```

This script:

1. Creates demo inputs: `docs/targets.json`, `docs/aws_demo.json`, `docs/policy.json`
2. Runs:
   * Demo paranoid run (HTML + JSON)
   * `scan` alias demo (HTML)
   * Real run from local inputs (HTML + JSON)
   * Quiet mode demo
   * Dry run demo (`--no-write`)

Each command is checked for non-zero exit codes and the script stops on failure.

## Deployment Notes

* **DNS bruteforce**: Install `dnspython`. Wordlist results are appended to discovery.
* **AWS live**: Install `boto3`. The tool uses `list_buckets`, `get_bucket_acl/policy_status`, `describe_security_groups/instances` and `list_roles`.
* **Banners**: HTTP/HTTPS banners are best-effort (raw sockets + TLS handshake).
* **Async probes**: Use `--async-probe` for large target sets.

## Troubleshooting

* `argument --policy: invalid choice: 'custom'`
  * *Use `--policy-json` with a valid built-in (`--policy balanced --policy-json docs/policy.json`).*
* *“No files written”* when expecting artifacts
  * *Check you didn’t pass `--no-write`. Also ensure you provided `--html-out` / `--json-out` if you want those.*
* AWS errors/missing creds
  * *Configure credentials via env vars or `~/.aws/*` or run inside an environment with an instance profile.*

## Security & Ethics

* Use real-mode responsibly and only against assets you own or are authorized to test.
* The tool does minimal, non-intrusive probing (TCP connect + banner fetch). Increase timeouts carefully to avoid false negatives.
