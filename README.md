# PrismEX

**PrismEX** is a standalone static analysis tool for **Portable Executable (PE)** files.

PrismEX focuses on **fast, offline, repeatable** inspection of Windows executables to help you triage unknown binaries and generate structured facts for pipelines.

---

## Features

- **Batch & recursive scanning**
  - scan a directory (optionally recursive) with glob filters
- **Richer heuristics** (offline)
  - overlay detection, entropy checks, RWX section detection, entrypoint sanity, clustered import behavior, URL/IP string signals
- **Explainable risk scoring (0–100)**
  - stable `score` field with a breakdown of top contributing factors
  - **configurable scoring & heuristic weights** via a JSON config file
- **YARA scanning (offline)**
  - bundled rules + custom `--yara-dir`
- **High-signal API indicators**
  - flags suspicious APIs using a curated list (bundled `stringsmatch.json`) + additional behavior clusters
- **Reports**
  - human-readable **text**
  - machine-friendly **JSON**
  - shareable **HTML** (single report or batch index)
  - each HTML report includes a **Download JSON** button
  - batch index supports **client-side filtering + sorting**
  - optional **CSV summary export** for batch scans
- **Plugin system**
  - load local plugins from a folder (`--plugin-dir`)
  - or install plugins via Python entry points (`prismex.plugins`)
- **Packaging & CI-ready**
  - ships with a GitHub Actions workflow that runs lint/tests and builds wheels

---

## Supported Platforms

- Linux (recommended)
- macOS
- Windows (works in Python envs where `python-magic` is set up)

---

## Installation

### 1) System dependencies

PrismEX uses `python-magic` and (optionally) YARA (`yara-python`). If you can't install YARA, you can still run PrismEX with `--no-yara`.

Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv libmagic1
```

> If `yara-python` fails to build on your platform, install your distro’s YARA development packages (names vary).

### 2) Install PrismEX

#### Option A — install from a local clone (recommended)

```bash
git clone <your PrismEX repo url here>
cd prismex
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
pip install -e .
```

#### Option B — install as a normal package

```bash
pip install .
```

#### Optional extras

- VirusTotal client helpers:

```bash
pip install .[vt]
```

- Document/VBA analysis helpers (if you add doc modules):

```bash
pip install .[docs]
```

- Authenticode parsing helper (optional, best-effort):

```bash
pip install .[sig]
```

---

## Quick Start

### Scan a PE and print a text report

```bash
prismex scan ./sample.exe
```

### Output JSON to stdout

```bash
prismex scan ./sample.exe --format json
```

### Write JSON to a file

```bash
prismex scan ./sample.exe --format json --out report.json
```

### Generate an HTML report

```bash
prismex scan ./sample.exe --format html --out report.html
```

### Disable heavier steps (strings / YARA)

```bash
prismex scan ./sample.exe --no-strings --no-yara
```

### Use your own YARA rules directory

```bash
prismex scan ./sample.exe --yara-dir ./my_yara_rules
```

---

## Recursive directory scanning

Scan a folder (non-recursive by default):

```bash
prismex scan ./samples --format json
```

Scan recursively and output a batch JSON file:

```bash
prismex scan ./samples --recursive --format json --out batch.json
```

Generate a batch HTML report (writes per-file HTML + an `index.html`):

```bash
prismex scan ./samples --recursive --format html --out ./prismex_html
# open ./prismex_html/index.html
```

Restrict directory scanning using glob patterns (repeatable):

```bash
prismex scan ./samples --recursive --pattern "*.exe" --pattern "*.dll" --format json
```


### Write a batch CSV summary

```bash
prismex scan ./samples --recursive --format html --out ./prismex_html --csv
# writes ./prismex_html/summary.csv
```

You can also choose the CSV location explicitly:

```bash
prismex scan ./samples --recursive --format json --csv-out ./summary.csv
```

### Tune heuristics / scoring without editing code (rules config)

PrismEX reads a JSON config file that can override **scores**, **severity**, and selected **thresholds**.
A ready-to-edit example is included at the repo root:

- `prismex_rules.example.json`

Run PrismEX with a custom config:

```bash
prismex scan ./sample.exe --config ./prismex_rules.example.json --format json
```

Common things to tune:

- `rules.scoring.thresholds` — level boundaries
- `rules.scoring.yara` / `rules.scoring.suspicious_apis` — scoring weights & caps
- `rules.heuristics.*.score` — per-heuristic weights
- `rules.heuristics.overrides` — disable or override a specific heuristic by ID
  - e.g. set `{ "enabled": false }` for noisy checks


---

## Plugins

### List plugins

```bash
prismex plugins list
```

### Run plugins from a folder

```bash
prismex scan ./sample.exe --plugin-dir ./examples/plugins --format json
```

### Only run specific plugins

```bash
prismex scan ./sample.exe --enable-plugin example_metadata --format json
```

### Plugin API

A plugin is a Python file that defines:

- `PLUGIN_NAME = "..."`
- `def prismex_plugin(ctx): ...`

It receives a `ctx` object with:

- `ctx.path` — target path
- `ctx.pe` — loaded `pefile.PE` (best-effort)
- `ctx.report` — mutable report dict you can extend
- `ctx.options` — optional plugin options

See: `examples/plugins/prismex_plugin_template.py`

---

## Report Schema (JSON)

The JSON output is designed to be stable and pipeline-friendly:

```json
{
  "tool": { "name": "PrismEX", "version": "0.3.0" },
  "target": {
    "path": "/abs/path/sample.exe",
    "size": 12345,
    "type": "PE32 executable ...",
    "hashes": { "md5": "...", "sha1": "...", "sha256": "..." }
  },
  "pe": {
    "imphash": "...",
    "timestamp_utc": "2020-01-01 00:00:00",
    "is_dll": false,
    "machine": "0x14c",
    "subsystem": 2,
    "imagebase": 4194304,
    "entrypoint_rva": 4096
  },
  "analysis": {
    "imports": { "KERNEL32.dll": ["CreateFileW", "..."] },
    "sections": { "count": 6, "details": [ /* ... */ ] },
    "directories": { /* ... */ },
    "metadata": { /* ... */ },
    "suspicious_apis": [ /* ... */ ],
    "strings": { "count": 123, "samples": ["http://...", "..."] },
    "yara": [ /* ... */ ],
    "heuristics": {
      "metrics": { "overlay_size": 0, "high_entropy_sections": [ /* ... */ ] },
      "hits": [ { "id": "high_entropy", "severity": "medium", "score": 10, "message": "..." } ]
    },
    "plugins_run": [ { "name": "example_metadata", "status": "ok" } ]
  },
  "score": {
    "value": 42,
    "level": "medium",
    "breakdown": [ { "id": "yara", "points": 25, "message": "..." } ]
  },
  "indicators": [
    { "id": "yara_hits", "severity": "high", "message": "..." }
  ],
  "timing": { "seconds": 0.1234 }
}
```

---

## CI / Packaging

This repo includes:

- `pyproject.toml` (PEP-517 build metadata)
- `.github/workflows/ci.yml` (lint, tests, wheel build)
- `.github/workflows/publish.yml` (optional: publish on tag `v*` via PyPI trusted publishing)

Build locally:

```bash
pip install -U build
python -m build
```

---

## Disclaimer

PrismEX is provided for **defensive analysis and research**. Always ensure you have permission to analyze a given file and follow applicable laws and policies.
