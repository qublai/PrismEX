# PrismEX

PrismEX is a **developer-first** static analysis tool for **Portable Executable (PE)** files (EXE/DLL). It’s designed for **fast, offline, repeatable triage** and produces **structured output** you can feed into pipelines.

---

## Key Features

- **Batch & recursive scanning**
  - Scan a single file or a directory
  - Optional recursion + repeatable glob patterns for deterministic batches

- **Richer offline heuristics**
  - Overlay detection
  - Section entropy signals
  - RWX section detection
  - Entrypoint sanity checks
  - Import clustering / suspicious import behaviors
  - URL/IP string signals

- **Explainable risk scoring (0–100)**
  - Stable numeric score with severity level buckets
  - Transparent breakdown showing top contributors
  - Tunable weights and thresholds via JSON rules config

- **YARA scanning (offline)**
  - Bundled rules + custom `--yara-dir`
  - Can be disabled when not available

- **High-signal API indicators**
  - Suspicious API detection via curated signatures (bundled `stringsmatch.json`)
  - Helps surface “why this binary looks risky” quickly

- **Reports**
  - Text (human-readable)
  - JSON (machine-friendly)
  - HTML (shareable)
    - Single-file HTML reports
    - Batch HTML index page
    - Download JSON button embedded in HTML
    - Batch index supports filtering + sorting
    - Optional CSV export for batch summary

- **Plugin system**
  - Load local plugins from a folder (`--plugin-dir`)
  - Or install plugins via Python entry points (`prismex.plugins`)

- **CI & packaging friendly**
  - Lint + test pipeline
  - Build sdist/wheel support

---

## Supported Platforms

- **Linux** (recommended)
- **macOS**
- **Windows** (works in standard Python environments; see notes on `libmagic` below)

---

# Installation (Developer Workflow)

PrismEX “running options for users” below assume **dev mode**: clone the repo, create a venv, install editable, run commands from that environment.

## 0) Prerequisites

- Python **3.9+**
- Pip (latest recommended)

### Notes about `python-magic` / `libmagic`
PrismEX uses `python-magic` for file-type identification. Depending on OS, you may need system `libmagic`.

---

## macOS (Developer Install)

### 1) Install system deps (Homebrew)
```bash
brew install libmagic
```

### 2) Clone + venv + dev install
```bash
cd ~
git clone <YOUR_PRISMEX_REPO_URL>
cd PrismEX

python3 -m venv .venv
source .venv/bin/activate

python -m pip install -U pip setuptools wheel
python -m pip install -r requirements.txt
python -m pip install -e ".[dev]"
```

### 3) Verify
```bash
prismex --help
```

---

## Linux (Ubuntu/Debian) (Developer Install)

### 1) Install system deps
```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip libmagic1
```

### 2) Clone + venv + dev install
```bash
cd ~
git clone <YOUR_PRISMEX_REPO_URL>
cd PrismEX

python3 -m venv .venv
source .venv/bin/activate

python -m pip install -U pip setuptools wheel
python -m pip install -r requirements.txt
python -m pip install -e ".[dev]"
```

### 3) Verify
```bash
prismex --help
```

---

## Windows (Developer Install)

### 1) Install Python
Install Python 3.9+ from the Microsoft Store or python.org, then confirm:
```bat
python --version
```

### 2) Get the repo (Git recommended)
If you don’t have Git installed, install it first:
```bat
git --version
```

Clone:
```bat
cd %USERPROFILE%
git clone <YOUR_PRISMEX_REPO_URL>
cd PrismEX
```

### 3) Create + activate venv

**PowerShell:**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**CMD:**
```bat
python -m venv .venv
.\.venv\Scripts\activate.bat
```

### 4) Install PrismEX (dev)
```bat
python -m pip install -U pip setuptools wheel
python -m pip install -r requirements.txt
python -m pip install -e ".[dev]"
```

### 5) `python-magic` on Windows (important)
If you see errors related to `magic` / `libmagic`, the easiest fix in the **venv** is:
```bat
python -m pip install python-magic-bin
```
(You can keep `python-magic` installed; `python-magic-bin` provides Windows binaries in many setups.)

### 6) Verify
```bat
prismex --help
```

---

# Running PrismEX (Dev Mode)

## Basic scan
```bash
prismex scan ./sample.exe
```

## JSON output to stdout
```bash
prismex scan ./sample.exe --format json
```

## JSON output to a file
```bash
prismex scan ./sample.exe --format json --out report.json
```

## HTML report (single file)
```bash
prismex scan ./sample.exe --format html --out report.html
```

## Disable heavier steps
```bash
prismex scan ./sample.exe --no-strings --no-yara
```

## Use custom YARA rules
```bash
prismex scan ./sample.exe --yara-dir ./my_yara_rules
```

---

## Directory scanning

### Scan a folder (non-recursive)
```bash
prismex scan ./samples --format json
```

### Recursive scan + batch JSON
```bash
prismex scan ./samples --recursive --format json --out batch.json
```

### Batch HTML report (writes per-file HTML + index.html)
```bash
prismex scan ./samples --recursive --format html --out ./prismex_html
# open ./prismex_html/index.html
```

### Restrict scanning with glob patterns
```bash
prismex scan ./samples --recursive --pattern "*.exe" --pattern "*.dll" --format json
```

### Batch CSV summary
```bash
prismex scan ./samples --recursive --format html --out ./prismex_html --csv
# writes ./prismex_html/summary.csv
```

Or choose CSV location:
```bash
prismex scan ./samples --recursive --format json --csv-out ./summary.csv
```

---

# Rules Config (Tune Heuristics & Scoring)

PrismEX can load a JSON config to override weights, thresholds, and enable/disable heuristics without editing code.

Example file (repo root):
- `prismex_rules.example.json`

Run with a custom config:
```bash
prismex scan ./sample.exe --config ./prismex_rules.example.json --format json
```

Common knobs:
- `rules.scoring.thresholds` — level boundaries
- `rules.scoring.yara` / `rules.scoring.suspicious_apis` — weights & caps
- `rules.heuristics.*.score` — per-heuristic weights
- `rules.heuristics.overrides` — disable/override a heuristic by ID (`{"enabled": false}`)

---

# Plugins

## List plugins
```bash
prismex plugins list
```

## Run plugins from a folder
```bash
prismex scan ./sample.exe --plugin-dir ./examples/plugins --format json
```

## Run only specific plugins
```bash
prismex scan ./sample.exe --enable-plugin example_metadata --format json
```

### Plugin API
A plugin is a Python file that defines:
- `PLUGIN_NAME = "..."`
- `def prismex_plugin(ctx): ...`

The `ctx` object provides:
- `ctx.path` — target path
- `ctx.pe` — loaded `pefile.PE` (best-effort)
- `ctx.report` — mutable report dict to extend
- `ctx.options` — optional plugin options

See:
- `examples/plugins/prismex_plugin_template.py`

---

# Developer Checks

## Lint
```bash
ruff check prismex tests
```

## Tests
```bash
pytest -q
```

---

# Troubleshooting

## `prismex: command not found` (macOS/Linux)
You likely didn’t activate the venv.
```bash
cd /path/to/PrismEX
source .venv/bin/activate
prismex --help
```

If you want to run without activating:
```bash
./.venv/bin/python -m prismex.cli --help
```

## Windows: activation commands differ
- PowerShell: `.\.venv\Scripts\Activate.ps1`
- CMD: `.\.venv\Scriptsctivate.bat`

## Windows: `magic` / `libmagic` errors
Install:
```bat
python -m pip install python-magic-bin
```

---

# Disclaimer

PrismEX is provided for defensive analysis and research. Only analyze binaries you have permission to inspect, and follow applicable laws and policies.
