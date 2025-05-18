# TA-DLA: Threat Actor Data Leak Analyzer

TA-DLA is a robust, modular Python toolkit for DFIR practitioners to process, analyze, and report on ransomware leak data published by threat actor groups. It is designed for per-case staging, modular scrapers/downloaders, automated enrichment, and robust reporting, with a strong focus on OpSec (anonymity, no case data in the repo, TOR support, etc.).

## Features
- Modular scrapers and downloaders for different TA leak sites (HTTP, FTP, MEGA; all support TOR/OpSec enforcement)
- Resumable, parallel downloads with granular inventory tracking (SQLite)
- Extraction of all major archive formats (zip, 7z, rar, tar.gz, gz, bz2; supports passwords and nested extraction)
- PII/PHI/PCI scanner (regex + entropy, parallelized, batch-processed, CSV output)
- YARA scanner (multiple rulesets, parallel, CSV output)
- ClamAV integration (optional, parallelized, with user guidance)
- Automated enrichment from Ransomware.live API
- Per-case directory structure and atomic status updates
- HTML dashboard reporting (Jinja2, OpSec reminders, cross-references, high-risk file highlighting)
- CLI-driven, no GUI dependencies, with strong OpSec enforcement and reminders
- Unit/integration tests and robust CI (GitHub Actions)
- MIT License

## Usage
1. Install dependencies: `pip install -r requirements.txt`
2. Run CLI commands: `python -m ta_dla.cli --help`
3. Each case is managed in its own directory (e.g., `--case-dir /cases/AcmeCorp_Qilin/`)

See `SoftwareRequirements.MD` for full requirements and workflow.

## Case Data Storage

**Important:** TA-DLA never stores case data, downloads, or extracted files inside the toolkit repository. All case data must be stored in a user-specified directory using the `--case-dir` argument. This ensures sensitive data is kept outside the toolkit codebase and can be placed on secure or external storage as needed.

## Case Initialization & Workflow

**Every case should be initialized with the `init-case` command:**

```
ta-dla init-case --case-dir /cases/AcmeCorp_Qilin/
```
- Prompts for victim, threat actor, description, analyst, and date
- Uses ransomware.live enrichment if available, but allows manual entry if offline
- Creates a standardized directory structure and saves all metadata in `case.json`

**Typical Case Flow:**
1. `init-case` — Set up the case directory, metadata, and structure
2. `scrape` (optional) — Scrape TA leak sites for download links
3. `download` / `download_ftp` / `download_http` — Download files (uses inventory tracking)
4. `extract` — Extract all supported archives (nested, password-protected)
5. `analyze` — Scan for PII/PHI/PCI, YARA, and ClamAV findings (uses metadata from `case.json`)
6. `report` — Generate HTML dashboard and CSV summaries (uses metadata from `case.json`)
7. Inventory/DB management as needed

All commands use `case.json` for victim, TA, and other metadata unless overridden by CLI options.

## Project Structure

```
ta_dla/                  # Main toolkit source code
  cli.py                 # CLI entry point
  case_manager.py        # Case directory/config management (case.json)
  scraper/               # Pluggable scraper modules (per TA)
  downloader/            # Pluggable downloader modules
  extractor/             # Archive extraction logic
  analyzer/              # Analysis modules (PII, malware, YARA)
  enrichment/            # Ransomware.live API integration
  db/                    # SQLite helpers
  utils.py               # Shared utilities

requirements.txt         # Python dependencies
README.md                # Project documentation
SoftwareRequirements.MD  # Full requirements
.github/workflows/ci.yml # GitHub Actions CI workflow
LICENSE                  # MIT License
```

To add support for a new threat actor or download method, create a new module in `scraper/` or `downloader/` and update your case's `case.json` as needed.

## CLI Overview

TA-DLA provides a modular CLI (via Click) with commands for scraping, downloading, extracting, analyzing, and reporting. All commands enforce OpSec by default (TOR checks, warnings, and bypass flags). Key commands include:
- `init-case`: Initialize a new case, prompt for metadata, create directories, and save `case.json`
- `download` / `download_ftp` / `download_http` / `resume_downloads`: Download files from various sources with OpSec enforcement
- `scrape`: Scrape TA leak sites for download links
- `extract`: Extract all supported archive types, including nested and password-protected
- `analyze`: Scan for PII/PHI/PCI, YARA, and ClamAV findings (CSV output; uses `case.json` for metadata)
- `report`: Generate HTML dashboard and CSV summaries (uses `case.json` for metadata)
- `inventory_status`, `pending_downloads`, `failed_downloads`, `clear_failed_downloads`, `retry_failed_downloads`, `export_inventory`: Inventory and DB management
- `opsec_check`: Print OpSec reminders and check if TOR is running

Run `python -m ta_dla.cli --help` for full command details.

## Reporting & Dashboard

- Generates HTML dashboard (Jinja2) summarizing downloads, findings, cross-references, and OpSec reminders
- CSV reports for PII/PHI/PCI, YARA, ClamAV, and cross-referenced files
- Highlights files with multiple types of sensitive data
- Designed for secure, air-gapped review

## Inventory Tracking (SQLite)

TA-DLA uses a per-case `inventory.db` (SQLite) to track download, extraction, and analysis status for every file. This enables:
- Resumable downloads and analysis (even for very large leak sets)
- Querying failed, pending, or partial downloads
- Tracking extraction and analysis findings with granular status codes (e.g., `pending`, `in-progress`, `complete`, `failed`, `skipped`, `corrupt`, `password-protected`, `partial`)
- Reliable reporting and workflow recovery

The database is created automatically in each case directory and is required for robust, large-scale workflows.

## OpSec & Anonymity

- All downloaders and scrapers enforce TOR/SOCKS5 usage for .onion and sensitive sites
- CLI and reporting include OpSec reminders and warnings
- MEGA downloads warn if not using system proxying
- Extraction, download, and analysis phases are robust to OpSec and error handling
- No case data is ever stored in the repo

## Testing & CI

- Unit and integration tests for core modules (downloaders, extractors, CLI, reporting, etc.)
- End-to-end workflow tests recommended for contributors
- GitHub Actions CI: runs linting, security audit, and tests (with coverage) on Python 3.9, 3.10, and 3.11
- Coverage report uploaded as an artifact on each run

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

For more details, see `SoftwareRequirements.MD` and the in-code documentation. 