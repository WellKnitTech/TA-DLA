# TA-DLA: Threat Actor Data Leak Analyzer

## Overview
TA-DLA is a modular Python toolkit for DFIR practitioners to process, analyze, and report on ransomware leak data. It supports scraping, downloading, extracting, analyzing, and reporting on data from a variety of leak site formats, with a strong focus on OpSec and extensibility via a plugin system.

## Key Features
- **Plugin-based architecture** for scrapers and downloaders (HTTP, FTP, MEGA, etc.)
- **Inventory tracking** with SQLite
- **Recursive extraction** and analysis
- **OpSec enforcement** (TOR/SOCKS5, warnings, and checks)
- **Extensible**: Add new scrapers/downloaders as plugins

## Installation
```
pip install -r requirements.txt
python setup.py develop
```

## Usage

### 1. Scraping Victim Data
Scrape links from a TA leak site (index-style or FTP):
```
ta-dla scrape --case-dir /path/to/case --ta qilin --root-url http://qilinleaksite.onion/victim/acm
```
- The correct scraper plugin will be auto-selected.
- For FTP-based leaks, you will be prompted to include/exclude generic FTP links.

### 2. Downloading Files
Download all files in the inventory (from scraping or manual input):
```
ta-dla download --case-dir /path/to/case
```
Or, download from a text file of URLs (HTTP, FTP, MEGA, etc.):
```
ta-dla download --case-dir /path/to/case --url-list urls.txt
```

#### Downloading FTP URLs Directly
If you have a text file of FTP URLs (with credentials and path):
```
ta-dla download-ftp-urls --case-dir /path/to/case --ftp-url-list ftp_urls.txt
```

### 3. Extraction, Analysis, and Reporting
Extract, analyze, and report as before:
```
ta-dla extract --case-dir /path/to/case

ta-dla analyze --case-dir /path/to/case

ta-dla report --case-dir /path/to/case
```

### 4. Listing Plugins
See all available scraper and downloader plugins:
```
ta-dla list-plugins
```

## OpSec Notes
- All downloads are routed through TOR/SOCKS5 by default.
- You will be warned if OpSec is at risk (e.g., MEGA without TOR).
- Always review findings in a secure, air-gapped environment.

## Extending TA-DLA
- Add new scrapers or downloaders by implementing the appropriate base class and registering via `setup.py` entry points.
- See `ta_dla/scraper/base.py` and `ta_dla/downloader/base.py` for interfaces.

## Example FTP URL Format
```
ftp://username:password@host/path/to/victim
```
- Victim-specific FTP links are preferred; generic links are optional and analyst-controlled.

## Questions?
See the documentation or use `--help` on any command for more details.

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

## Dragonforce Scraper & Downloader

TA-DLA now supports Dragonforce-style leak sites with a dedicated scraper and downloader plugin.

### Usage Example

1. Scrape all files from a Dragonforce leak site:

```
ta-dla scrape --case-dir /path/to/case --ta dragonforce --root-url http://<dragonforce-onion-site>/<victim-leak-page>
```

2. Download all enumerated files (via Tor):

```
ta-dla download --case-dir /path/to/case
```

- The scraper will recursively enumerate all files and directories, saving download links to the inventory.
- The downloader will fetch all pending files using the correct token and path, routing requests through Tor.
- Both plugins are auto-discovered via the plugin system. 