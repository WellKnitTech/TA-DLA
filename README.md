# TA-DLA: Threat Actor Data Leak Analyzer

TA-DLA is a modular Python toolkit for DFIR practitioners to process, analyze, and report on ransomware leak data published by threat actor groups. It supports per-case staging, pluggable modules, and automated enrichment from public threat intel APIs.

## Features
- Modular scrapers and downloaders for different TA leak sites
- Resumable, parallel downloads with inventory tracking
- Extraction of all major archive formats (including nested)
- PII/PHI/PCI and malware/YARA scanning
- Per-case directory structure and SQLite tracking
- Automated enrichment from Ransomware.live
- CLI-driven, no GUI dependencies

## Usage
1. Install dependencies: `pip install -r requirements.txt`
2. Run CLI commands: `python -m ta_dla.cli --help`
3. Each case is managed in its own directory under `cases/`

See `SoftwareRequirements.MD` for full requirements and workflow.

## Case Data Storage

**Important:** TA-DLA never stores case data, downloads, or extracted files inside the toolkit repository. All case data must be stored in a user-specified directory using the `--case-dir` argument. This ensures sensitive data is kept outside the toolkit codebase and can be placed on secure or external storage as needed.

## Project Structure

```
ta_dla/                  # Main toolkit source code
  cli.py                 # CLI entry point
  case_manager.py        # Case directory/config management
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
```

To add support for a new threat actor or download method, create a new module in `scraper/` or `downloader/` and update `ta_config.json` for your case.

## Optional: ClamAV Antivirus Scanning

TA-DLA supports scanning files for malware using ClamAV, via the optional [python-clamd](https://pypi.org/project/clamd/) package and a running ClamAV daemon. This is not required for core functionality, but is recommended for additional malware detection.

### To enable ClamAV scanning:
1. **Install ClamAV and the daemon:**
   - **Ubuntu/Debian:**
     ```sh
     sudo apt-get install clamav-daemon clamav-freshclam
     sudo freshclam
     sudo systemctl start clamav-daemon
     ```
   - **Arch/Manjaro:**
     ```sh
     sudo pacman -S clamav clamav-daemon
     sudo freshclam
     sudo systemctl start clamav-daemon
     ```
2. **Install the Python package:**
   ```sh
   pip install clamd
   ```
3. **Run TA-DLA with ClamAV scanning enabled (CLI integration required).**

If ClamAV or python-clamd is not installed, TA-DLA will skip AV scanning and provide instructions.

## Inventory Tracking (SQLite)

TA-DLA uses a per-case `inventory.db` (SQLite) to track download, extraction, and analysis status for every file. This enables:
- Resumable downloads and analysis (even for very large leak sets)
- Querying failed or pending downloads
- Tracking extraction and analysis findings
- Reliable reporting and workflow recovery

The database is created automatically in each case directory and is required for robust, large-scale workflows. 