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