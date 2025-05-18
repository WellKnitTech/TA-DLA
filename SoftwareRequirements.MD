# 📄 Requirements Document: TA-DLA (Threat Actor Data Leak Analyzer)

## 🛠 Purpose

TA-DLA is a **modular Python toolkit** designed to assist DFIR practitioners in handling, processing, and reporting on **ransomware leak data** published by threat actor groups. The toolkit supports **per-case staging**, **per-TA module customization**, and **automated enrichment** from public threat intel APIs.

---

## 🔁 Workflow Phases

### 1. **Scraping** (optional)

* Pulls download links from known TA blog pages over TOR
* TA-specific logic via pluggable scraper modules
* Output stored in `scraped/<victim_id>.json` inside the case directory

### 2. **Downloading**

* Supports hundreds or thousands of files via MEGA, FTP, HTTP/S
* Uses modular downloader logic (selected by TA or method)
* Supports:

  * Resumable downloads
  * Parallel threads
  * Inventory tracking of file success/failure
* Output stored in `downloads/` inside the case directory

### 3. **Extraction**

* Handles `.zip`, `.7z`, `.rar`, `.tar.gz`, including nested archives
* Reconstructs directory structure if available
* Output stored in `extracted/`

### 4. **Analysis**

* Optional scanning modules:

  * **PII/PHI/PCI detection** via regex and entropy
  * **Malware/YARA scanning**
* Output includes:

  * `reports/pii.csv`, `malware.csv`, etc.
  * `reports/dashboard.html`

---

## 📁 Case Directory Structure

Each case is worked within its own `--case-dir`, created and managed by the toolkit.

```plaintext
/cases/<case-dir>/
├── scraped/              # Output from scraper modules
├── downloads/            # All downloaded leak files
├── extracted/            # Fully unpacked contents
├── reports/              # CSV + HTML output
├── logs/                 # Download or extraction errors
├── inventory/            # Download tracking per file
├── enriched.json         # Victim metadata (from Ransomware.live)
├── ta_config.json        # Mapping of TA to scraper/downloader
```

---

## ✅ Core Functional Requirements

| ID   | Requirement                                                                         |
| ---- | ----------------------------------------------------------------------------------- |
| FR1  | Support for scraper modules, each tailored to a specific TA leak site layout        |
| FR2  | Support for modular downloaders (FTP, MEGA, HTTP) selected by TA or method          |
| FR3  | Resumable downloads with progress/inventory tracking                                |
| FR4  | Batch download support (hundreds or thousands of files)                             |
| FR5  | Optional scraping can be bypassed with manual URL input                             |
| FR6  | Download staging, extraction, and reporting organized by `--case-dir`               |
| FR7  | Automatic directory creation for case work                                          |
| FR8  | Extraction of all major archive formats, including nested handling                  |
| FR9  | Optional PII/PHI/PCI scanning with regex/entropy                                    |
| FR10 | Optional YARA/malware scanning using external signatures or ClamAV                  |
| FR11 | Output includes CSV reports and summary HTML dashboard                              |
| FR12 | All CLI steps (`scrape`, `download`, `extract`, `analyze`) can be run independently |
| FR13 | Uses `ta_config.json` to determine scraper/downloader module per TA                 |
| FR14 | Uses Ransomware.live API to enrich cases (`/groups`, `/searchvictims/<keyword>`)    |

---

## 🔐 Non-Functional Requirements

| ID   | Requirement                                                                |
| ---- | -------------------------------------------------------------------------- |
| NFR1 | TOR or SOCKS5 proxy required for any .onion site interactions              |
| NFR2 | CLI-native design; no GUI dependencies                                     |
| NFR3 | Runs on Linux or Windows (Python 3.10+)                                    |
| NFR4 | All forensic artifacts must be read-only or copied; never altered in place |
| NFR5 | Output should be suitable for non-technical consumers (e.g., legal teams)  |
| NFR6 | Should support offline/air-gapped analysis post-download                   |

---

## 🔗 External Integration Points

### Ransomware.live API

| Endpoint                       | Usage                                                              |
| ------------------------------ | ------------------------------------------------------------------ |
| `GET /groups`                  | Used to refresh list of known TAs and their active/inactive status |
| `GET /searchvictims/<keyword>` | Enrich case metadata and validate public exposure                  |

---

## 📊 Case Activity Tracking (SQLite Required)

Each case must persist structured state across all phases of execution using a **lightweight SQLite database (`inventory.db`)**. This ensures reliable, queryable tracking of download progress, file metadata, analysis results, and recovery/resumption logic — even for extremely large leak sets (500,000+ files).

### 🔹 Core Table: `downloads`
Tracks all download targets and their status.

```sql
CREATE TABLE downloads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  url TEXT,
  filename TEXT,
  status TEXT,            -- pending, complete, failed
  sha1 TEXT,
  size INTEGER,
  last_attempt TEXT,
  error TEXT
);
CREATE INDEX idx_status ON downloads(status);
```

### 🔹 Future Tables (optional extensions)
- `extracted_files`: metadata, timestamps, nested depth
- `pii_findings`: path, pattern match type, sensitivity level
- `malware_hits`: rule name, matched path, severity
- `events`: case activity log and milestone tracking

### 🔹 Workflow Integration
The toolkit must:
- **Populate `downloads` before the download phase begins**
- **Update rows live during threaded download**
- **Resume from incomplete state if `status != 'complete'`**
- **Allow CLI user to confirm restart, resume, or skip**

### 🔹 Example Queries

```sql
SELECT COUNT(*) FROM downloads WHERE status = 'failed';
SELECT * FROM downloads WHERE status = 'pending' LIMIT 10;
SELECT * FROM downloads WHERE error IS NOT NULL;
```
