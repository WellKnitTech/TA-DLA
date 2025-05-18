"""
SQLite inventory tracking for TA-DLA.
Tracks downloads, extraction, analysis, and events per case.
"""
import os
import sqlite3
from typing import Optional, List, Dict, Any
import logging

SCHEMA = {
    'downloads': '''
        CREATE TABLE IF NOT EXISTS downloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            filename TEXT,
            status TEXT,            -- pending, complete, failed, skipped, corrupt, password-protected, partial, in-progress
            sha1 TEXT,
            size INTEGER,
            last_attempt TEXT,
            error TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_status ON downloads(status);
    ''',
    'extracted_files': '''
        CREATE TABLE IF NOT EXISTS extracted_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT,
            parent_archive TEXT,
            depth INTEGER,
            extracted_at TEXT
        );
    ''',
    'pii_findings': '''
        CREATE TABLE IF NOT EXISTS pii_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file TEXT,
            pattern_type TEXT,
            match TEXT,
            line INTEGER,
            context TEXT,
            detected_at TEXT
        );
    ''',
    'malware_hits': '''
        CREATE TABLE IF NOT EXISTS malware_hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file TEXT,
            rule_name TEXT,
            signature TEXT,
            engine TEXT,
            detected_at TEXT
        );
    ''',
    'events': '''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT,
            details TEXT,
            timestamp TEXT
        );
    '''
}

# Status codes for downloads.status:
#   pending: waiting to be downloaded
#   in-progress: currently being downloaded
#   complete: successfully downloaded
#   failed: download failed (network, server, etc.)
#   skipped: intentionally skipped by user or logic
#   corrupt: file was downloaded but failed integrity check or extraction
#   password-protected: file could not be extracted due to missing password
#   partial: partially downloaded, can be resumed

# Additional status codes for downloads.status and analysis:
#   malware-detected: file flagged by YARA or ClamAV
#   pii-detected: file flagged by PII/PHI/PCI scanner
#   yara-flagged: file flagged by YARA
#   clamav-flagged: file flagged by ClamAV
#   analyzed: file analyzed, no issues found

def get_db_path(case_dir: str) -> str:
    """Return the path to the inventory.db for a given case directory."""
    return os.path.join(case_dir, 'inventory.db')

def init_inventory_db(case_dir: str):
    """Initialize inventory.db with all required tables."""
    db_path = get_db_path(case_dir)
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        for ddl in SCHEMA.values():
            for stmt in ddl.strip().split(';'):
                if stmt.strip():
                    cur.execute(stmt)
        conn.commit()

def get_logger(case_dir: str):
    logs_dir = os.path.join(case_dir, 'logs')
    os.makedirs(logs_dir, exist_ok=True)
    log_path = os.path.join(logs_dir, 'inventory_errors.log')
    logger = logging.getLogger(f'ta_dla.inventory.{os.path.basename(case_dir)}')
    if not logger.handlers:
        handler = logging.FileHandler(log_path)
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.ERROR)
        logger.propagate = False
    return logger

def add_download(case_dir: str, url: str, filename: str, status: str = 'pending', sha1: Optional[str] = None, size: Optional[int] = None, error: Optional[str] = None) -> bool:
    """Add a new download record. If (url, filename) exists, do not insert a duplicate."""
    db_path = get_db_path(case_dir)
    logger = get_logger(case_dir)
    try:
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute('SELECT id FROM downloads WHERE url=? AND filename=?', (url, filename))
            if cur.fetchone():
                return False  # Already exists
            cur.execute('''
                INSERT INTO downloads (url, filename, status, sha1, size, last_attempt, error)
                VALUES (?, ?, ?, ?, ?, datetime('now'), ?)
            ''', (url, filename, status, sha1, size, error))
            conn.commit()
        return True
    except Exception as e:
        logger.error(f"add_download error: url={url}, filename={filename}, error={e}")
        return False

def update_download_status(case_dir: str, url: str, status: str, sha1: Optional[str] = None, size: Optional[int] = None, error: Optional[str] = None) -> bool:
    """Update the status, sha1, size, or error for a download by URL."""
    db_path = get_db_path(case_dir)
    logger = get_logger(case_dir)
    try:
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute('''
                UPDATE downloads SET status=?, sha1=?, size=?, last_attempt=datetime('now'), error=? WHERE url=?
            ''', (status, sha1, size, error, url))
            conn.commit()
        return True
    except Exception as e:
        logger.error(f"update_download_status error: url={url}, status={status}, error={e}")
        return False

def get_downloads_by_status(case_dir: str, status: str) -> List[Dict[str, Any]]:
    """Return all downloads with a given status (pending, failed, complete)."""
    db_path = get_db_path(case_dir)
    logger = get_logger(case_dir)
    try:
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM downloads WHERE status=?', (status,))
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]
    except Exception as e:
        logger.error(f"get_downloads_by_status error: status={status}, error={e}")
        return []

def get_failed_downloads(case_dir: str) -> List[Dict[str, Any]]:
    """Return all failed downloads."""
    return get_downloads_by_status(case_dir, 'failed')

def get_pending_downloads(case_dir: str) -> List[Dict[str, Any]]:
    """Return all pending downloads."""
    return get_downloads_by_status(case_dir, 'pending')

def add_extracted_file(case_dir: str, path: str, parent_archive: Optional[str], depth: int) -> bool:
    """Add a record for an extracted file. Deduplicate on (path, parent_archive, depth)."""
    db_path = get_db_path(case_dir)
    logger = get_logger(case_dir)
    try:
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute('SELECT id FROM extracted_files WHERE path=? AND parent_archive=? AND depth=?', (path, parent_archive, depth))
            if cur.fetchone():
                return False  # Already exists
            cur.execute('''
                INSERT INTO extracted_files (path, parent_archive, depth, extracted_at)
                VALUES (?, ?, ?, datetime('now'))
            ''', (path, parent_archive, depth))
            conn.commit()
        return True
    except Exception as e:
        logger.error(f"add_extracted_file error: path={path}, parent_archive={parent_archive}, depth={depth}, error={e}")
        return False

def add_pii_finding(case_dir: str, file: str, pattern_type: str, match: str, line: int, context: str) -> bool:
    """Add a PII/PHI/PCI finding record. Deduplicate on (file, pattern_type, match, line)."""
    db_path = get_db_path(case_dir)
    logger = get_logger(case_dir)
    try:
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute('SELECT id FROM pii_findings WHERE file=? AND pattern_type=? AND match=? AND line=?', (file, pattern_type, match, line))
            if cur.fetchone():
                return False
            cur.execute('''
                INSERT INTO pii_findings (file, pattern_type, match, line, context, detected_at)
                VALUES (?, ?, ?, ?, ?, datetime('now'))
            ''', (file, pattern_type, match, line, context))
            conn.commit()
        return True
    except Exception as e:
        logger.error(f"add_pii_finding error: file={file}, pattern_type={pattern_type}, match={match}, line={line}, error={e}")
        return False

def add_malware_hit(case_dir: str, file: str, rule_name: str, signature: str, engine: str) -> bool:
    """Add a malware hit record (YARA or ClamAV). Deduplicate on (file, rule_name, signature, engine)."""
    db_path = get_db_path(case_dir)
    logger = get_logger(case_dir)
    try:
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute('SELECT id FROM malware_hits WHERE file=? AND rule_name=? AND signature=? AND engine=?', (file, rule_name, signature, engine))
            if cur.fetchone():
                return False
            cur.execute('''
                INSERT INTO malware_hits (file, rule_name, signature, engine, detected_at)
                VALUES (?, ?, ?, ?, datetime('now'))
            ''', (file, rule_name, signature, engine))
            conn.commit()
        return True
    except Exception as e:
        logger.error(f"add_malware_hit error: file={file}, rule_name={rule_name}, signature={signature}, engine={engine}, error={e}")
        return False

def add_event(case_dir: str, event_type: str, details: str) -> bool:
    """Add an event log record. Deduplicate on (event_type, details, timestamp)."""
    db_path = get_db_path(case_dir)
    logger = get_logger(case_dir)
    try:
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            # Not deduplicating on timestamp, but could deduplicate on (event_type, details) if needed
            cur.execute('''
                INSERT INTO events (event_type, details, timestamp)
                VALUES (?, ?, datetime('now'))
            ''', (event_type, details))
            conn.commit()
        return True
    except Exception as e:
        logger.error(f"add_event error: event_type={event_type}, details={details}, error={e}")
        return False

def get_download_stats(case_dir: str) -> Dict[str, int]:
    """Return counts of downloads by status."""
    db_path = get_db_path(case_dir)
    logger = get_logger(case_dir)
    try:
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute('SELECT status, COUNT(*) FROM downloads GROUP BY status')
            return {row[0]: row[1] for row in cur.fetchall()}
    except Exception as e:
        logger.error(f"get_download_stats error: {e}")
        return {}

def update_analysis_status(case_dir: str, filename: str, status: str) -> bool:
    """Update the analysis status for a file in downloads table by filename."""
    db_path = get_db_path(case_dir)
    logger = get_logger(case_dir)
    try:
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute('''
                UPDATE downloads SET status=?, last_attempt=datetime('now') WHERE filename=?
            ''', (status, filename))
            conn.commit()
        return True
    except Exception as e:
        logger.error(f"update_analysis_status error: filename={filename}, status={status}, error={e}")
        return False

# Helper: get all extracted files

def get_extracted_files(case_dir: str) -> List[Dict[str, Any]]:
    """Return all extracted files for a case."""
    db_path = get_db_path(case_dir)
    logger = get_logger(case_dir)
    try:
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM extracted_files')
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]
    except Exception as e:
        logger.error(f"get_extracted_files error: {e}")
        return []

# Helper: get all PII findings

def get_pii_findings(case_dir: str) -> List[Dict[str, Any]]:
    """Return all PII/PHI/PCI findings for a case."""
    db_path = get_db_path(case_dir)
    logger = get_logger(case_dir)
    try:
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM pii_findings')
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]
    except Exception as e:
        logger.error(f"get_pii_findings error: {e}")
        return []

# Helper: get all malware hits

def get_malware_hits(case_dir: str) -> List[Dict[str, Any]]:
    """Return all malware hits (YARA/ClamAV) for a case."""
    db_path = get_db_path(case_dir)
    logger = get_logger(case_dir)
    try:
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM malware_hits')
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]
    except Exception as e:
        logger.error(f"get_malware_hits error: {e}")
        return []

# Helper: get all events

def get_events(case_dir: str) -> List[Dict[str, Any]]:
    """Return all event log records for a case."""
    db_path = get_db_path(case_dir)
    logger = get_logger(case_dir)
    try:
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM events')
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]
    except Exception as e:
        logger.error(f"get_events error: {e}")
        return [] 