"""
SQLite inventory tracking for TA-DLA.
Tracks downloads, extraction, analysis, and events per case.
"""
import os
import sqlite3
from typing import Optional, List, Dict, Any

SCHEMA = {
    'downloads': '''
        CREATE TABLE IF NOT EXISTS downloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            filename TEXT,
            status TEXT,            -- pending, complete, failed
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

def add_download(case_dir: str, url: str, filename: str, status: str = 'pending', sha1: Optional[str] = None, size: Optional[int] = None, error: Optional[str] = None):
    """Add a new download record."""
    db_path = get_db_path(case_dir)
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO downloads (url, filename, status, sha1, size, last_attempt, error)
            VALUES (?, ?, ?, ?, ?, datetime('now'), ?)
        ''', (url, filename, status, sha1, size, error))
        conn.commit()

def update_download_status(case_dir: str, url: str, status: str, sha1: Optional[str] = None, size: Optional[int] = None, error: Optional[str] = None):
    """Update the status, sha1, size, or error for a download by URL."""
    db_path = get_db_path(case_dir)
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute('''
            UPDATE downloads SET status=?, sha1=?, size=?, last_attempt=datetime('now'), error=? WHERE url=?
        ''', (status, sha1, size, error, url))
        conn.commit()

def get_downloads_by_status(case_dir: str, status: str) -> List[Dict[str, Any]]:
    """Return all downloads with a given status (pending, failed, complete)."""
    db_path = get_db_path(case_dir)
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute('SELECT * FROM downloads WHERE status=?', (status,))
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

def get_failed_downloads(case_dir: str) -> List[Dict[str, Any]]:
    """Return all failed downloads."""
    return get_downloads_by_status(case_dir, 'failed')

def get_pending_downloads(case_dir: str) -> List[Dict[str, Any]]:
    """Return all pending downloads."""
    return get_downloads_by_status(case_dir, 'pending')

def add_extracted_file(case_dir: str, path: str, parent_archive: Optional[str], depth: int):
    """Add a record for an extracted file."""
    db_path = get_db_path(case_dir)
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO extracted_files (path, parent_archive, depth, extracted_at)
            VALUES (?, ?, ?, datetime('now'))
        ''', (path, parent_archive, depth))
        conn.commit()

def add_pii_finding(case_dir: str, file: str, pattern_type: str, match: str, line: int, context: str):
    """Add a PII/PHI/PCI finding record."""
    db_path = get_db_path(case_dir)
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO pii_findings (file, pattern_type, match, line, context, detected_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
        ''', (file, pattern_type, match, line, context))
        conn.commit()

def add_malware_hit(case_dir: str, file: str, rule_name: str, signature: str, engine: str):
    """Add a malware hit record (YARA or ClamAV)."""
    db_path = get_db_path(case_dir)
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO malware_hits (file, rule_name, signature, engine, detected_at)
            VALUES (?, ?, ?, ?, datetime('now'))
        ''', (file, rule_name, signature, engine))
        conn.commit()

def add_event(case_dir: str, event_type: str, details: str):
    """Add an event log record."""
    db_path = get_db_path(case_dir)
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO events (event_type, details, timestamp)
            VALUES (?, ?, datetime('now'))
        ''', (event_type, details))
        conn.commit()

def get_download_stats(case_dir: str) -> Dict[str, int]:
    """Return counts of downloads by status."""
    db_path = get_db_path(case_dir)
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute('SELECT status, COUNT(*) FROM downloads GROUP BY status')
        return {row[0]: row[1] for row in cur.fetchall()} 