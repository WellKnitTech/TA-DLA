import os
import tempfile
import csv
import pytest
from ta_dla.analyzer.reporting import (
    output_sensitive_files_report,
    output_sensitive_directories_report,
    yara_summary_report,
    cross_reference_sensitive_files,
)

def write_csv(path, rows, fieldnames):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

def test_output_sensitive_files_report(tmp_path):
    findings = [
        {'file': 'a.txt', 'type': 'PII', 'pattern': 'EMAIL', 'match': 'a@b.com', 'line': 1, 'context': 'a@b.com'},
        {'file': 'a.txt', 'type': 'PII', 'pattern': 'SSN', 'match': '123-45-6789', 'line': 2, 'context': '123-45-6789'},
        {'file': 'b.txt', 'type': 'PII', 'pattern': 'EMAIL', 'match': 'c@d.com', 'line': 1, 'context': 'c@d.com'},
    ]
    csv_path = tmp_path / 'findings.csv'
    write_csv(csv_path, findings, findings[0].keys())
    report = output_sensitive_files_report(str(csv_path))
    assert any(r['file'] == 'a.txt' and r['count'] == 2 for r in report)
    assert any(r['file'] == 'b.txt' and r['count'] == 1 for r in report)

def test_output_sensitive_directories_report(tmp_path):
    findings = [
        {'file': 'dir1/a.txt', 'type': 'PII', 'pattern': 'EMAIL', 'match': 'a@b.com', 'line': 1, 'context': 'a@b.com'},
        {'file': 'dir1/a.txt', 'type': 'PII', 'pattern': 'SSN', 'match': '123-45-6789', 'line': 2, 'context': '123-45-6789'},
        {'file': 'dir2/b.txt', 'type': 'PII', 'pattern': 'EMAIL', 'match': 'c@d.com', 'line': 1, 'context': 'c@d.com'},
    ]
    csv_path = tmp_path / 'findings.csv'
    write_csv(csv_path, findings, findings[0].keys())
    report = output_sensitive_directories_report(str(csv_path))
    assert any(r['directory'] == 'dir1' and r['count'] == 2 for r in report)
    assert any(r['directory'] == 'dir2' and r['count'] == 1 for r in report)

def test_yara_summary_report(tmp_path):
    findings = [
        {'file': 'a.txt', 'rule': 'malware1', 'tags': 'mal', 'meta': '{}', 'ruleset': 'yararules'},
        {'file': 'a.txt', 'rule': 'malware2', 'tags': 'mal', 'meta': '{}', 'ruleset': 'yararules'},
        {'file': 'b.txt', 'rule': 'malware1', 'tags': 'mal', 'meta': '{}', 'ruleset': 'reversinglabs'},
    ]
    csv_path = tmp_path / 'yara.csv'
    write_csv(csv_path, findings, findings[0].keys())
    summary = yara_summary_report(str(csv_path))
    assert summary['total_hits'] == 3
    assert summary['unique_files_flagged'] == 2
    assert any(r[0] == 'malware1' and r[1] == 2 for r in summary['top_rules'])

def test_cross_reference_sensitive_files(tmp_path):
    yara_findings = [
        {'file': 'a.txt', 'rule': 'malware1', 'tags': 'mal', 'meta': '{}', 'ruleset': 'yararules'},
        {'file': 'b.txt', 'rule': 'malware2', 'tags': 'mal', 'meta': '{}', 'ruleset': 'yararules'},
    ]
    pii_findings = [
        {'file': 'a.txt', 'type': 'PII', 'pattern': 'EMAIL', 'match': 'a@b.com', 'line': 1, 'context': 'a@b.com'},
        {'file': 'c.txt', 'type': 'PII', 'pattern': 'SSN', 'match': '123-45-6789', 'line': 2, 'context': '123-45-6789'},
    ]
    yara_csv = tmp_path / 'yara.csv'
    pii_csv = tmp_path / 'pii.csv'
    write_csv(yara_csv, yara_findings, yara_findings[0].keys())
    write_csv(pii_csv, pii_findings, pii_findings[0].keys())
    both = cross_reference_sensitive_files(str(yara_csv), str(pii_csv))
    assert 'a.txt' in both
    assert 'b.txt' not in both 