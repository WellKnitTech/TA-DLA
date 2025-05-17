import os
import csv
from collections import defaultdict, Counter
from typing import List, Dict, Any, Optional

def summarize_downloads(downloads: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Summarize total download count and total size.
    Args:
        downloads: List of dicts with keys 'filename', 'size', 'status', etc.
    Returns:
        Dict with total_count, total_size_bytes, completed_count, failed_count.
    """
    total_count = len(downloads)
    total_size = sum(d.get('size', 0) for d in downloads if d.get('status') == 'complete')
    completed_count = sum(1 for d in downloads if d.get('status') == 'complete')
    failed_count = sum(1 for d in downloads if d.get('status') == 'failed')
    return {
        'total_count': total_count,
        'total_size_bytes': total_size,
        'completed_count': completed_count,
        'failed_count': failed_count,
    }

def summarize_pii_phi_pci(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Summarize PII/PHI/PCI findings from regex/entropy scans.
    Args:
        findings: List of dicts with keys 'type' (PII/PHI/PCI), 'count', etc.
    Returns:
        Dict with total counts per type.
    """
    summary = {'PII': 0, 'PHI': 0, 'PCI': 0}
    for f in findings:
        t = f.get('type')
        if t in summary:
            summary[t] += f.get('count', 1)
    return summary

def generate_counsel_summary(download_stats: Dict[str, Any], pii_stats: Dict[str, int], victim_info: Dict[str, Any], ta_info: Dict[str, Any]) -> str:
    """
    Generate a plain-language summary for Counsel.
    Args:
        download_stats: Output of summarize_downloads.
        pii_stats: Output of summarize_pii_phi_pci.
        victim_info: Dict with victim name, group, date, etc.
        ta_info: Dict with TA profile/summary.
    Returns:
        Plain text summary string.
    """
    lines = []
    lines.append(f"Victim: {victim_info.get('name', 'Unknown')}")
    lines.append(f"Threat Actor: {victim_info.get('group', 'Unknown')}")
    lines.append(f"Date Listed: {victim_info.get('date', 'Unknown')}")
    lines.append("")
    lines.append(f"Total files downloaded: {download_stats['completed_count']} (of {download_stats['total_count']})")
    lines.append(f"Total data size: {download_stats['total_size_bytes'] / (1024*1024):.2f} MB")
    lines.append(f"Failed downloads: {download_stats['failed_count']}")
    lines.append("")
    lines.append(f"PII findings: {pii_stats.get('PII', 0)}")
    lines.append(f"PHI findings: {pii_stats.get('PHI', 0)}")
    lines.append(f"PCI findings: {pii_stats.get('PCI', 0)}")
    lines.append("")
    lines.append(f"About {ta_info.get('name', 'the threat actor')}: {ta_info.get('summary', '')}")
    return '\n'.join(lines)

def output_sensitive_files_report(findings_csv: str, output_csv: Optional[str] = None) -> List[Dict]:
    """
    Generate a report of all files containing suspected sensitive information.
    Args:
        findings_csv: Path to the CSV file with findings (from scanner).
        output_csv: Optional path to write the report as CSV.
    Returns:
        List of dicts: [{'file': ..., 'count': ...}]
    """
    file_counts = defaultdict(int)
    with open(findings_csv, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            file_counts[row['file']] += 1
    report = [{'file': f, 'count': c} for f, c in file_counts.items()]
    report.sort(key=lambda x: x['count'], reverse=True)
    if output_csv:
        with open(output_csv, 'w', newline='', encoding='utf-8') as out:
            writer = csv.DictWriter(out, fieldnames=['file', 'count'])
            writer.writeheader()
            writer.writerows(report)
    return report

def output_sensitive_directories_report(findings_csv: str, output_csv: Optional[str] = None) -> List[Dict]:
    """
    Generate a report of directories likely to contain the most sensitive values.
    Args:
        findings_csv: Path to the CSV file with findings (from scanner).
        output_csv: Optional path to write the report as CSV.
    Returns:
        List of dicts: [{'directory': ..., 'count': ...}]
    """
    dir_counts = defaultdict(int)
    with open(findings_csv, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            directory = os.path.dirname(row['file'])
            dir_counts[directory] += 1
    report = [{'directory': d, 'count': c} for d, c in dir_counts.items()]
    report.sort(key=lambda x: x['count'], reverse=True)
    if output_csv:
        with open(output_csv, 'w', newline='', encoding='utf-8') as out:
            writer = csv.DictWriter(out, fieldnames=['directory', 'count'])
            writer.writeheader()
            writer.writerows(report)
    return report

def yara_summary_report(yara_csv: str, output_csv: Optional[str] = None) -> Dict:
    """
    Summarize YARA scan results: top rules, top directories, file type breakdown, unique files flagged.
    Args:
        yara_csv: Path to YARA findings CSV.
        output_csv: Optional path to write summary as CSV.
    Returns:
        Dict with summary statistics and top lists.
    """
    rule_counts = Counter()
    dir_counts = Counter()
    type_counts = Counter()
    unique_files = set()
    with open(yara_csv, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            rule_counts[row['rule']] += 1
            dir_counts[os.path.dirname(row['file'])] += 1
            ext = os.path.splitext(row['file'])[1].lower()
            type_counts[ext] += 1
            unique_files.add(row['file'])
    summary = {
        'total_hits': sum(rule_counts.values()),
        'unique_files_flagged': len(unique_files),
        'top_rules': rule_counts.most_common(10),
        'top_directories': dir_counts.most_common(10),
        'file_type_breakdown': type_counts.most_common(10),
    }
    if output_csv:
        with open(output_csv, 'w', newline='', encoding='utf-8') as out:
            writer = csv.writer(out)
            writer.writerow(['Metric', 'Value'])
            writer.writerow(['Total Hits', summary['total_hits']])
            writer.writerow(['Unique Files Flagged', summary['unique_files_flagged']])
            writer.writerow([])
            writer.writerow(['Top Rules', 'Count'])
            for rule, count in summary['top_rules']:
                writer.writerow([rule, count])
            writer.writerow([])
            writer.writerow(['Top Directories', 'Count'])
            for d, count in summary['top_directories']:
                writer.writerow([d, count])
            writer.writerow([])
            writer.writerow(['File Type', 'Count'])
            for ext, count in summary['file_type_breakdown']:
                writer.writerow([ext, count])
    return summary

def cross_reference_sensitive_files(yara_csv: str, pii_csv: str, output_csv: Optional[str] = None) -> List[str]:
    """
    Output files flagged by both YARA and PII/PHI/PCI scans.
    Args:
        yara_csv: Path to YARA findings CSV.
        pii_csv: Path to PII/PHI/PCI findings CSV.
        output_csv: Optional path to write the list as CSV.
    Returns:
        List of file paths flagged by both.
    """
    yara_files = set()
    pii_files = set()
    with open(yara_csv, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            yara_files.add(row['file'])
    with open(pii_csv, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            pii_files.add(row['file'])
    both = sorted(yara_files & pii_files)
    if output_csv:
        with open(output_csv, 'w', newline='', encoding='utf-8') as out:
            writer = csv.writer(out)
            writer.writerow(['file'])
            for f in both:
                writer.writerow([f])
    return both

# Stub for future HTML reporting with jinja2
def yara_html_report(summary: Dict, output_html: str):
    """
    Generate an HTML report for YARA scan summary (stub).
    Args:
        summary: Output of yara_summary_report.
        output_html: Path to write HTML file.
    """
    # TODO: Implement with jinja2 templates
    pass

# TODO: Add functions to output HTML and CSV reports 