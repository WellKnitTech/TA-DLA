import os
import csv
from collections import defaultdict, Counter
from typing import List, Dict, Any, Optional
from jinja2 import Environment, FileSystemLoader, select_autoescape, Template
import json

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

def per_file_pii_type_summary(findings_csv: str) -> dict:
    """Return a dict mapping file -> set of PII/PHI/PCI types detected in that file."""
    import csv
    file_types = {}
    with open(findings_csv, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            file = row['file']
            typ = row['type']
            if typ in ('PII', 'PHI', 'PCI'):
                file_types.setdefault(file, set()).add(typ)
    return file_types

def files_with_multiple_pii_types(file_types: dict) -> list:
    """Return a list of files with more than one PII/PHI/PCI type."""
    return [f for f, types in file_types.items() if len(types) > 1]

def generate_html_dashboard(
    output_html: str,
    download_stats: Dict[str, Any],
    pii_stats: Dict[str, int],
    yara_summary: Dict[str, Any],
    clamav_summary: Optional[Dict[str, Any]],
    cross_refs: List[str],
    opsec_reminder: str = None,
    victim_info: Optional[Dict[str, Any]] = None,
    ta_info: Optional[Dict[str, Any]] = None,
    template_path: Optional[str] = None,
    multi_pii_files: Optional[list] = None,
    cert_contacts: Optional[list] = None,
    enrichment_path: Optional[str] = None,
    yara_rules_used: Optional[bool] = None
):
    """
    Generate a summary HTML dashboard for the case using Jinja2.
    Args:
        output_html: Path to write HTML file.
        download_stats: Output of summarize_downloads.
        pii_stats: Output of summarize_pii_phi_pci.
        yara_summary: Output of yara_summary_report.
        clamav_summary: Dict with ClamAV summary (optional).
        cross_refs: List of files flagged by both YARA and PII/PHI/PCI.
        opsec_reminder: String with OpSec reminders.
        victim_info: Dict with victim metadata.
        ta_info: Dict with TA metadata.
        template_path: Optional path to a Jinja2 template file.
        multi_pii_files: Optional list of files with multiple PII/PHI/PCI types.
        cert_contacts: Optional list of CERT contacts.
        enrichment_path: Optional path to enrichment.json.
        yara_rules_used: True if ransomware.live YARA rules were used.
    """
    # Load enrichment if not provided
    if enrichment_path and os.path.exists(enrichment_path):
        with open(enrichment_path, 'r', encoding='utf-8') as f:
            enrichment = json.load(f)
        if not ta_info:
            ta_info = enrichment.get('group')
        if not cert_contacts:
            cert_contacts = enrichment.get('cert_contacts')
        if not victim_info:
            victim_info = enrichment.get('victim')
        if yara_rules_used is None:
            yara_rules_used = bool(enrichment.get('yara_rules') and 'rule ' in enrichment.get('yara_rules'))
    if not opsec_reminder:
        opsec_reminder = (
            "<b>OpSec Reminder:</b> Always use TOR for .onion sites. Never upload case data to public repos. "
            "Review all findings in a secure, air-gapped environment."
        )
    if template_path and os.path.exists(template_path):
        env = Environment(
            loader=FileSystemLoader(os.path.dirname(template_path)),
            autoescape=select_autoescape(['html', 'xml'])
        )
        template = env.get_template(os.path.basename(template_path))
    else:
        # Simple default template
        template = Template('''
        <html>
        <head><title>TA-DLA Case Dashboard</title>
        <style>
        body { font-family: Arial, sans-serif; margin: 2em; }
        h1 { color: #2c3e50; }
        .section { margin-bottom: 2em; }
        .opsec { background: #ffeeba; padding: 1em; border-radius: 5px; margin-bottom: 2em; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ccc; padding: 0.5em; }
        th { background: #f8f9fa; }
        </style>
        </head>
        <body>
        <h1>TA-DLA Case Dashboard</h1>
        <div class="opsec">{{ opsec_reminder|safe }}</div>
        <div class="section">
            <h2>Case Info</h2>
            <ul>
                <li><b>Victim:</b> {{ victim_info.name if victim_info else 'Unknown' }}</li>
                <li><b>Threat Actor:</b> {{ ta_info.name if ta_info else (victim_info.group if victim_info else 'Unknown') }}</li>
                <li><b>Date Listed:</b> {{ victim_info.date if victim_info else 'Unknown' }}</li>
            </ul>
        </div>
        <div class="section">
            <h2>Download Status</h2>
            <ul>
                <li><b>Total files:</b> {{ download_stats.total_count }}</li>
                <li><b>Completed:</b> {{ download_stats.completed_count }}</li>
                <li><b>Failed:</b> {{ download_stats.failed_count }}</li>
                <li><b>Total size:</b> {{ '%.2f' % (download_stats.total_size_bytes / (1024*1024)) }} MB</li>
            </ul>
        </div>
        <div class="section">
            <h2>PII/PHI/PCI Findings</h2>
            <ul>
                <li><b>PII:</b> {{ pii_stats.PII }}</li>
                <li><b>PHI:</b> {{ pii_stats.PHI }}</li>
                <li><b>PCI:</b> {{ pii_stats.PCI }}</li>
            </ul>
        </div>
        <div class="section">
            <h2>High-Risk Files: Multiple PII/PHI/PCI Types</h2>
            {% if multi_pii_files %}
            <ul>
            {% for f in multi_pii_files %}<li>{{ f }}</li>{% endfor %}
            </ul>
            {% else %}
            <p>None.</p>
            {% endif %}
        </div>
        <div class="section">
            <h2>YARA/ClamAV Summary</h2>
            <ul>
                <li><b>YARA Total Hits:</b> {{ yara_summary.total_hits }}</li>
                <li><b>YARA Unique Files Flagged:</b> {{ yara_summary.unique_files_flagged }}</li>
                {% if clamav_summary %}
                <li><b>ClamAV Infected Files:</b> {{ clamav_summary.infected_files }}</li>
                {% endif %}
                {% if yara_rules_used %}
                <li><b>Custom YARA rules from ransomware.live were used for this group.</b></li>
                {% endif %}
            </ul>
            <h3>Top YARA Rules</h3>
            <table><tr><th>Rule</th><th>Count</th></tr>
            {% for rule, count in yara_summary.top_rules %}
            <tr><td>{{ rule }}</td><td>{{ count }}</td></tr>
            {% endfor %}
            </table>
        </div>
        <div class="section">
            <h2>Cross-Referenced Files (Flagged by Both YARA and PII/PHI/PCI)</h2>
            {% if cross_refs %}
            <ul>
            {% for f in cross_refs %}<li>{{ f }}</li>{% endfor %}
            </ul>
            {% else %}
            <p>None.</p>
            {% endif %}
        </div>
        <div class="section">
            <h2>About the Threat Actor</h2>
            <p>{{ ta_info.summary if ta_info else '' }}</p>
        </div>
        <div class="section">
            <h2>National CERT/CSIRT Contacts</h2>
            {% if cert_contacts %}
            <ul>
            {% for cert in cert_contacts %}
                <li><b>{{ cert.team_full or cert.team }}</b> ({{ cert.country }}): <a href="{{ cert.website }}">{{ cert.website }}</a> | {{ cert.email }}</li>
            {% endfor %}
            </ul>
            {% else %}
            <p>No CERT/CSIRT contacts available.</p>
            {% endif %}
        </div>
        </body></html>
        ''')
    html = template.render(
        download_stats=download_stats,
        pii_stats=pii_stats,
        yara_summary=yara_summary,
        clamav_summary=clamav_summary,
        cross_refs=cross_refs,
        opsec_reminder=opsec_reminder,
        victim_info=victim_info,
        ta_info=ta_info,
        multi_pii_files=multi_pii_files or [],
        cert_contacts=cert_contacts,
        yara_rules_used=yara_rules_used,
    )
    with open(output_html, 'w', encoding='utf-8') as f:
        f.write(html)

# TODO: Add functions to output HTML and CSV reports 