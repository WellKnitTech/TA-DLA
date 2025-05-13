import os
from typing import List, Dict, Any

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

# TODO: Add functions to output HTML and CSV reports 