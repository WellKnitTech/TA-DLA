import os
import re
import logging
import csv
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from ta_dla.utils import get_case_logger
from ta_dla.db import inventory

# Example regexes for PII/PHI/PCI (expand as needed)
PII_PATTERNS = {
    'EMAIL': re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'),
    'SSN': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    'PHONE': re.compile(r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b'),
    'PASSPORT': re.compile(r'\b[\dA-Z]{5,9}\b'),
    'DRIVERS_LICENSE': re.compile(r'\b[A-Z]{1,2}\d{6,8}\b'),
    'IBAN': re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b'),
}
PHI_PATTERNS = {
    'ICD10': re.compile(r'\b[A-TV-Z][0-9][A-Z0-9]{2,6}\b'),  # Simplified
    'NPI': re.compile(r'\b\d{10}\b'),
    'MRN': re.compile(r'\b\d{6,10}\b'),
}
PCI_PATTERNS = {
    'CREDIT_CARD': re.compile(r'\b(?:\d[ -]*?){13,16}\b'),
    'AMEX': re.compile(r'\b3[47][0-9]{13}\b'),
    'VISA': re.compile(r'\b4[0-9]{12}(?:[0-9]{3})?\b'),
    'MASTERCARD': re.compile(r'\b5[1-5][0-9]{14}\b'),
    'DISCOVER': re.compile(r'\b6(?:011|5[0-9]{2})[0-9]{12}\b'),
}

ALL_PATTERNS = {
    'PII': PII_PATTERNS,
    'PHI': PHI_PATTERNS,
    'PCI': PCI_PATTERNS,
}

def is_text_file(filepath: str) -> bool:
    try:
        with open(filepath, 'rb') as f:
            chunk = f.read(1024)
            if b'\0' in chunk:
                return False
        return True
    except Exception:
        return False

def find_high_entropy_strings(text, threshold=4.0, min_length=20):
    import math
    results = []
    for word in text.split():
        if len(word) < min_length:
            continue
        entropy = 0
        prob = [float(word.count(c)) / len(word) for c in set(word)]
        entropy = -sum([p * math.log2(p) for p in prob])
        if entropy >= threshold:
            results.append((word, entropy))
    return results

def scan_file_for_patterns(filepath: str, logger: Optional[logging.Logger] = None, case_dir: Optional[str] = None) -> List[Dict]:
    """
    Scan a single file for PII/PHI/PCI patterns. Returns a list of findings.
    Also records findings in the inventory DB if case_dir is provided.
    """
    findings = []
    if not is_text_file(filepath):
        if logger:
            logger.info(f"Skipping binary file: {filepath}")
        return findings
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for lineno, line in enumerate(f, 1):
                for category, patterns in ALL_PATTERNS.items():
                    for ptype, regex in patterns.items():
                        for match in regex.finditer(line):
                            finding = {
                                'file': filepath,
                                'type': category,
                                'pattern': ptype,
                                'match': match.group(),
                                'line': lineno,
                                'context': line.strip(),
                            }
                            findings.append(finding)
                            if case_dir:
                                inventory.add_pii_finding(case_dir, filepath, ptype, match.group(), lineno, line.strip())
                # Entropy-based detection
                for word, entropy in find_high_entropy_strings(line):
                    finding = {
                        'file': filepath,
                        'type': 'ENTROPY',
                        'pattern': f'entropy>={entropy:.2f}',
                        'match': word,
                        'line': lineno,
                        'context': line.strip(),
                    }
                    findings.append(finding)
                    if case_dir:
                        inventory.add_pii_finding(case_dir, filepath, 'ENTROPY', word, lineno, line.strip())
    except Exception as e:
        if logger:
            logger.error(f"Error scanning {filepath}: {e}")
    return findings

def scan_directory_for_pii_phi_pci(
    directory: str,
    case_dir: Optional[str] = None,
    logger: Optional[logging.Logger] = None,
    max_workers: Optional[int] = None,
    batch_size: int = 32,
    csv_output_path: Optional[str] = None
) -> int:
    """
    Recursively scan all files in a directory for PII/PHI/PCI patterns in parallel, in batches to reduce disk IO.
    Streams findings to a CSV file if csv_output_path is provided. Returns the total finding count.
    Also records findings in the inventory DB and updates file status to 'pii-detected' if any findings are found.
    """
    if logger is None and case_dir:
        logger = get_case_logger(case_dir)
    if max_workers is None:
        max_workers = min(4, os.cpu_count() or 1)
    all_files = []
    for root, dirs, files in os.walk(directory):
        for fname in files:
            fpath = os.path.join(root, fname)
            all_files.append(fpath)
    finding_count = 0
    csv_file = None
    csv_writer = None
    if csv_output_path:
        csv_file = open(csv_output_path, 'w', newline='', encoding='utf-8')
        csv_writer = csv.DictWriter(csv_file, fieldnames=['file', 'type', 'pattern', 'match', 'line', 'context'])
        csv_writer.writeheader()
    # Process files in batches to reduce disk IO pressure
    for i in range(0, len(all_files), batch_size):
        batch = all_files[i:i+batch_size]
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {executor.submit(scan_file_for_patterns, fpath, logger, case_dir): fpath for fpath in batch}
            for future in as_completed(future_to_file):
                findings = future.result()
                if findings and case_dir:
                    # Update status for this file
                    inventory.update_analysis_status(case_dir, future_to_file[future], 'pii-detected')
                if csv_writer:
                    for row in findings:
                        csv_writer.writerow(row)
                finding_count += len(findings)
    if csv_file:
        csv_file.close()
    logger.info(f"PII/PHI/PCI scan complete. {finding_count} findings.")
    return finding_count

# TODO: Add entropy-based detection, more regexes 