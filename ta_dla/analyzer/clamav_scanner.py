"""
ClamAV scanner integration for TA-DLA.
- Requires python-clamd (https://pypi.org/project/clamd/) and a running clamd daemon.
- Scans files for malware using ClamAV, outputs results to CSV.
- Handles missing dependencies gracefully and provides install instructions.
"""
import os
import csv
import logging
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from ta_dla.utils import get_case_logger
from ta_dla.db import inventory

try:
    import clamd
    CLAMD_AVAILABLE = True
except ImportError:
    CLAMD_AVAILABLE = False

INSTALL_INSTRUCTIONS = """
ClamAV scanning requires both the ClamAV daemon and the python-clamd package.

To install ClamAV and python-clamd on Ubuntu/Debian:
    sudo apt-get install clamav-daemon clamav-freshclam
    sudo freshclam
    sudo systemctl start clamav-daemon
    pip install clamd

On Arch/Manjaro:
    sudo pacman -S clamav clamav-daemon
    sudo freshclam
    sudo systemctl start clamav-daemon
    pip install clamd

See https://pypi.org/project/clamd/ and https://docs.clamav.net/ for more info.
"""

def print_clamav_install_instructions():
    print(INSTALL_INSTRUCTIONS)

def get_clamd_client(logger=None):
    if not CLAMD_AVAILABLE:
        if logger:
            logger.warning("python-clamd is not installed. ClamAV scanning is unavailable.")
        return None
    # Try Unix socket first, then network socket
    try:
        cd = clamd.ClamdUnixSocket()
        cd.ping()
        return cd
    except Exception as e:
        if logger:
            logger.warning(f"ClamdUnixSocket failed: {e}. Trying network socket...")
        try:
            cd = clamd.ClamdNetworkSocket()
            cd.ping()
            return cd
        except Exception as e2:
            if logger:
                logger.error(f"ClamAV daemon not available: {e2}")
            return None

def scan_file_with_clamav(filepath: str, cd, logger: Optional[logging.Logger] = None, case_dir: Optional[str] = None) -> Dict:
    result = {
        'file': filepath,
        'status': 'ERROR',
        'signature': '',
        'engine_version': '',
        'scan_method': '',
    }
    if cd is None:
        result['status'] = 'NO_CLAMD'
        return result
    try:
        scan_result = cd.scan(filepath)
        version = cd.version() if hasattr(cd, 'version') else ''
        if scan_result is None:
            result['status'] = 'CLEAN'
            result['scan_method'] = 'clamd'
            result['engine_version'] = version
        else:
            for f, (status, sig) in scan_result.items():
                result['status'] = status
                result['signature'] = sig if status == 'FOUND' else ''
                result['scan_method'] = 'clamd'
                result['engine_version'] = version
                if status == 'FOUND' and case_dir:
                    inventory.add_malware_hit(case_dir, filepath, sig, sig, 'clamav')
                    inventory.update_analysis_status(case_dir, filepath, 'clamav-flagged')
        if logger:
            logger.info(f"ClamAV scan: {filepath} -> {result['status']} {result['signature']}")
    except Exception as e:
        if logger:
            logger.error(f"ClamAV scan error for {filepath}: {e}")
        result['status'] = 'ERROR'
        result['signature'] = str(e)
    return result

def scan_directory_with_clamav(
    directory: str,
    output_csv: str = 'clamav.csv',
    case_dir: Optional[str] = None,
    logger: Optional[logging.Logger] = None,
    max_workers: Optional[int] = None,
    batch_size: int = 32
) -> int:
    """
    Recursively scan all files in a directory with ClamAV. Streams findings to a CSV file.
    Also records findings in the inventory DB and updates file status to 'clamav-flagged' if any findings are found.
    Args:
        directory: Directory to scan.
        output_csv: Path to CSV file for findings.
        case_dir: Path to the case directory (for logger if not provided).
        logger: Logger instance for this case.
        max_workers: Number of parallel workers.
        batch_size: Number of files to process per batch.
    Returns:
        Total number of findings (files flagged as FOUND).
    """
    if logger is None and case_dir:
        logger = get_case_logger(case_dir)
    if not CLAMD_AVAILABLE:
        if logger:
            logger.warning("python-clamd is not installed. Skipping ClamAV scan.")
        print_clamav_install_instructions()
        return 0
    cd = get_clamd_client(logger)
    if cd is None:
        if logger:
            logger.error("ClamAV daemon is not available. Skipping ClamAV scan.")
        print_clamav_install_instructions()
        return 0
    all_files = []
    for root, dirs, files in os.walk(directory):
        for fname in files:
            fpath = os.path.join(root, fname)
            all_files.append(fpath)
    finding_count = 0
    with open(output_csv, 'w', newline='', encoding='utf-8') as csv_file:
        csv_writer = csv.DictWriter(csv_file, fieldnames=['file', 'status', 'signature', 'engine_version', 'scan_method'])
        csv_writer.writeheader()
        for i in range(0, len(all_files), batch_size):
            batch = all_files[i:i+batch_size]
            with ThreadPoolExecutor(max_workers=max_workers or min(4, os.cpu_count() or 1)) as executor:
                futures = [executor.submit(scan_file_with_clamav, fpath, cd, logger, case_dir) for fpath in batch]
                for future in as_completed(futures):
                    result = future.result()
                    csv_writer.writerow(result)
                    if result['status'] == 'FOUND':
                        finding_count += 1
    if logger:
        logger.info(f"ClamAV scan complete. {finding_count} infected files written to {output_csv}")
    return finding_count 