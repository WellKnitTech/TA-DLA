import os
import yara
import logging
import csv
import requests
import subprocess
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from ta_dla.utils import get_case_logger
from ta_dla.db import inventory

YARA_RULES_REPO = 'https://github.com/Yara-Rules/rules.git'
REVERSINGLABS_RULES_REPO = 'https://github.com/reversinglabs/reversinglabs-yara-rules.git'
YARA_RULES_DIR = 'yara_rules'  # Default local rules directory
REVERSINGLABS_RULES_DIR = 'reversinglabs_yara_rules'

RULESET_MAP = {
    'yararules': (YARA_RULES_REPO, YARA_RULES_DIR),
    'reversinglabs': (REVERSINGLABS_RULES_REPO, REVERSINGLABS_RULES_DIR),
}


def ensure_yara_rules_repo(local_dir: str, logger: Optional[logging.Logger] = None, repo_url: Optional[str] = None):
    """
    Clone or update a YARA rules repository from GitHub.
    Args:
        local_dir: Local directory to clone/update the rules repo.
        repo_url: GitHub repo URL.
    """
    if repo_url is None:
        raise ValueError("repo_url must be specified")
    if os.path.exists(os.path.join(local_dir, '.git')):
        try:
            subprocess.run(['git', '-C', local_dir, 'pull'], check=True)
            if logger:
                logger.info(f"Updated YARA rules repo in {local_dir}")
        except Exception as e:
            if logger:
                logger.error(f"Failed to update YARA rules repo: {e}")
    else:
        try:
            subprocess.run(['git', 'clone', '--depth', '1', repo_url, local_dir], check=True)
            if logger:
                logger.info(f"Cloned YARA rules repo to {local_dir}")
        except Exception as e:
            if logger:
                logger.error(f"Failed to clone YARA rules repo: {e}")


def update_yara_rules(remote_url: str, local_path: str, logger: Optional[logging.Logger] = None):
    """
    Download or update YARA rules from a remote source.
    Args:
        remote_url: URL to download rules from.
        local_path: Local file path to save rules.
    """
    try:
        r = requests.get(remote_url, timeout=30)
        r.raise_for_status()
        with open(local_path, 'wb') as f:
            f.write(r.content)
        if logger:
            logger.info(f"Downloaded YARA rules from {remote_url} to {local_path}")
    except Exception as e:
        if logger:
            logger.error(f"Failed to update YARA rules from {remote_url}: {e}")


def load_yara_rules(rules_path: str, logger: Optional[logging.Logger] = None):
    """
    Compile YARA rules from a file or directory.
    Args:
        rules_path: Path to a .yar file or directory of .yar/.yara files.
    Returns:
        Compiled YARA rules object.
    """
    try:
        if os.path.isdir(rules_path):
            rule_files = [os.path.join(rules_path, f) for f in os.listdir(rules_path) if f.endswith(('.yar', '.yara'))]
            rules = yara.compile(filepaths={os.path.basename(f): f for f in rule_files})
        else:
            rules = yara.compile(filepath=rules_path)
        return rules
    except Exception as e:
        if logger:
            logger.error(f"Failed to compile YARA rules from {rules_path}: {e}")
        return None


def scan_file_with_yara(filepath: str, rules, logger: Optional[logging.Logger] = None, ruleset_name: str = "", case_dir: Optional[str] = None) -> List[Dict]:
    """
    Scan a single file with YARA rules. Returns a list of findings.
    Also records findings in the inventory DB if case_dir is provided.
    """
    findings = []
    try:
        matches = rules.match(filepath)
        for match in matches:
            finding = {
                'file': filepath,
                'rule': match.rule,
                'tags': ','.join(match.tags),
                'meta': str(match.meta),
                'ruleset': ruleset_name,
            }
            findings.append(finding)
            if case_dir:
                inventory.add_malware_hit(case_dir, filepath, match.rule, str(match.meta), f'yara:{ruleset_name}')
    except Exception as e:
        if logger:
            logger.error(f"YARA scan error for {filepath}: {e}")
    return findings


def scan_directory_with_yara(
    directory: str,
    rulesets: Optional[List[str]] = None,
    output_csv: str = 'malware.csv',
    case_dir: Optional[str] = None,
    logger: Optional[logging.Logger] = None,
    max_workers: Optional[int] = None,
    batch_size: int = 32
) -> int:
    """
    Recursively scan all files in a directory with one or more YARA rulesets. Streams findings to a CSV file.
    Also records findings in the inventory DB and updates file status to 'yara-flagged' if any findings are found.
    """
    if logger is None and case_dir:
        logger = get_case_logger(case_dir)
    if rulesets is None:
        rulesets = ['yararules', 'reversinglabs']
    compiled_rules: List[Tuple[str, any]] = []
    for ruleset in rulesets:
        repo_url, local_dir = RULESET_MAP[ruleset]
        ensure_yara_rules_repo(local_dir, logger=logger, repo_url=repo_url)
        rules = load_yara_rules(local_dir, logger=logger)
        if rules:
            compiled_rules.append((ruleset, rules))
        else:
            logger.error(f"Failed to load ruleset: {ruleset}")
    all_files = []
    for root, dirs, files in os.walk(directory):
        for fname in files:
            fpath = os.path.join(root, fname)
            all_files.append(fpath)
    finding_count = 0
    with open(output_csv, 'w', newline='', encoding='utf-8') as csv_file:
        csv_writer = csv.DictWriter(csv_file, fieldnames=['file', 'rule', 'tags', 'meta', 'ruleset'])
        csv_writer.writeheader()
        for i in range(0, len(all_files), batch_size):
            batch = all_files[i:i+batch_size]
            with ThreadPoolExecutor(max_workers=max_workers or min(4, os.cpu_count() or 1)) as executor:
                futures = []
                for fpath in batch:
                    for ruleset_name, rules in compiled_rules:
                        futures.append(executor.submit(scan_file_with_yara, fpath, rules, logger, ruleset_name, case_dir))
                for future in as_completed(futures):
                    findings = future.result()
                    if findings and case_dir:
                        inventory.update_analysis_status(case_dir, findings[0]['file'], 'yara-flagged')
                    for row in findings:
                        csv_writer.writerow(row)
                    finding_count += len(findings)
    logger.info(f"YARA scan complete. {finding_count} findings written to {output_csv}")
    return finding_count

# TODO: CLI integration, rule source config, error handling improvements 