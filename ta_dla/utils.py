"""Shared utility functions for TA-DLA."""
# TODO: Implement logging, config helpers, etc. 

import logging
import os
import requests
from datetime import datetime, timedelta

def get_case_logger(case_dir, log_name='downloader.log'):
    """
    Returns a logger that writes to the case's logs directory and also outputs to the console.
    Args:
        case_dir (str): Path to the case directory.
        log_name (str): Log file name (default: downloader.log).
    Returns:
        logging.Logger: Configured logger instance.
    """
    logs_dir = os.path.join(case_dir, 'logs')
    os.makedirs(logs_dir, exist_ok=True)
    log_path = os.path.join(logs_dir, log_name)
    logger_name = f'ta_dla.{os.path.basename(case_dir)}.{log_name}'
    logger = logging.getLogger(logger_name)
    if not logger.handlers:
        # File handler
        file_handler = logging.FileHandler(log_path)
        file_formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        # Console handler
        stream_handler = logging.StreamHandler()
        stream_formatter = logging.Formatter('%(levelname)s %(message)s')
        stream_handler.setFormatter(stream_formatter)
        logger.addHandler(stream_handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    # TODO: Add log rotation if needed
    return logger 

def get_active_ransomware_groups_last_6_months():
    """
    Fetch all ransomware groups (TAs) active in the last 6 months using ransomware.live API.
    Returns a sorted list of unique group names.
    """
    BASE_URL = "https://api.ransomware.live/v2"
    now = datetime.utcnow()
    months = [(now.year, now.month)]
    for i in range(1, 6):
        prev = now - timedelta(days=30*i)
        months.append((prev.year, prev.month))
    active_groups = set()
    for year, month in months:
        url = f"{BASE_URL}/victims/{year}/{month:02d}"
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                victims = resp.json()
                for victim in victims:
                    group = victim.get("group_name")
                    if group:
                        active_groups.add(group)
            else:
                print(f"[WARN] Failed to fetch {year}-{month:02d}: HTTP {resp.status_code}")
        except Exception as e:
            print(f"[ERROR] Exception fetching {year}-{month:02d}: {e}")
    return sorted(active_groups) 