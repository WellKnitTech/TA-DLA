import os
import logging
from typing import Optional
from mega import Mega
from ta_dla.utils import get_case_logger

def is_running_under_torsocks() -> bool:
    """
    Check if the process is running under torsocks/proxychains by checking environment variables.
    """
    return any(
        os.environ.get(var) for var in [
            'TORSOCKS_VERSION', 'PROXYCHAINS_CONF_FILE', 'LD_PRELOAD'
        ]
    )

def download_mega_file(
    url: str,
    output_dir: str,
    case_dir: str = None,
    logger: Optional[logging.Logger] = None,
    require_tor: bool = True,
    opsec_guard=None
) -> bool:
    """
    Download a file from MEGA.nz using mega.py.
    WARNING: For true anonymity, run this process with torsocks or proxychains, or in a network-isolated environment.
    If opsec_guard is provided, it will be called before download. If it returns False, abort.
    Args:
        url: MEGA file URL.
        output_dir: Directory to save the downloaded file.
        case_dir: Path to the case directory (for logger if not provided).
        logger: Logger instance for this case.
        proxy_url: Optional SOCKS5 proxy (not natively supported by mega.py).
        require_tor: If True, abort unless running under torsocks/proxychains. Default: True.
    Returns:
        True if download succeeded, False otherwise.
    """
    if logger is None and case_dir:
        logger = get_case_logger(case_dir)
    if require_tor and not is_running_under_torsocks():
        error = (
            "[ERROR] MEGA downloads require anonymity. "
            "Please run this script with torsocks or proxychains, "
            "or override with require_tor=False if you accept the risk."
        )
        if logger:
            logger.error(error)
        else:
            print(error)
        return False
    if not is_running_under_torsocks():
        warning = (
            "[WARNING] MEGA downloads are not natively proxied. "
            "For anonymity, run this script with torsocks or proxychains, "
            "or use a network-isolated environment."
        )
        if logger:
            logger.warning(warning)
        else:
            print(warning)
    if opsec_guard and not opsec_guard():
        if logger:
            logger.warning('Aborting MEGA download due to OpSec policy.')
        return False
    try:
        mega = Mega()
        # TODO: Add proxy support if mega.py or pycryptodome supports it
        m = mega.login()  # Anonymous login
        logger.info(f"Starting MEGA download: {url}")
        file = m.find(url)
        if not file:
            logger.error(f"File not found or invalid MEGA URL: {url}")
            return False
        filename = file['a'].get('n', 'downloaded_file')
        output_path = os.path.join(output_dir, filename)
        m.download_url(url, dest_path=output_dir)
        logger.info(f"Downloaded MEGA file to {output_path}")
        return True
    except Exception as e:
        if logger:
            logger.error(f"MEGA download failed for {url}: {e}")
        return False 