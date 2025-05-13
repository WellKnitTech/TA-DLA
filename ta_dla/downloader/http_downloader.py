import os
import random
import logging
from typing import Optional
import requests
from ta_dla.utils import get_case_logger

USER_AGENTS = [
    # Common, non-identifying user agents
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0',
]

def download_file(
    url: str,
    output_path: str,
    proxy_url: str = 'socks5h://localhost:9050',
    force_proxy: bool = True,
    timeout: int = 60,
    logger: Optional[logging.Logger] = None,
    case_dir: Optional[str] = None
) -> bool:
    """
    Download a file over HTTP/S, optionally routing through a SOCKS5 proxy (TOR).
    Supports resuming if the server supports HTTP Range requests.

    Args:
        url: The file URL to download.
        output_path: Where to save the downloaded file.
        proxy_url: SOCKS5 proxy URL (default: TOR at localhost:9050).
        force_proxy: If True, always use the proxy (recommended for .onion).
        timeout: Timeout in seconds for the request.
        logger: Logger instance for this case.
        case_dir: Path to the case directory (for logger if not provided).
    Returns:
        True if download succeeded, False otherwise.
    """
    if logger is None and case_dir:
        logger = get_case_logger(case_dir)
    headers = {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': '*/*',
        'Connection': 'close',
    }
    proxies = {'http': proxy_url, 'https': proxy_url} if force_proxy or '.onion' in url else None
    resume_byte_pos = 0
    if os.path.exists(output_path):
        resume_byte_pos = os.path.getsize(output_path)
        if resume_byte_pos > 0:
            headers['Range'] = f'bytes={resume_byte_pos}-'
            if logger:
                logger.info(f"Resuming download for {url} at byte {resume_byte_pos}")
    try:
        with requests.get(url, headers=headers, proxies=proxies, timeout=timeout, stream=True) as response:
            if response.status_code == 416:
                if logger:
                    logger.info(f"File already fully downloaded: {output_path}")
                return True
            response.raise_for_status()
            mode = 'ab' if 'Range' in headers else 'wb'
            try:
                with open(output_path, mode) as file:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            file.write(chunk)
            except OSError as file_err:
                if logger:
                    logger.error(f"File write error for {output_path}: {file_err}")
                return False
        if logger:
            logger.info(f"Download completed: {url} -> {output_path}")
        return True
    except requests.exceptions.RequestException as req_err:
        if logger:
            logger.error(f"HTTP request error for {url}: {req_err}")
        return False
    except Exception as e:
        if logger:
            logger.error(f"Unexpected error for {url}: {e}")
        return False 