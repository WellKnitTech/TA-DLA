import os
import json
import logging
from typing import Optional
from ftplib import FTP, error_perm
import socket
import socks  # PySocks
from ta_dla.utils import get_case_logger
from ta_dla.case_manager import CaseManager
from ta_dla.downloader.base import DownloaderPlugin
from urllib.parse import urlparse, unquote

def save_ftp_metadata(case_dir: str, server: str, username: str, password: str, remote_path: str):
    """
    Save FTP credentials and path to metadata.json in the case directory.
    """
    cm = CaseManager(case_dir)
    metadata = cm.load_metadata()
    metadata['ftp'] = {
        'server': server,
        'username': username,
        'password': password,
        'remote_path': remote_path
    }
    cm.save_metadata(metadata)

def download_ftp_files(
    server: str,
    username: str,
    password: str,
    remote_path: str,
    output_dir: str,
    case_dir: Optional[str] = None,
    proxy_host: str = 'localhost',
    proxy_port: int = 9050,
    logger: Optional[logging.Logger] = None,
    opsec_guard=None
) -> bool:
    """
    Download files from an FTP server over TOR (SOCKS5), always using passive mode.
    Credentials and path are saved to metadata.json for resuming.
    Supports resuming interrupted downloads if a partial file exists.
    If opsec_guard is provided, it will be called before download. If it returns False, abort.
    """
    if logger is None and case_dir:
        logger = get_case_logger(case_dir)
    if case_dir:
        save_ftp_metadata(case_dir, server, username, password, remote_path)
    if opsec_guard and not opsec_guard():
        if logger:
            logger.warning('Aborting FTP download due to OpSec policy.')
        return False
    # Patch socket to use SOCKS5 proxy
    socks.set_default_proxy(socks.SOCKS5, proxy_host, proxy_port)
    socket.socket = socks.socksocket
    try:
        with FTP() as ftp:
            ftp.connect(server, 21, timeout=30)
            ftp.login(username, password)
            ftp.set_pasv(True)
            logger.info(f"Connected to FTP {server} as {username}, passive mode enabled.")
            # TODO: Implement recursive download of all files in remote_path
            # Resumable download for a single file
            local_filename = os.path.join(output_dir, os.path.basename(remote_path))
            remote_size = ftp.size(remote_path)
            resume_pos = 0
            if os.path.exists(local_filename):
                local_size = os.path.getsize(local_filename)
                if local_size < remote_size:
                    resume_pos = local_size
                    logger.info(f"Resuming download for {remote_path} at byte {resume_pos}")
                elif local_size == remote_size:
                    logger.info(f"File already fully downloaded: {local_filename}")
                    return True
            mode = 'ab' if resume_pos > 0 else 'wb'
            with open(local_filename, mode) as f:
                def write_chunk(chunk):
                    f.write(chunk)
                if resume_pos > 0:
                    ftp.sendcmd(f'REST {resume_pos}')
                ftp.retrbinary(f'RETR {remote_path}', write_chunk, rest=resume_pos)
            logger.info(f"Downloaded {remote_path} to {local_filename}")
        return True
    except error_perm as e:
        if logger:
            logger.error(f"FTP permission error: {e}")
        return False
    except Exception as e:
        if logger:
            logger.error(f"FTP download failed: {e}")
        return False

class FTPDownloader(DownloaderPlugin):
    name = "FTPDownloader"
    supported_tas = []  # Generic: supports all TAs

    def supports(self, ta, url):
        return url.startswith("ftp://")

    def download(self, url, dest, logger=None, case_dir=None, proxy_host='localhost', proxy_port=9050, opsec_guard=None, **kwargs):
        """
        Download recursively from the given FTP URL (with credentials and path).
        """
        if logger is None and case_dir:
            logger = get_case_logger(case_dir)
        parsed = urlparse(url)
        if not (parsed.scheme == 'ftp' and parsed.hostname and parsed.username and parsed.password):
            if logger:
                logger.error(f"Invalid FTP URL: {url}")
            return False
        server = parsed.hostname
        username = unquote(parsed.username)
        password = unquote(parsed.password)
        remote_path = unquote(parsed.path or '/')
        # Patch socket to use SOCKS5 proxy
        socks.set_default_proxy(socks.SOCKS5, proxy_host, proxy_port)
        socket.socket = socks.socksocket
        try:
            with FTP() as ftp:
                ftp.connect(server, 21, timeout=30)
                ftp.login(username, password)
                ftp.set_pasv(True)
                logger.info(f"Connected to FTP {server} as {username}, passive mode enabled.")
                self._download_recursive(ftp, remote_path, dest, logger)
            return True
        except error_perm as e:
            if logger:
                logger.error(f"FTP permission error: {e}")
            return False
        except Exception as e:
            if logger:
                logger.error(f"FTP download failed: {e}")
            return False

    def _download_recursive(self, ftp, remote_path, local_path, logger):
        """
        Recursively download files and directories from remote_path to local_path.
        """
        try:
            # Try to change to the directory; if fails, treat as file
            ftp.cwd(remote_path)
            if not os.path.exists(local_path):
                os.makedirs(local_path, exist_ok=True)
            items = ftp.nlst()
            for item in items:
                if item in ('.', '..'):
                    continue
                try:
                    ftp.cwd(item)
                    # It's a directory
                    ftp.cwd('..')  # Go back up
                    self._download_recursive(ftp, os.path.join(remote_path, item), os.path.join(local_path, item), logger)
                except error_perm:
                    # It's a file
                    local_file = os.path.join(local_path, item)
                    with open(local_file, 'wb') as f:
                        logger.info(f"Downloading file: {os.path.join(remote_path, item)} -> {local_file}")
                        ftp.retrbinary(f'RETR {os.path.join(remote_path, item)}', f.write)
        except error_perm:
            # Not a directory, treat as file
            if not os.path.exists(os.path.dirname(local_path)):
                os.makedirs(os.path.dirname(local_path), exist_ok=True)
            with open(local_path, 'wb') as f:
                logger.info(f"Downloading file: {remote_path} -> {local_path}")
                ftp.retrbinary(f'RETR {remote_path}', f.write) 