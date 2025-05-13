import os
import json
import logging
from typing import Optional
from ftplib import FTP, error_perm
import socket
import socks  # PySocks
from ta_dla.utils import get_case_logger
from ta_dla.case_manager import CaseManager

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
    logger: Optional[logging.Logger] = None
) -> bool:
    """
    Download files from an FTP server over TOR (SOCKS5), always using passive mode.
    Credentials and path are saved to metadata.json for resuming.
    Supports resuming interrupted downloads if a partial file exists.
    """
    if logger is None and case_dir:
        logger = get_case_logger(case_dir)
    if case_dir:
        save_ftp_metadata(case_dir, server, username, password, remote_path)
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