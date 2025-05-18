from ta_dla.downloader.base import DownloaderPlugin
from ta_dla.utils import get_case_logger
from ta_dla.case_manager import CaseManager
import logging
import re
from urllib.parse import urlparse, unquote
import os
import requests
from ta_dla.db.inventory import get_pending_downloads, update_download_status

class DragonforceDownloader(DownloaderPlugin):
    name = "DragonforceDownloader"
    supported_tas = ["dragonforce"]

    def supports(self, ta, url):
        # Support URLs that look like the Dragonforce iframe
        return (
            (ta and ta.lower() == "dragonforce") or
            (url and re.search(r'dragonforce.*iframe', url, re.IGNORECASE)) or
            (url and re.search(r'token=.+', url))
        )

    def download(self, url, dest, logger=None, case_dir=None, **kwargs):
        if logger is None and case_dir:
            logger = get_case_logger(case_dir)
        logger.info(f"DragonforceDownloader invoked for URL: {url}")
        # Load token and path from case metadata
        token = None
        path = None
        if case_dir:
            cm = CaseManager(case_dir)
            metadata = cm.load_metadata()
            dragonforce_meta = metadata.get('dragonforce', {})
            token = dragonforce_meta.get('token')
            path = dragonforce_meta.get('path')
        logger.info(f"Token: {token}")
        logger.info(f"Path: {path}")
        logger.info(f"Destination: {dest}")
        # Download all pending files from inventory
        session = requests.Session()
        session.proxies = {
            "http": "socks5h://127.0.0.1:9050",
            "https": "socks5h://127.0.0.1:9050",
        }
        pending = get_pending_downloads(case_dir)
        if not pending:
            logger.info("No pending Dragonforce downloads found in inventory.")
            return True
        os.makedirs(dest, exist_ok=True)
        for entry in pending:
            file_url = entry['url']
            filename = unquote(entry['filename'])
            local_path = os.path.join(dest, filename)
            try:
                logger.info(f"Downloading {file_url} -> {local_path}")
                update_download_status(case_dir, file_url, 'in-progress')
                resp = session.get(file_url, timeout=120, stream=True)
                resp.raise_for_status()
                with open(local_path, 'wb') as f:
                    for chunk in resp.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                update_download_status(case_dir, file_url, 'complete', size=os.path.getsize(local_path))
                logger.info(f"Downloaded {file_url} -> {local_path}")
            except Exception as e:
                logger.error(f"Failed to download {file_url}: {e}")
                update_download_status(case_dir, file_url, 'failed', error=str(e))
        logger.info("Dragonforce download process complete.")
        return True 