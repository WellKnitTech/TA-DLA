import requests
import time
import tempfile
from ta_dla.downloader.base import DownloaderPlugin
from ta_dla.utils import get_case_logger
from ta_dla.db.inventory import update_download_status

class BitTorrentDownloader(DownloaderPlugin):
    name = "BitTorrentDownloader"
    supported_tas = ["akira"]
    TRIBLER_API = "http://localhost:8085"

    def supports(self, ta, url):
        return url and (url.startswith("magnet:?") or url.endswith(".torrent") or "/t/" in url)

    def download(self, url, dest, logger=None, case_dir=None, **kwargs):
        if logger is None and case_dir:
            logger = get_case_logger(case_dir)
        logger.info(f"BitTorrentDownloader (Tribler) invoked for: {url}")
        logger.warning("Ensure you are running Tribler in anonymous mode for best OpSec. Consider using a VPN or VM for extra safety.")
        if not self._tribler_api_running(logger):
            logger.error("Tribler API is not reachable. Please start Tribler before downloading.")
            update_download_status(case_dir, url, 'failed', error='Tribler API not running')
            return False
        try:
            update_download_status(case_dir, url, 'in-progress')
            if url.startswith("magnet:?"):
                add_url = f"{self.TRIBLER_API}/downloads"
                resp = requests.put(add_url, json={"uri": url})
                if resp.status_code not in (200, 201):
                    logger.error(f"Failed to add magnet to Tribler: {resp.text}")
                    update_download_status(case_dir, url, 'failed', error=resp.text)
                    return False
                download_info = resp.json()
                download_id = download_info.get('id')
                logger.info(f"Magnet link added to Tribler. Download ID: {download_id}")
            else:
                logger.info(f"Downloading .torrent file: {url}")
                with tempfile.NamedTemporaryFile(delete=False, suffix='.torrent') as tf:
                    r = requests.get(url, stream=True)
                    r.raise_for_status()
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            tf.write(chunk)
                    tf.flush()
                    torrent_path = tf.name
                logger.info(f".torrent file saved to: {torrent_path}")
                add_url = f"{self.TRIBLER_API}/downloads"
                files = {'file': open(torrent_path, 'rb')}
                resp = requests.post(add_url, files=files)
                files['file'].close()
                import os
                os.unlink(torrent_path)
                if resp.status_code not in (200, 201):
                    logger.error(f"Failed to add .torrent to Tribler: {resp.text}")
                    update_download_status(case_dir, url, 'failed', error=resp.text)
                    return False
                download_info = resp.json()
                download_id = download_info.get('id')
                logger.info(f".torrent file added to Tribler. Download ID: {download_id}")
            complete = self._wait_for_download(download_id, logger)
            if complete:
                update_download_status(case_dir, url, 'complete')
                logger.info(f"Download complete for: {url}")
                return True
            else:
                update_download_status(case_dir, url, 'failed', error='Download did not complete in time')
                logger.error(f"Download failed or timed out for: {url}")
                return False
        except Exception as e:
            logger.error(f"Exception during Tribler torrent download: {e}")
            update_download_status(case_dir, url, 'failed', error=str(e))
            return False

    def _tribler_api_running(self, logger):
        try:
            resp = requests.get(f"{self.TRIBLER_API}/version", timeout=3)
            return resp.status_code == 200
        except Exception as e:
            logger.error(f"Could not reach Tribler API: {e}")
            return False

    def _wait_for_download(self, download_id, logger, timeout=3600, poll_interval=10):
        if not download_id:
            logger.warning("No download ID returned from Tribler; cannot poll status.")
            return False
        status_url = f"{self.TRIBLER_API}/downloads/{download_id}"
        elapsed = 0
        while elapsed < timeout:
            try:
                resp = requests.get(status_url)
                if resp.status_code == 200:
                    info = resp.json()
                    state = info.get('state', '').lower()
                    logger.info(f"Tribler download state: {state}")
                    if state == 'seeding' or state == 'completed':
                        return True
                else:
                    logger.warning(f"Failed to get download status from Tribler: {resp.text}")
            except Exception as e:
                logger.warning(f"Error polling Tribler API: {e}")
            time.sleep(poll_interval)
            elapsed += poll_interval
        logger.warning("Timeout waiting for Tribler download to complete.")
        return False 