from ta_dla.scraper.base import ScraperPlugin
from ta_dla.utils import get_case_logger
from ta_dla.db.inventory import init_inventory_db, add_download
from ta_dla.case_manager import CaseManager
from bs4 import BeautifulSoup
import requests
import re
import os
from urllib.parse import urljoin, unquote

class DragonforceScraper(ScraperPlugin):
    name = "DragonforceScraper"
    supported_tas = ["dragonforce"]

    def supports(self, ta: str) -> bool:
        return ta.lower() == "dragonforce"

    def enumerate_files(self, base_url, path, token, session, logger, case_dir, files=None):
        if files is None:
            files = []
        url = f"{base_url}/?path={path}&token={token}"
        try:
            resp = session.get(url, timeout=60)
            resp.raise_for_status()
        except Exception as e:
            logger.error(f"Failed to fetch directory listing from {url}: {e}")
            return files
        soup = BeautifulSoup(resp.text, "html.parser")
        for a in soup.select('.item .name a'):
            href = a.get('href')
            name = a.text.strip()
            classes = a.get('class', [])
            if 'dir' in classes:
                # Directory: recurse
                new_path = href.split('path=')[1].split('&')[0]
                self.enumerate_files(base_url, new_path, token, session, logger, case_dir, files)
            elif href and href.startswith('/download?path='):
                file_url = urljoin(base_url, href)
                filename = unquote(name)
                logger.info(f"Discovered file: {file_url} -> {filename}")
                result = add_download(case_dir, file_url, filename, status='pending')
                if not result:
                    logger.warning(f'Failed to add download to inventory DB: {file_url}')
                files.append({'name': filename, 'url': file_url})
        return files

    def scrape_victims(self, root_url, case_dir, **kwargs):
        logger = get_case_logger(case_dir, log_name="dragonforce_scraper.log")
        init_inventory_db(case_dir)
        session = requests.Session()
        session.proxies = {
            "http": "socks5h://127.0.0.1:9050",
            "https": "socks5h://127.0.0.1:9050",
        }
        try:
            resp = session.get(root_url, timeout=60)
            resp.raise_for_status()
        except Exception as e:
            logger.error(f"Failed to fetch Dragonforce victim page {root_url}: {e}")
            return

        soup = BeautifulSoup(resp.text, "html.parser")
        iframe = soup.find("iframe", {"class": "visor-content"})
        if not iframe or not iframe.get("src"):
            logger.error("No iframe with class 'visor-content' found on the page.")
            return

        iframe_url = iframe["src"]
        logger.info(f"Discovered Dragonforce iframe URL: {iframe_url}")

        # Parse token and path
        m = re.search(r'token=([^&]+)', iframe_url)
        token = m.group(1) if m else None
        m2 = re.search(r'path=([^&]+)', iframe_url)
        path = m2.group(1) if m2 else None

        logger.info(f"Token: {token}")
        logger.info(f"Path: {path}")

        # Save the iframe URL to the inventory for a custom downloader
        add_download(case_dir, iframe_url, "dragonforce_iframe_url.txt", status='pending')

        # Save token/path as metadata for the downloader
        cm = CaseManager(case_dir)
        metadata = cm.load_metadata()
        metadata['dragonforce'] = {
            'iframe_url': iframe_url,
            'token': token,
            'path': path
        }
        cm.save_metadata(metadata)
        logger.info(f"Saved Dragonforce iframe URL, token, and path to case metadata.")

        # Enumerate all files recursively and save to inventory
        base_url = iframe_url.split('/?')[0]
        self.enumerate_files(base_url, path, token, session, logger, case_dir)
        logger.info("Dragonforce enumeration complete.") 