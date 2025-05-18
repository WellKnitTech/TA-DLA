from ta_dla.scraper.base import ScraperPlugin
from ta_dla.utils import get_case_logger
from ta_dla.db.inventory import init_inventory_db, add_download
import os
from urllib.parse import urljoin, unquote
from bs4 import BeautifulSoup
import requests

class IndexDirectoryScraper(ScraperPlugin):
    name = "IndexDirectoryScraper"
    supported_tas = []  # Empty means supports all by default

    def supports(self, ta: str) -> bool:
        # Generic: supports all TAs
        return True

    def is_index_page(self, html: str) -> bool:
        # Heuristic: look for <title>Index of / or <h1>Index of /
        soup = BeautifulSoup(html, "html.parser")
        title = soup.title.string if soup.title else ""
        h1 = soup.h1.string if soup.h1 else ""
        return ("Index of" in title) or ("Index of" in h1)

    def scrape_victims(self, root_url, case_dir, **kwargs):
        """
        Recursively scrape all files from an Apache/nginx-style index directory.
        Adds each file to the inventory DB as 'pending' for later download.
        """
        logger = get_case_logger(case_dir, log_name="index_directory_scraper.log")
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
            logger.error(f"Failed to fetch root URL {root_url}: {e}")
            return
        if not self.is_index_page(resp.text):
            logger.error(f"URL does not appear to be an index directory page: {root_url}")
            return
        self.scrape_directory(root_url, os.path.join(case_dir, "downloads"), session, logger, case_dir)

    def scrape_directory(self, base_url, local_dir, session, logger, case_dir):
        os.makedirs(local_dir, exist_ok=True)
        try:
            resp = session.get(base_url, timeout=60)
            resp.raise_for_status()
        except Exception as e:
            logger.error(f"Failed to fetch directory listing from {base_url}: {e}")
            return
        if not self.is_index_page(resp.text):
            logger.warning(f"Skipping non-index page: {base_url}")
            return
        soup = BeautifulSoup(resp.text, "html.parser")
        for link in soup.find_all("a"):
            href = link.get("href")
            if not href or href == "../":
                continue
            name = unquote(href)
            remote_url = urljoin(base_url, href)
            local_path = os.path.join(local_dir, name)
            if href.endswith("/"):
                self.scrape_directory(remote_url, local_path, session, logger, case_dir)
            else:
                logger.info(f"Discovered file: {remote_url} -> {local_path}")
                result = add_download(case_dir, remote_url, local_path, status='pending')
                if not result:
                    logger.warning(f'Failed to add download to inventory DB: {remote_url}') 