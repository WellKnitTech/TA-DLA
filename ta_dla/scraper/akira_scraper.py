from ta_dla.scraper.base import ScraperPlugin
from ta_dla.utils import get_case_logger
from ta_dla.db.inventory import init_inventory_db, add_download
from bs4 import BeautifulSoup
import requests
import re

class AkiraScraper(ScraperPlugin):
    name = "AkiraScraper"
    supported_tas = ["akira"]

    def supports(self, ta: str) -> bool:
        return ta.lower() == "akira"

    def scrape_victims(self, root_url, case_dir, **kwargs):
        logger = get_case_logger(case_dir, log_name="akira_scraper.log")
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
            logger.error(f"Failed to fetch Akira victim page {root_url}: {e}")
            return
        soup = BeautifulSoup(resp.text, "html.parser")
        # Find all magnet links in <a> tags and plain text
        magnet_links = set(a['href'] for a in soup.find_all('a', href=True) if a['href'].startswith('magnet:?'))
        text = soup.get_text()
        magnet_links.update(re.findall(r'magnet:\?[^\s\'\"]+', text))
        # Find all .torrent or seed file links in <a> tags
        seed_links = set()
        for a in soup.find_all('a', href=True):
            href = a['href']
            if href.lower().endswith('.torrent') or '/t/' in href or 'seed' in href.lower():
                seed_links.add(href)
        if not magnet_links and not seed_links:
            logger.warning(f"No magnet or seed links found on page: {root_url}")
            return
        for magnet in magnet_links:
            logger.info(f"Discovered magnet link: {magnet}")
            result = add_download(case_dir, magnet, "akira_leak.torrent", status='pending')
            if not result:
                logger.warning(f'Failed to add magnet link to inventory DB: {magnet}')
        for seed in seed_links:
            logger.info(f"Discovered seed file link: {seed}")
            filename = seed.split('/')[-1] or 'akira_seed.torrent'
            result = add_download(case_dir, seed, filename, status='pending')
            if not result:
                logger.warning(f'Failed to add seed file link to inventory DB: {seed}') 