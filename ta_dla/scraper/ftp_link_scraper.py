from ta_dla.scraper.base import ScraperPlugin
from ta_dla.utils import get_case_logger
from ta_dla.db.inventory import init_inventory_db, add_download
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import click

class FTPLinkScraper(ScraperPlugin):
    name = "FTPLinkScraper"
    supported_tas = []  # Generic: supports all TAs

    def supports(self, ta: str) -> bool:
        return True

    def scrape_victims(self, root_url, case_dir, **kwargs):
        """
        Scrape all FTP URLs (with credentials) from a victim page and add them to the inventory.
        Prompts the analyst to include generic FTP links or not.
        """
        logger = get_case_logger(case_dir, log_name="ftp_link_scraper.log")
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
            logger.error(f"Failed to fetch victim page {root_url}: {e}")
            return

        soup = BeautifulSoup(resp.text, "html.parser")
        all_ftp_links = self.extract_ftp_links(soup)
        victim_links = [url for url in all_ftp_links if self.is_victim_specific_ftp_url(url)]
        generic_links = [url for url in all_ftp_links if not self.is_victim_specific_ftp_url(url)]

        if not all_ftp_links:
            logger.warning(f"No FTP links found on page: {root_url}")
            return

        # Always add victim-specific links
        for ftp_url in victim_links:
            logger.info(f"Discovered victim-specific FTP URL: {ftp_url}")
            filename = ftp_url.split('/')[-1] or 'ftp_download'
            result = add_download(case_dir, ftp_url, filename, status='pending')
            if not result:
                logger.warning(f'Failed to add FTP download to inventory DB: {ftp_url}')

        # Prompt for generic links
        if generic_links:
            click.secho(f"Generic FTP links found (not victim-specific):", fg='yellow')
            for url in generic_links:
                click.secho(f"  {url}", fg='yellow')
            include = click.confirm("Do you want to add these generic FTP links to the inventory?", default=False)
            if include:
                for ftp_url in generic_links:
                    logger.info(f"Analyst chose to add generic FTP URL: {ftp_url}")
                    filename = ftp_url.split('/')[-1] or 'ftp_download'
                    result = add_download(case_dir, ftp_url, filename, status='pending')
                    if not result:
                        logger.warning(f'Failed to add FTP download to inventory DB: {ftp_url}')
            else:
                logger.info("Analyst chose NOT to add generic FTP links.")

    def extract_ftp_links(self, soup):
        ftp_links = set()
        # From <a href="ftp://...">
        for a in soup.find_all('a', href=True):
            href = a['href']
            if self.is_valid_ftp_url(href):
                ftp_links.add(href)
        # From visible text
        text = soup.get_text()
        for match in re.findall(r'ftp://[^\s\'"<>]+', text):
            if self.is_valid_ftp_url(match):
                ftp_links.add(match)
        return list(ftp_links)

    def is_valid_ftp_url(self, url):
        # Must have credentials and host
        return re.match(r'^ftp://[^:@]+:[^:@]+@[^/]+', url) is not None

    def is_victim_specific_ftp_url(self, url):
        parsed = urlparse(url)
        return parsed.scheme == 'ftp' and parsed.path and parsed.path not in ('', '/') 