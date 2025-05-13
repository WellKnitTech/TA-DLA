import click
import os
import json
from ta_dla.downloader.http_downloader import download_file
from ta_dla.utils import get_case_logger

@click.group()
def cli():
    """TA-DLA: Threat Actor Data Leak Analyzer CLI"""
    pass

@cli.command()
@click.option('--case-dir', required=True, type=click.Path(), help='Path to the case directory')
@click.option('--url-list', type=click.Path(), help='Path to a .txt file with one URL per line')
@click.option('--scraper-json', type=click.Path(), help='Path to a JSON file with a list of URLs or dicts with url/filename')
def download(case_dir, url_list, scraper_json):
    """
    Download files for the case from a manual URL list or a scraper JSON output.
    """
    downloads_dir = os.path.join(case_dir, 'downloads')
    os.makedirs(downloads_dir, exist_ok=True)
    logger = get_case_logger(case_dir)
    urls = []
    # Ingest from txt file
    if url_list:
        with open(url_list, 'r') as f:
            for line in f:
                url = line.strip()
                if url:
                    urls.append({'url': url})
    # Ingest from scraper JSON
    if scraper_json:
        with open(scraper_json, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and 'url' in item:
                        urls.append(item)
                    elif isinstance(item, str):
                        urls.append({'url': item})
    if not urls:
        logger.error('No URLs found to download.')
        click.echo('No URLs found to download.')
        return
    for item in urls:
        url = item['url']
        filename = item.get('filename') or url.split('/')[-1] or 'downloaded_file'
        output_path = os.path.join(downloads_dir, filename)
        logger.info(f"Starting download: {url} -> {output_path}")
        success = download_file(url, output_path, logger=logger, case_dir=case_dir)
        if success:
            logger.info(f"Successfully downloaded: {url}")
        else:
            logger.error(f"Failed to download: {url}")

@cli.command()
@click.option('--case-dir', required=True, type=click.Path(), help='Path to the case directory')
def scrape(case_dir):
    """Scrape download links from TA leak sites."""
    # TODO: Implement scraper logic
    pass

@cli.command()
@click.option('--case-dir', required=True, type=click.Path(), help='Path to the case directory')
def extract(case_dir):
    """Extract archives for the case."""
    # TODO: Implement extraction logic
    pass

@cli.command()
@click.option('--case-dir', required=True, type=click.Path(), help='Path to the case directory')
def analyze(case_dir):
    """Analyze extracted files for PII, malware, etc."""
    # TODO: Implement analysis logic
    pass

if __name__ == '__main__':
    cli() 