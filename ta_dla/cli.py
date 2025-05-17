import click
import os
import json
from ta_dla.downloader.http_downloader import download_file as http_download_file
from ta_dla.downloader.ftp_downloader import download_ftp_files
from ta_dla.downloader.mega_downloader import download_mega_file
from ta_dla.utils import get_case_logger
from ta_dla.analyzer.pii_scanner import scan_directory_for_pii_phi_pci
from ta_dla.analyzer.yara_scanner import scan_directory_with_yara, ensure_yara_rules_repo, RULESET_MAP
from ta_dla.analyzer.clamav_scanner import scan_directory_with_clamav, print_clamav_install_instructions
import ta_dla.db.inventory as inventory

def is_mega_url(url: str) -> bool:
    return url.startswith('https://mega.nz/') or url.startswith('https://www.mega.nz/')

def is_ftp_url(url: str) -> bool:
    return url.startswith('ftp://')

@click.group()
def cli():
    """TA-DLA: Threat Actor Data Leak Analyzer CLI"""
    pass

@cli.command()
@click.option('--case-dir', required=True, type=click.Path(), help='Path to the case directory')
@click.option('--url-list', type=click.Path(), help='Path to a .txt file with one URL per line')
@click.option('--scraper-json', type=click.Path(), help='Path to a JSON file with a list of URLs or dicts with url/filename')
@click.option('--allow-insecure-mega', is_flag=True, default=False, help='Allow MEGA downloads without TOR (not recommended)')
def download(case_dir, url_list, scraper_json, allow_insecure_mega):
    """
    Download files for the case from a manual URL list or a scraper JSON output.
    Supports HTTP, FTP, and MEGA links. MEGA downloads require TOR by default.
    """
    downloads_dir = os.path.join(case_dir, 'downloads')
    os.makedirs(downloads_dir, exist_ok=True)
    logger = get_case_logger(case_dir)
    # Initialize inventory DB
    inventory.init_inventory_db(case_dir)
    inventory.add_event(case_dir, 'download_start', 'Starting download phase')
    urls = []
    if url_list:
        with open(url_list, 'r') as f:
            for line in f:
                url = line.strip()
                if url:
                    urls.append({'url': url})
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
    # Add all URLs to inventory as pending
    for item in urls:
        url = item['url']
        filename = item.get('filename') or url.split('/')[-1] or 'downloaded_file'
        inventory.add_download(case_dir, url, filename, status='pending')
    for item in urls:
        url = item['url']
        filename = item.get('filename') or url.split('/')[-1] or 'downloaded_file'
        output_path = os.path.join(downloads_dir, filename)
        logger.info(f"Starting download: {url} -> {output_path}")
        if is_mega_url(url):
            success = download_mega_file(url, downloads_dir, case_dir=case_dir, logger=logger, require_tor=not allow_insecure_mega)
        elif is_ftp_url(url):
            logger.warning(f"FTP URL detected: {url}. Please use the dedicated FTP download command or ensure credentials are in metadata.json.")
            success = False
        else:
            success = http_download_file(url, output_path, logger=logger, case_dir=case_dir)
        if success:
            logger.info(f"Successfully downloaded: {url}")
            # Update inventory
            size = os.path.getsize(output_path) if os.path.exists(output_path) else None
            inventory.update_download_status(case_dir, url, 'complete', size=size)
        else:
            logger.error(f"Failed to download: {url}")
            inventory.update_download_status(case_dir, url, 'failed', error='Download failed')
    inventory.add_event(case_dir, 'download_end', 'Download phase complete')

@cli.command()
@click.option('--case-dir', required=True, type=click.Path(), help='Path to the case directory')
@click.option('--ftp-server', type=str, help='FTP server address')
@click.option('--ftp-user', type=str, help='FTP username')
@click.option('--ftp-pass', type=str, help='FTP password')
@click.option('--ftp-path', type=str, help='Remote FTP file path')
def download_ftp(case_dir, ftp_server, ftp_user, ftp_pass, ftp_path):
    """
    Download files from an FTP server for the case. Credentials and path are required.
    """
    downloads_dir = os.path.join(case_dir, 'downloads')
    os.makedirs(downloads_dir, exist_ok=True)
    logger = get_case_logger(case_dir)
    if not all([ftp_server, ftp_user, ftp_pass, ftp_path]):
        logger.error('FTP server, user, password, and path are required.')
        click.echo('FTP server, user, password, and path are required.')
        return
    logger.info(f"Starting FTP download: {ftp_server}:{ftp_path}")
    success = download_ftp_files(
        server=ftp_server,
        username=ftp_user,
        password=ftp_pass,
        remote_path=ftp_path,
        output_dir=downloads_dir,
        case_dir=case_dir,
        logger=logger
    )
    if success:
        logger.info(f"Successfully downloaded from FTP: {ftp_server}:{ftp_path}")
    else:
        logger.error(f"Failed to download from FTP: {ftp_server}:{ftp_path}")

@cli.command()
@click.option('--case-dir', required=True, type=click.Path(), help='Path to the case directory')
@click.option('--extracted-dir', type=click.Path(), default=None, help='Directory of extracted files (default: <case-dir>/extracted)')
@click.option('--output-csv', type=click.Path(), default=None, help='CSV file to write PII/PHI/PCI findings (default: <case-dir>/reports/pii.csv)')
@click.option('--batch-size', type=int, default=32, help='Number of files to process per batch')
@click.option('--max-workers', type=int, default=None, help='Number of parallel workers (default: 4 or CPU count)')
@click.option('--yara', is_flag=True, default=False, help='Enable YARA malware scanning')
@click.option('--yara-output-csv', type=click.Path(), default=None, help='CSV file to write YARA findings (default: <case-dir>/reports/malware.csv)')
@click.option('--yara-rulesets', type=str, default='yararules,reversinglabs', help='Comma-separated list of YARA rulesets to use (default: both)')
@click.option('--update-yara', is_flag=True, default=False, help='Update YARA rulesets before scanning')
@click.option('--clamav', is_flag=True, default=False, help='Enable ClamAV antivirus scanning (optional, requires clamd)')
@click.option('--clamav-output-csv', type=click.Path(), default=None, help='CSV file to write ClamAV findings (default: <case-dir>/reports/clamav.csv)')
@click.option('--skip-clamav', is_flag=True, default=False, help='Explicitly skip ClamAV scanning (overrides --clamav)')
def analyze(case_dir, extracted_dir, output_csv, batch_size, max_workers, yara, yara_output_csv, yara_rulesets, update_yara, clamav, clamav_output_csv, skip_clamav):
    """
    Analyze extracted files for PII, PHI, PCI, high-entropy secrets, and (optionally) malware with YARA and ClamAV.
    Outputs findings to CSV files for reporting.
    """
    logger = get_case_logger(case_dir)
    inventory.init_inventory_db(case_dir)
    inventory.add_event(case_dir, 'analyze_start', 'Starting analysis phase')
    if not extracted_dir:
        extracted_dir = os.path.join(case_dir, 'extracted')
    reports_dir = os.path.join(case_dir, 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    if not output_csv:
        output_csv = os.path.join(reports_dir, 'pii.csv')
    logger.info(f"Starting PII/PHI/PCI/entropy scan: {extracted_dir} -> {output_csv}")
    finding_count = scan_directory_for_pii_phi_pci(
        directory=extracted_dir,
        case_dir=case_dir,
        logger=logger,
        max_workers=max_workers,
        batch_size=batch_size,
        csv_output_path=output_csv
    )
    # Log PII findings to inventory
    if os.path.exists(output_csv):
        import csv as _csv
        with open(output_csv, newline='', encoding='utf-8') as f:
            reader = _csv.DictReader(f)
            for row in reader:
                inventory.add_pii_finding(case_dir, row['file'], row['pattern'], row['match'], int(row['line']), row['context'])
    logger.info(f"Scan complete. {finding_count} findings written to {output_csv}")
    click.echo(f"Scan complete. {finding_count} findings written to {output_csv}")
    # YARA scanning
    if yara:
        if not yara_output_csv:
            yara_output_csv = os.path.join(reports_dir, 'malware.csv')
        ruleset_names = [r.strip() for r in yara_rulesets.split(',') if r.strip() in RULESET_MAP]
        if update_yara:
            for r in ruleset_names:
                repo_url, local_dir = RULESET_MAP[r]
                ensure_yara_rules_repo(local_dir, logger=logger, repo_url=repo_url)
        logger.info(f"Starting YARA scan with rulesets: {ruleset_names} -> {yara_output_csv}")
        yara_count = scan_directory_with_yara(
            directory=extracted_dir,
            rulesets=ruleset_names,
            output_csv=yara_output_csv,
            case_dir=case_dir,
            logger=logger,
            max_workers=max_workers,
            batch_size=batch_size
        )
        # Log YARA findings to inventory
        if os.path.exists(yara_output_csv):
            import csv as _csv
            with open(yara_output_csv, newline='', encoding='utf-8') as f:
                reader = _csv.DictReader(f)
                for row in reader:
                    inventory.add_malware_hit(case_dir, row['file'], row['rule'], row['meta'], row['ruleset'])
        logger.info(f"YARA scan complete. {yara_count} findings written to {yara_output_csv}")
        click.echo(f"YARA scan complete. {yara_count} findings written to {yara_output_csv}")
    # ClamAV scanning
    if clamav and not skip_clamav:
        if not clamav_output_csv:
            clamav_output_csv = os.path.join(reports_dir, 'clamav.csv')
        logger.info(f"Starting ClamAV scan -> {clamav_output_csv}")
        clamav_count = scan_directory_with_clamav(
            directory=extracted_dir,
            output_csv=clamav_output_csv,
            case_dir=case_dir,
            logger=logger,
            max_workers=max_workers,
            batch_size=batch_size
        )
        # Log ClamAV findings to inventory
        if os.path.exists(clamav_output_csv):
            import csv as _csv
            with open(clamav_output_csv, newline='', encoding='utf-8') as f:
                reader = _csv.DictReader(f)
                for row in reader:
                    inventory.add_malware_hit(case_dir, row['file'], row['signature'], row['signature'], 'clamav')
        logger.info(f"ClamAV scan complete. {clamav_count} infected files written to {clamav_output_csv}")
        click.echo(f"ClamAV scan complete. {clamav_count} infected files written to {clamav_output_csv}")
    elif clamav and skip_clamav:
        logger.info("ClamAV scan explicitly skipped by user (--skip-clamav)")
        click.echo("ClamAV scan explicitly skipped by user (--skip-clamav)")
    inventory.add_event(case_dir, 'analyze_end', 'Analysis phase complete')

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
    # Example: after extracting each file, call inventory.add_extracted_file(...)
    pass

@cli.command()
@click.option('--case-dir', required=True, type=click.Path(), help='Path to the case directory')
def inventory_status(case_dir):
    """Show counts of downloads by status (pending, complete, failed) and summary stats."""
    stats = inventory.get_download_stats(case_dir)
    click.echo(f"Download status for case: {case_dir}")
    for status, count in stats.items():
        click.echo(f"  {status}: {count}")

@cli.command()
@click.option('--case-dir', required=True, type=click.Path(), help='Path to the case directory')
def pending_downloads(case_dir):
    """List all pending downloads for a case."""
    pending = inventory.get_pending_downloads(case_dir)
    if not pending:
        click.echo("No pending downloads.")
        return
    click.echo(f"Pending downloads for case: {case_dir}")
    for d in pending:
        click.echo(f"  {d['url']} -> {d['filename']}")

@cli.command()
@click.option('--case-dir', required=True, type=click.Path(), help='Path to the case directory')
def failed_downloads(case_dir):
    """List all failed downloads for a case."""
    failed = inventory.get_failed_downloads(case_dir)
    if not failed:
        click.echo("No failed downloads.")
        return
    click.echo(f"Failed downloads for case: {case_dir}")
    for d in failed:
        click.echo(f"  {d['url']} -> {d['filename']} (error: {d['error']})")

@cli.command()
@click.option('--case-dir', required=True, type=click.Path(), help='Path to the case directory')
@click.option('--allow-insecure-mega', is_flag=True, default=False, help='Allow MEGA downloads without TOR (not recommended)')
def resume_downloads(case_dir, allow_insecure_mega):
    """Resume only pending/failed downloads for a case (retries only those, not all)."""
    downloads_dir = os.path.join(case_dir, 'downloads')
    os.makedirs(downloads_dir, exist_ok=True)
    logger = get_case_logger(case_dir)
    pending = inventory.get_pending_downloads(case_dir)
    failed = inventory.get_failed_downloads(case_dir)
    to_resume = pending + failed
    if not to_resume:
        click.echo("No pending or failed downloads to resume.")
        return
    click.echo(f"Resuming {len(to_resume)} downloads for case: {case_dir}")
    for d in to_resume:
        url = d['url']
        filename = d['filename']
        output_path = os.path.join(downloads_dir, filename)
        logger.info(f"Resuming download: {url} -> {output_path}")
        if is_mega_url(url):
            success = download_mega_file(url, downloads_dir, case_dir=case_dir, logger=logger, require_tor=not allow_insecure_mega)
        elif is_ftp_url(url):
            logger.warning(f"FTP URL detected: {url}. Please use the dedicated FTP download command or ensure credentials are in metadata.json.")
            success = False
        else:
            success = http_download_file(url, output_path, logger=logger, case_dir=case_dir)
        if success:
            logger.info(f"Successfully downloaded: {url}")
            size = os.path.getsize(output_path) if os.path.exists(output_path) else None
            inventory.update_download_status(case_dir, url, 'complete', size=size)
        else:
            logger.error(f"Failed to download: {url}")
            inventory.update_download_status(case_dir, url, 'failed', error='Download failed')
    click.echo("Resume operation complete.")

if __name__ == '__main__':
    cli() 