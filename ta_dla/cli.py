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
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from ta_dla.extractor.extract import extract_all_archives
from ta_dla.analyzer.reporting import (
    summarize_downloads, summarize_pii_phi_pci, yara_summary_report, cross_reference_sensitive_files, generate_html_dashboard
)
import sys
from ta_dla.enrichment import RansomwareLiveEnrichment
from ta_dla.case_manager import CaseManager

def is_mega_url(url: str) -> bool:
    return url.startswith('https://mega.nz/') or url.startswith('https://www.mega.nz/')

def is_ftp_url(url: str) -> bool:
    return url.startswith('ftp://')

def tor_health_check(proxy_url='socks5h://127.0.0.1:9050', test_onion='http://expyuzz4wqqyqhjn.onion', timeout=10):
    """
    Check if TOR is running and SOCKS5 proxy is routing traffic. Attempts to connect to a known .onion service.
    Returns True if successful, False otherwise.
    """
    import requests
    try:
        proxies = {'http': proxy_url, 'https': proxy_url}
        resp = requests.get(test_onion, proxies=proxies, timeout=timeout)
        if resp.status_code == 200:
            return True
    except Exception:
        pass
    return False

def opsec_guard(ignore_opsec):
    if ignore_opsec:
        click.echo('[WARNING] OpSec bypass flag set. Proceeding without TOR check.')
        return True
    if not tor_health_check():
        click.echo('[WARNING] TOR is NOT running or not proxying traffic!')
        click.echo('Proceeding may expose your real IP and compromise OpSec.')
        if not click.confirm('Do you want to continue anyway? (NOT RECOMMENDED)', default=False):
            click.echo('Aborting for OpSec.')
            sys.exit(1)
        return True
    return True

@click.group()
def cli():
    """TA-DLA: Threat Actor Data Leak Analyzer CLI\n\nOpSec Notice: Always use TOR/SOCKS5 for .onion sites. Never upload case data to public repos.\nReview all findings in a secure, air-gapped environment.\n"""
    pass

@cli.command()
@click.option('--case-dir', required=True, type=click.Path(), help='Path to the case directory')
@click.option('--url-list', type=click.Path(), help='Path to a .txt file with one URL per line')
@click.option('--scraper-json', type=click.Path(), help='Path to a JSON file with a list of URLs or dicts with url/filename')
@click.option('--allow-insecure-mega', is_flag=True, default=False, help='Allow MEGA downloads without TOR (not recommended)')
@click.option('--ignore-opsec-this-is-a-bad-idea', is_flag=True, default=False, help='Ignore OpSec checks and warnings (NOT RECOMMENDED)')
def download(case_dir, url_list, scraper_json, allow_insecure_mega, ignore_opsec_this_is_a_bad_idea):
    """
    Download files for the case from a manual URL list or a scraper JSON output.
    Supports HTTP, FTP, and MEGA links. MEGA downloads require TOR by default.
    """
    if not opsec_guard(ignore_opsec_this_is_a_bad_idea):
        return
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
        success = inventory.add_download(case_dir, url, filename, status='pending')
        if not success:
            logger.warning('Failed to add download to inventory DB')
            click.echo('Warning: Failed to add download to inventory DB')
    for item in urls:
        url = item['url']
        filename = item.get('filename') or url.split('/')[-1] or 'downloaded_file'
        output_path = os.path.join(downloads_dir, filename)
        logger.info(f"Starting download: {url} -> {output_path}")
        if is_mega_url(url):
            click.echo("OpSec Warning: Always use TOR for .onion sites and all downloads.")
            success = download_mega_file(url, downloads_dir, case_dir=case_dir, logger=logger, require_tor=not allow_insecure_mega)
        elif is_ftp_url(url):
            click.echo("OpSec Warning: Always use TOR for .onion sites and all downloads.")
            logger.warning(f"FTP URL detected: {url}. Please use the dedicated FTP download command or ensure credentials are in metadata.json.")
            success = False
        else:
            success = http_download_file(url, output_path, logger=logger, case_dir=case_dir)
        if success:
            logger.info(f"Successfully downloaded: {url}")
            # Update inventory
            size = os.path.getsize(output_path) if os.path.exists(output_path) else None
            success = inventory.update_download_status(case_dir, url, 'complete', size=size)
            if not success:
                logger.warning('Failed to update download status in inventory DB')
                click.echo('Warning: Failed to update download status in inventory DB')
        else:
            logger.error(f"Failed to download: {url}")
            success = inventory.update_download_status(case_dir, url, 'failed', error='Download failed')
            if not success:
                logger.warning('Failed to update download status in inventory DB')
                click.echo('Warning: Failed to update download status in inventory DB')
    inventory.add_event(case_dir, 'download_end', 'Download phase complete')

@cli.command()
@click.option('--case-dir', required=True, type=click.Path(), help='Path to the case directory')
@click.option('--ftp-server', type=str, help='FTP server address')
@click.option('--ftp-user', type=str, help='FTP username')
@click.option('--ftp-pass', type=str, help='FTP password')
@click.option('--ftp-path', type=str, help='Remote FTP file path')
@click.option('--ignore-opsec-this-is-a-bad-idea', is_flag=True, default=False, help='Ignore OpSec checks and warnings (NOT RECOMMENDED)')
def download_ftp(case_dir, ftp_server, ftp_user, ftp_pass, ftp_path, ignore_opsec_this_is_a_bad_idea):
    """
    Download files from an FTP server for the case. Credentials and path are required.
    """
    if not opsec_guard(ignore_opsec_this_is_a_bad_idea):
        return
    downloads_dir = os.path.join(case_dir, 'downloads')
    os.makedirs(downloads_dir, exist_ok=True)
    logger = get_case_logger(case_dir)
    if not all([ftp_server, ftp_user, ftp_pass, ftp_path]):
        logger.error('FTP server, user, password, and path are required.')
        click.echo('FTP server, user, password, and path are required.')
        return
    logger.info(f"Starting FTP download: {ftp_server}:{ftp_path}")
    click.echo("OpSec Warning: Always use TOR for .onion sites and all downloads.")
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

def load_case_config(case_dir):
    cm = CaseManager(case_dir)
    return cm.load_config() or {}

@cli.command()
@click.option('--case-dir', required=True, type=click.Path(), help='Path to the case directory')
@click.option('--victim', type=str, default=None, help='Victim/organization name (will be matched to ransomware.live, or use "unknown")')
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
@click.option('--ta-group', type=str, default=None, help='Threat Actor group name (will be matched to ransomware.live, or use "unknown")')
@click.option('--refresh-enrichment', is_flag=True, default=False, help='Force refresh of enrichment data from ransomware.live')
def analyze(case_dir, victim, extracted_dir, output_csv, batch_size, max_workers, yara, yara_output_csv, yara_rulesets, update_yara, clamav, clamav_output_csv, skip_clamav, ta_group, refresh_enrichment):
    """
    Analyze extracted files for PII, PHI, PCI, high-entropy secrets, and (optionally) malware with YARA and ClamAV.
    Outputs findings to CSV files for reporting. Integrates ransomware.live enrichment and YARA rules if available.
    """
    config = load_case_config(case_dir)
    # Use case.json as default for victim and ta_group
    if not victim:
        victim = (config.get('victim', {}) or {}).get('name') or config.get('victim_name')
    if not ta_group:
        ta_group = config.get('ta_group') or config.get('group_name')
    logger = get_case_logger(case_dir)
    inventory.init_inventory_db(case_dir)
    inventory.add_event(case_dir, 'analyze_start', 'Starting analysis phase')
    if not extracted_dir:
        extracted_dir = os.path.join(case_dir, 'extracted')
    reports_dir = os.path.join(case_dir, 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    enrichment_path = os.path.join(reports_dir, 'enrichment.json')
    enrichment = None
    group_info = None
    yara_rules_str = None
    cert_contacts = None
    victim_info = None
    enrichment_client = RansomwareLiveEnrichment(logger=logger)
    # Prompt for victim name if not provided
    if victim is None:
        recent_victims = enrichment_client.get_recent_victims() or []
        victim_names = [v['victim'] for v in recent_victims if 'victim' in v]
        click.echo("Recent victims from ransomware.live:")
        click.echo(", ".join(sorted(victim_names)[:30]) + (", ..." if len(victim_names) > 30 else ""))
        victim = click.prompt('Enter victim/organization name (or "unknown")', default='unknown')
    else:
        recent_victims = enrichment_client.get_recent_victims() or []
        victim_names = [v['victim'] for v in recent_victims if 'victim' in v]
    matched_victim = None
    if victim and victim.lower() != 'unknown':
        for v in recent_victims:
            if victim.lower() == v['victim'].lower():
                matched_victim = v
                break
        if not matched_victim:
            for v in recent_victims:
                if victim.lower() in v['victim'].lower():
                    matched_victim = v
                    break
        if not matched_victim:
            click.echo(f"Victim '{victim}' not found in recent ransomware.live data. Proceeding as 'unknown'.")
            victim = 'unknown'
    else:
        victim = 'unknown'
    if matched_victim:
        victim_info = matched_victim
    else:
        victim_info = {'name': victim}
    # ... existing group enrichment logic ...
    if ta_group is None:
        groups = enrichment_client.get_groups() or []
        group_names = [g['name'] for g in groups if 'name' in g]
        click.echo("Known Threat Actor groups from ransomware.live:")
        click.echo(", ".join(sorted(group_names)))
        ta_group = click.prompt('Enter Threat Actor group name (or "unknown")', default='unknown')
    else:
        groups = enrichment_client.get_groups() or []
        group_names = [g['name'] for g in groups if 'name' in g]
    matched_group = None
    if ta_group and ta_group.lower() != 'unknown':
        for g in groups:
            if ta_group.lower() == g['name'].lower():
                matched_group = g['name']
                break
        if not matched_group:
            for g in groups:
                if ta_group.lower() in g['name'].lower():
                    matched_group = g['name']
                    break
        if not matched_group:
            click.echo(f"Group '{ta_group}' not found in ransomware.live. Proceeding as 'unknown'.")
            ta_group = 'unknown'
    else:
        ta_group = 'unknown'
    enrichment_data = {}
    if (victim != 'unknown' or ta_group != 'unknown') and (refresh_enrichment or not os.path.exists(enrichment_path)):
        group_info = enrichment_client.get_group(matched_group or ta_group) if ta_group != 'unknown' else None
        yara_rules_str = enrichment_client.get_yara_rules(matched_group or ta_group) if ta_group != 'unknown' else None
        cert_contacts = enrichment_client.get_cert_contacts('US')
        enrichment_data = {
            'victim': victim_info,
            'group': group_info,
            'yara_rules': yara_rules_str,
            'cert_contacts': cert_contacts,
            'group_name': matched_group or ta_group,
            'victim_name': victim
        }
        with open(enrichment_path, 'w', encoding='utf-8') as f:
            json.dump(enrichment_data, f, indent=2)
    elif os.path.exists(enrichment_path):
        with open(enrichment_path, 'r', encoding='utf-8') as f:
            enrichment_data = json.load(f)
        group_info = enrichment_data.get('group')
        yara_rules_str = enrichment_data.get('yara_rules')
        cert_contacts = enrichment_data.get('cert_contacts')
        victim_info = enrichment_data.get('victim')
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
                success = inventory.add_pii_finding(case_dir, row['file'], row['pattern'], row['match'], int(row['line']), row['context'])
                if not success:
                    logger.warning('Failed to add PII finding to inventory DB')
                    click.echo('Warning: Failed to add PII finding to inventory DB')
    logger.info(f"Scan complete. {finding_count} findings written to {output_csv}")
    click.echo(f"Scan complete. {finding_count} findings written to {output_csv}")
    # YARA scanning (inject enrichment rules if available)
    extra_rules = []
    if yara and yara_rules_str and isinstance(yara_rules_str, str) and 'rule ' in yara_rules_str:
        from ta_dla.analyzer.yara_scanner import load_yara_rules_from_string
        compiled = load_yara_rules_from_string(yara_rules_str, logger=logger)
        if compiled:
            extra_rules.append((f"ransomware.live:{ta_group}", compiled))
            click.echo(f"[INFO] Using YARA rules from ransomware.live for group: {ta_group}")
    if yara:
        if not yara_output_csv:
            yara_output_csv = os.path.join(reports_dir, 'malware.csv')
        ruleset_names = [r.strip() for r in yara_rulesets.split(',') if r.strip() in RULESET_MAP]
        if update_yara:
            for r in ruleset_names:
                repo_url, local_dir = RULESET_MAP[r]
                success = ensure_yara_rules_repo(local_dir, logger=logger, repo_url=repo_url)
                if not success:
                    logger.warning('Failed to update YARA rulesets in inventory DB')
                    click.echo('Warning: Failed to update YARA rulesets in inventory DB')
        logger.info(f"Starting YARA scan with rulesets: {ruleset_names} -> {yara_output_csv}")
        yara_count = scan_directory_with_yara(
            directory=extracted_dir,
            rulesets=ruleset_names,
            output_csv=yara_output_csv,
            case_dir=case_dir,
            logger=logger,
            max_workers=max_workers,
            batch_size=batch_size,
            extra_rules=extra_rules if extra_rules else None
        )
        # Log YARA findings to inventory
        if os.path.exists(yara_output_csv):
            import csv as _csv
            with open(yara_output_csv, newline='', encoding='utf-8') as f:
                reader = _csv.DictReader(f)
                for row in reader:
                    success = inventory.add_malware_hit(case_dir, row['file'], row['rule'], row['meta'], row['ruleset'])
                    if not success:
                        logger.warning('Failed to add malware hit to inventory DB')
                        click.echo('Warning: Failed to add malware hit to inventory DB')
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
                    success = inventory.add_malware_hit(case_dir, row['file'], row['signature'], row['signature'], 'clamav')
                    if not success:
                        logger.warning('Failed to add malware hit to inventory DB')
                        click.echo('Warning: Failed to add malware hit to inventory DB')
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
@click.option('--password', multiple=True, help='Password(s) to try for encrypted archives')
@click.option('--password-list', type=click.Path(), help='Path to a file with passwords (one per line)')
@click.option('--max-depth', type=int, default=5, help='Maximum recursion depth for nested extraction (default: 5)')
def extract(case_dir, password, password_list, max_depth):
    """
    Extract all supported archives for the case, including nested archives. Handles .zip, .7z, .rar, .tar.gz, .gz, .bz2.
    Logs extracted files to the DB and reports errors. Password-protected and multi-part archives are handled or reported.
    Accepts passwords via --password and/or --password-list.
    """
    logger = get_case_logger(case_dir)
    downloads_dir = os.path.join(case_dir, 'downloads')
    extracted_dir = os.path.join(case_dir, 'extracted')
    os.makedirs(extracted_dir, exist_ok=True)
    # Combine passwords from CLI and file
    passwords = list(password) if password else []
    if password_list:
        try:
            with open(password_list, 'r') as f:
                for line in f:
                    pw = line.strip()
                    if pw and not pw.startswith('#'):
                        passwords.append(pw)
        except Exception as e:
            logger.error(f"Failed to read password list: {e}")
            click.echo(f"Failed to read password list: {e}")
    logger.info(f"Starting extraction: {downloads_dir} -> {extracted_dir}")
    try:
        extract_all_archives(
            input_dir=downloads_dir,
            output_dir=extracted_dir,
            case_dir=case_dir,
            logger=logger,
            depth=0,
            max_depth=max_depth,
            passwords=passwords if passwords else None
        )
        logger.info("Extraction phase complete.")
        click.echo("Extraction phase complete.")
    except Exception as e:
        logger.error(f"Extraction failed: {e}")
        click.echo(f"Extraction failed: {e}")

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
@click.option('--ignore-opsec-this-is-a-bad-idea', is_flag=True, default=False, help='Ignore OpSec checks and warnings (NOT RECOMMENDED)')
def resume_downloads(case_dir, allow_insecure_mega, ignore_opsec_this_is_a_bad_idea):
    """Resume only pending/failed downloads for a case (retries only those, not all)."""
    if not opsec_guard(ignore_opsec_this_is_a_bad_idea):
        return
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
            click.echo("OpSec Warning: Always use TOR for .onion sites and all downloads.")
            success = download_mega_file(url, downloads_dir, case_dir=case_dir, logger=logger, require_tor=not allow_insecure_mega)
        elif is_ftp_url(url):
            click.echo("OpSec Warning: Always use TOR for .onion sites and all downloads.")
            logger.warning(f"FTP URL detected: {url}. Please use the dedicated FTP download command or ensure credentials are in metadata.json.")
            success = False
        else:
            success = http_download_file(url, output_path, logger=logger, case_dir=case_dir)
        if success:
            logger.info(f"Successfully downloaded: {url}")
            size = os.path.getsize(output_path) if os.path.exists(output_path) else None
            success = inventory.update_download_status(case_dir, url, 'complete', size=size)
            if not success:
                logger.warning('Failed to update download status in inventory DB')
                click.echo('Warning: Failed to update download status in inventory DB')
        else:
            logger.error(f"Failed to download: {url}")
            success = inventory.update_download_status(case_dir, url, 'failed', error='Download failed')
            if not success:
                logger.warning('Failed to update download status in inventory DB')
                click.echo('Warning: Failed to update download status in inventory DB')
    click.echo("Resume operation complete.")

@cli.command()
@click.option('--case-dir', required=True, type=click.Path(), help='Path to the case directory')
@click.option('--max-workers', type=int, default=4, help='Number of parallel downloads (default: 4)')
@click.option('--ignore-opsec-this-is-a-bad-idea', is_flag=True, default=False, help='Ignore OpSec checks and warnings (NOT RECOMMENDED)')
def download_http(case_dir, max_workers, ignore_opsec_this_is_a_bad_idea):
    """
    Download all pending HTTP/HTTPS files for a case in parallel, updating status in the inventory DB.
    """
    if not opsec_guard(ignore_opsec_this_is_a_bad_idea):
        return
    downloads_dir = os.path.join(case_dir, 'downloads')
    os.makedirs(downloads_dir, exist_ok=True)
    logger = get_case_logger(case_dir)
    from ta_dla.db import inventory
    pending = inventory.get_pending_downloads(case_dir)
    if not pending:
        click.echo("No pending HTTP/HTTPS downloads.")
        return
    click.echo(f"Starting parallel download of {len(pending)} files (max_workers={max_workers})...")
    def download_task(d):
        url = d['url']
        filename = d['filename']
        output_path = filename if os.path.isabs(filename) else os.path.join(downloads_dir, filename)
        logger.info(f"Downloading: {url} -> {output_path}")
        success = http_download_file(url, output_path, logger=logger, case_dir=case_dir)
        if success:
            logger.info(f"Successfully downloaded: {url}")
            size = os.path.getsize(output_path) if os.path.exists(output_path) else None
            success = inventory.update_download_status(case_dir, url, 'complete', size=size)
            if not success:
                logger.warning('Failed to update download status in inventory DB')
                click.echo('Warning: Failed to update download status in inventory DB')
        else:
            logger.error(f"Failed to download: {url}")
            success = inventory.update_download_status(case_dir, url, 'failed', error='Download failed')
            if not success:
                logger.warning('Failed to update download status in inventory DB')
                click.echo('Warning: Failed to update download status in inventory DB')
        return url, success
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(download_task, d): d for d in pending if url_is_http(d['url'])}
        for future in as_completed(futures):
            url, success = future.result()
            click.echo(f"{'[OK]' if success else '[FAIL]'} {url}")
    click.echo("HTTP/HTTPS download phase complete.")

@cli.command()
@click.option('--case-dir', required=True, type=click.Path(), help='Path to the case directory')
@click.option('--url-list', required=True, type=click.Path(), help='Path to a .txt file with one URL per line (TOR links or others)')
def scraper_feed(case_dir, url_list):
    """
    Feed a text file of URLs (one per line) into the inventory DB as 'pending' downloads for the case.
    Useful when you have a list of TOR links and do not want to dynamically scrape a TA's site.
    """
    from ta_dla.db import inventory
    downloads_dir = os.path.join(case_dir, 'downloads')
    os.makedirs(downloads_dir, exist_ok=True)
    inventory.init_inventory_db(case_dir)
    count = 0
    with open(url_list, 'r') as f:
        for line in f:
            url = line.strip()
            if not url or url.startswith('#'):
                continue
            filename = url.split('/')[-1] or f'file_{count}'
            local_path = os.path.join(downloads_dir, filename)
            success = inventory.add_download(case_dir, url, local_path, status='pending')
            if not success:
                logger.warning('Failed to add download to inventory DB')
                click.echo('Warning: Failed to add download to inventory DB')
            count += 1
    click.echo(f"Added {count} URLs from {url_list} to inventory as pending downloads.")

@cli.command()
@click.option('--case-dir', required=True, type=click.Path(), help='Path to the case directory')
@click.option('--output-html', type=click.Path(), default=None, help='Path to output HTML dashboard (default: <case-dir>/reports/dashboard.html)')
@click.option('--pii-csv', type=click.Path(), default=None, help='PII/PHI/PCI findings CSV (default: <case-dir>/reports/pii.csv)')
@click.option('--yara-csv', type=click.Path(), default=None, help='YARA findings CSV (default: <case-dir>/reports/malware.csv)')
@click.option('--clamav-csv', type=click.Path(), default=None, help='ClamAV findings CSV (default: <case-dir>/reports/clamav.csv)')
@click.option('--victim-info', type=click.Path(), default=None, help='Victim info JSON (optional)')
@click.option('--ta-info', type=click.Path(), default=None, help='Threat actor info JSON (optional)')
@click.option('--template', type=click.Path(), default=None, help='Jinja2 template for HTML dashboard (optional)')
def report(case_dir, output_html, pii_csv, yara_csv, clamav_csv, victim_info, ta_info, template):
    """
    Generate HTML dashboard and summary reports for the case, including enrichment from ransomware.live if available.
    """
    config = load_case_config(case_dir)
    # Use case.json as default for victim and ta_info if not provided
    victim_info_obj = None
    ta_info_obj = None
    if not victim_info:
        victim_info_obj = config.get('victim')
    if not ta_info:
        ta_info_obj = config.get('ta_group')
    reports_dir = os.path.join(case_dir, 'reports')
    enrichment_path = os.path.join(reports_dir, 'enrichment.json')
    # Load enrichment if present
    enrichment = None
    group_info = None
    cert_contacts = None
    yara_rules_used = None
    if os.path.exists(enrichment_path):
        with open(enrichment_path, 'r', encoding='utf-8') as f:
            enrichment = json.load(f)
        group_info = enrichment.get('group')
        cert_contacts = enrichment.get('cert_contacts')
        yara_rules_used = bool(enrichment.get('yara_rules') and 'rule ' in enrichment.get('yara_rules'))
    # Pass enrichment to reporting
    generate_html_dashboard(
        output_html=output_html or os.path.join(reports_dir, 'dashboard.html'),
        download_stats=summarize_downloads(inventory.get_all_downloads(case_dir)),
        pii_stats=summarize_pii_phi_pci([] if not pii_csv or not os.path.exists(pii_csv) else list(csv.DictReader(open(pii_csv, encoding='utf-8')))),
        yara_summary=yara_summary_report(yara_csv) if yara_csv and os.path.exists(yara_csv) else {},
        clamav_summary=None,  # Add clamav summary if needed
        cross_refs=cross_reference_sensitive_files(yara_csv, pii_csv) if yara_csv and pii_csv and os.path.exists(yara_csv) and os.path.exists(pii_csv) else [],
        opsec_reminder=None,
        victim_info=victim_info_obj,
        ta_info=ta_info_obj,
        template_path=template,
        multi_pii_files=None,
        cert_contacts=cert_contacts,
        enrichment_path=enrichment_path,
        yara_rules_used=yara_rules_used
    )

@cli.command()
def opsec_check():
    """
    Perform an OpSec check: verify TOR is running, print OpSec reminders, and warn about risky settings.
    """
    click.echo("\n=== TA-DLA OpSec Check ===\n")
    click.echo("OpSec Reminders:")
    click.echo("- Always use TOR/SOCKS5 for .onion sites and all downloads.")
    click.echo("- Never upload case data, logs, or findings to public repositories or cloud services.")
    click.echo("- Use an air-gapped or isolated environment for analysis.")
    click.echo("- Be cautious with MEGA/FTP downloads: ensure proxying is enforced.")
    click.echo("- Review all findings for sensitive data before sharing.")
    click.echo("")
    click.echo("Checking TOR/SOCKS5 proxy...")
    if tor_health_check():
        click.echo("[OK] TOR is running and proxying traffic.")
    else:
        click.echo("[WARNING] TOR is NOT running or not proxying traffic! Ensure the TOR service is active and listening on 127.0.0.1:9050.")
    click.echo("")
    click.echo("For more OpSec guidance, see the README and documentation.")

def url_is_http(url):
    return url.lower().startswith('http://') or url.lower().startswith('https://')

@cli.command()
@click.option('--case-dir', required=True, type=click.Path(), help='Path to the case directory')
def clear_failed_downloads(case_dir):
    """Remove all failed downloads from the inventory DB."""
    db_path = inventory.get_db_path(case_dir)
    import sqlite3
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM downloads WHERE status='failed'")
        conn.commit()
    click.echo("All failed downloads have been removed from the inventory DB.")

@cli.command()
@click.option('--case-dir', required=True, type=click.Path(), help='Path to the case directory')
def retry_failed_downloads(case_dir):
    """Set all failed downloads back to pending in the inventory DB."""
    db_path = inventory.get_db_path(case_dir)
    import sqlite3
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute("UPDATE downloads SET status='pending', error=NULL WHERE status='failed'")
        conn.commit()
    click.echo("All failed downloads have been set to pending.")

@cli.command()
@click.option('--case-dir', required=True, type=click.Path(), help='Path to the case directory')
@click.option('--output', required=True, type=click.Path(), help='Path to output CSV or JSON file')
@click.option('--format', type=click.Choice(['csv', 'json']), default='csv', help='Export format (csv or json)')
def export_inventory(case_dir, output, format):
    """Export the downloads table to CSV or JSON."""
    downloads = inventory.get_downloads_by_status(case_dir, 'pending') + \
                inventory.get_downloads_by_status(case_dir, 'complete') + \
                inventory.get_downloads_by_status(case_dir, 'failed') + \
                inventory.get_downloads_by_status(case_dir, 'skipped') + \
                inventory.get_downloads_by_status(case_dir, 'corrupt') + \
                inventory.get_downloads_by_status(case_dir, 'password-protected') + \
                inventory.get_downloads_by_status(case_dir, 'partial') + \
                inventory.get_downloads_by_status(case_dir, 'in-progress')
    if format == 'csv':
        import csv as _csv
        if downloads:
            with open(output, 'w', newline='', encoding='utf-8') as f:
                writer = _csv.DictWriter(f, fieldnames=downloads[0].keys())
                writer.writeheader()
                writer.writerows(downloads)
        click.echo(f"Exported {len(downloads)} records to {output} (CSV).")
    else:
        import json as _json
        with open(output, 'w', encoding='utf-8') as f:
            _json.dump(downloads, f, indent=2)
        click.echo(f"Exported {len(downloads)} records to {output} (JSON).")

@cli.command()
@click.option('--case-dir', required=True, type=click.Path(), help='Path to the new case directory')
def init_case(case_dir):
    """
    Initialize a new TA-DLA case: prompt for metadata, create directories, and save case.json.
    Uses ransomware.live enrichment if available, but allows manual entry if offline.
    """
    import click
    from ta_dla.enrichment import RansomwareLiveEnrichment
    cm = CaseManager(case_dir)
    cm.ensure_structure()
    try:
        enrichment_client = RansomwareLiveEnrichment()
    except Exception:
        enrichment_client = None
    metadata = CaseManager.prompt_for_case_metadata(enrichment_client=enrichment_client)
    cm.save_config(metadata)
    click.echo(f"\nCase initialized at: {case_dir}")
    click.echo("Case metadata:")
    for k, v in metadata.items():
        click.echo(f"  {k}: {v if not isinstance(v, dict) else v.get('name', v)}")

if __name__ == '__main__':
    cli() 