import os
import logging
import zipfile
import tarfile
import rarfile
import py7zr
import gzip
import bz2
from typing import Optional, List, Union
from ta_dla.utils import get_case_logger
import ta_dla.db.inventory as inventory

def extract_all_archives(
    input_dir: str,
    output_dir: str,
    case_dir: Optional[str] = None,
    logger: Optional[logging.Logger] = None,
    depth: int = 0,
    max_depth: int = 5,
    passwords: Optional[Union[str, List[str]]] = None
):
    """
    Recursively extract all supported archives in input_dir to output_dir.
    Supports .zip, .7z, .rar, .tar, .tar.gz, .tgz, .gz, .bz2. Handles nested archives up to max_depth.
    Tries provided passwords for encrypted archives.
    Args:
        input_dir: Directory containing archives to extract.
        output_dir: Directory to extract files into.
        case_dir: Path to the case directory (for logger if not provided).
        logger: Logger instance for this case.
        depth: Current recursion depth (for nested archives).
        max_depth: Maximum recursion depth for nested extraction.
        passwords: Password or list of passwords to try for encrypted archives.
    """
    if logger is None and case_dir:
        logger = get_case_logger(case_dir)
    if depth > max_depth:
        if logger:
            logger.warning(f"Max extraction depth {max_depth} reached at {input_dir}")
        return
    if passwords is None:
        passwords = []
    elif isinstance(passwords, str):
        passwords = [passwords]
    for root, dirs, files in os.walk(input_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            rel_path = os.path.relpath(fpath, input_dir)
            out_path = os.path.join(output_dir, rel_path)
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            try:
                # ZIP
                if zipfile.is_zipfile(fpath):
                    with zipfile.ZipFile(fpath) as zf:
                        if zf.needs_password():
                            extracted = False
                            for pw in passwords:
                                try:
                                    zf.extractall(os.path.dirname(out_path), pwd=pw.encode())
                                    logger.info(f"Extracted password-protected ZIP: {fpath} with password: {pw}")
                                    extracted = True
                                    break
                                except RuntimeError:
                                    continue
                            if not extracted:
                                logger.error(f"Failed to extract password-protected ZIP: {fpath}")
                                continue
                        else:
                            zf.extractall(os.path.dirname(out_path))
                            logger.info(f"Extracted ZIP: {fpath}")
                        extract_all_archives(os.path.dirname(out_path), output_dir, case_dir, logger, depth+1, max_depth, passwords)
                        inventory.add_extracted_file(case_dir, out_path, fpath, depth)
                # RAR
                elif rarfile.is_rarfile(fpath):
                    with rarfile.RarFile(fpath) as rf:
                        if rf.needs_password():
                            extracted = False
                            for pw in passwords:
                                try:
                                    rf.extractall(os.path.dirname(out_path), pwd=pw)
                                    logger.info(f"Extracted password-protected RAR: {fpath} with password: {pw}")
                                    extracted = True
                                    break
                                except rarfile.BadRarFile:
                                    continue
                            if not extracted:
                                logger.error(f"Failed to extract password-protected RAR: {fpath}")
                                continue
                        else:
                            rf.extractall(os.path.dirname(out_path))
                            logger.info(f"Extracted RAR: {fpath}")
                        extract_all_archives(os.path.dirname(out_path), output_dir, case_dir, logger, depth+1, max_depth, passwords)
                        inventory.add_extracted_file(case_dir, out_path, fpath, depth)
                # 7z
                elif fpath.endswith('.7z'):
                    extracted = False
                    for pw in ([None] + passwords):
                        try:
                            with py7zr.SevenZipFile(fpath, mode='r', password=pw) as szf:
                                szf.extractall(path=os.path.dirname(out_path))
                                logger.info(f"Extracted 7z: {fpath} with password: {pw if pw else 'None'}")
                                extracted = True
                                break
                        except (py7zr.exceptions.PasswordRequired, py7zr.exceptions.InvalidPassword):
                            continue
                        except Exception as e:
                            logger.error(f"7z extraction error for {fpath}: {e}")
                            break
                    if not extracted:
                        logger.error(f"Failed to extract 7z: {fpath}")
                        continue
                    extract_all_archives(os.path.dirname(out_path), output_dir, case_dir, logger, depth+1, max_depth, passwords)
                    inventory.add_extracted_file(case_dir, out_path, fpath, depth)
                # TAR
                elif tarfile.is_tarfile(fpath):
                    with tarfile.open(fpath) as tf:
                        tf.extractall(os.path.dirname(out_path))
                        logger.info(f"Extracted TAR: {fpath}")
                        extract_all_archives(os.path.dirname(out_path), output_dir, case_dir, logger, depth+1, max_depth, passwords)
                        inventory.add_extracted_file(case_dir, out_path, fpath, depth)
                # GZ (single file)
                elif fpath.endswith('.gz') and not tarfile.is_tarfile(fpath):
                    try:
                        with gzip.open(fpath, 'rb') as gz_in, open(out_path[:-3], 'wb') as out_f:
                            out_f.write(gz_in.read())
                        logger.info(f"Extracted GZ: {fpath}")
                    except Exception as e:
                        logger.error(f"GZ extraction failed for {fpath}: {e}")
                    inventory.add_extracted_file(case_dir, out_path, fpath, depth)
                # BZ2 (single file)
                elif fpath.endswith('.bz2'):
                    try:
                        with bz2.open(fpath, 'rb') as bz_in, open(out_path[:-4], 'wb') as out_f:
                            out_f.write(bz_in.read())
                        logger.info(f"Extracted BZ2: {fpath}")
                    except Exception as e:
                        logger.error(f"BZ2 extraction failed for {fpath}: {e}")
                    inventory.add_extracted_file(case_dir, out_path, fpath, depth)
                # TODO: Add more formats as needed
            except Exception as e:
                if logger:
                    logger.error(f"Extraction failed for {fpath}: {e}") 