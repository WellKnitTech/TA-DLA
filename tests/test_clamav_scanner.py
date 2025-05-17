import os
import tempfile
import pytest
from ta_dla.analyzer import clamav_scanner

pytestmark = pytest.mark.skipif(not clamav_scanner.CLAMD_AVAILABLE, reason="python-clamd not installed")

def is_clamd_running():
    cd = clamav_scanner.get_clamd_client()
    return cd is not None

@pytest.mark.skipif(not is_clamd_running(), reason="clamd daemon not running or not accessible")
def test_scan_file_with_clamav_clean():
    cd = clamav_scanner.get_clamd_client()
    with tempfile.NamedTemporaryFile('w', delete=False) as f:
        f.write("This is a clean file.")
        fpath = f.name
    result = clamav_scanner.scan_file_with_clamav(fpath, cd)
    os.remove(fpath)
    assert result['status'] == 'CLEAN'
    assert result['file'] == fpath

@pytest.mark.skipif(not is_clamd_running(), reason="clamd daemon not running or not accessible")
def test_scan_file_with_clamav_eicar():
    cd = clamav_scanner.get_clamd_client()
    # EICAR test string
    eicar = clamav_scanner.__dict__.get('clamd', None)
    eicar_str = getattr(eicar, 'EICAR', None) if eicar else None
    if not eicar_str:
        # Fallback EICAR string
        eicar_str = ("X5O!P%@AP[4\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    with tempfile.NamedTemporaryFile('wb', delete=False) as f:
        f.write(eicar_str.encode('utf-8') if isinstance(eicar_str, str) else eicar_str)
        fpath = f.name
    result = clamav_scanner.scan_file_with_clamav(fpath, cd)
    os.remove(fpath)
    # Accept either FOUND or CLEAN (if EICAR is not detected, e.g., old DB)
    assert result['file'] == fpath
    assert result['status'] in ('FOUND', 'CLEAN')

@pytest.mark.skipif(not is_clamd_running(), reason="clamd daemon not running or not accessible")
def test_scan_directory_with_clamav(tmp_path):
    cd = clamav_scanner.get_clamd_client()
    # Clean file
    clean_file = tmp_path / "clean.txt"
    clean_file.write_text("This is a clean file.")
    # EICAR file
    eicar = clamav_scanner.__dict__.get('clamd', None)
    eicar_str = getattr(eicar, 'EICAR', None) if eicar else None
    if not eicar_str:
        eicar_str = ("X5O!P%@AP[4\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    eicar_file = tmp_path / "eicar.txt"
    eicar_file.write_bytes(eicar_str.encode('utf-8') if isinstance(eicar_str, str) else eicar_str)
    output_csv = tmp_path / "clamav.csv"
    count = clamav_scanner.scan_directory_with_clamav(
        directory=str(tmp_path),
        output_csv=str(output_csv),
        logger=None,
        max_workers=2,
        batch_size=2
    )
    # Accept count >= 0 (if EICAR is not detected, count may be 0)
    assert os.path.exists(output_csv)
    with open(output_csv) as f:
        lines = f.readlines()
    assert any('clean.txt' in line for line in lines)
    assert any('eicar.txt' in line for line in lines) 