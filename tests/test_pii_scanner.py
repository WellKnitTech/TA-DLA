import os
import tempfile
import pytest
from ta_dla.analyzer.pii_scanner import is_text_file, scan_file_for_patterns, scan_directory_for_pii_phi_pci

def write_temp_file(content):
    fd, path = tempfile.mkstemp()
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(content)
    return path

def test_is_text_file():
    text_path = write_temp_file("hello world\n")
    bin_path = write_temp_file("\x00\x01\x02\x03")
    assert is_text_file(text_path)
    assert not is_text_file(bin_path)
    os.remove(text_path)
    os.remove(bin_path)

def test_email_detection():
    path = write_temp_file("Contact: alice@example.com\n")
    findings = scan_file_for_patterns(path)
    assert any(f['pattern'] == 'EMAIL' for f in findings)
    os.remove(path)

def test_ssn_detection():
    path = write_temp_file("SSN: 123-45-6789\n")
    findings = scan_file_for_patterns(path)
    assert any(f['pattern'] == 'SSN' for f in findings)
    os.remove(path)

def test_phone_detection():
    path = write_temp_file("Call 555-123-4567 now\n")
    findings = scan_file_for_patterns(path)
    assert any(f['pattern'] == 'PHONE' for f in findings)
    os.remove(path)

def test_iban_detection():
    path = write_temp_file("IBAN: GB82WEST12345698765432\n")
    findings = scan_file_for_patterns(path)
    assert any(f['pattern'] == 'IBAN' for f in findings)
    os.remove(path)

def test_passport_detection():
    path = write_temp_file("Passport: 123456789\n")
    findings = scan_file_for_patterns(path)
    assert any(f['pattern'] == 'PASSPORT' for f in findings)
    os.remove(path)

def test_npi_detection():
    path = write_temp_file("NPI: 1234567890\n")
    findings = scan_file_for_patterns(path)
    assert any(f['pattern'] == 'NPI' for f in findings)
    os.remove(path)

def test_mrn_detection():
    path = write_temp_file("MRN: 1234567\n")
    findings = scan_file_for_patterns(path)
    assert any(f['pattern'] == 'MRN' for f in findings)
    os.remove(path)

def test_credit_card_detection():
    path = write_temp_file("Card: 4111 1111 1111 1111\n")
    findings = scan_file_for_patterns(path)
    assert any(f['pattern'] == 'CREDIT_CARD' for f in findings)
    os.remove(path)

def test_cvv_detection():
    path = write_temp_file("CVV: 123\n")
    findings = scan_file_for_patterns(path)
    assert any(f['pattern'] == 'CVV' for f in findings)
    os.remove(path)

def test_aws_key_detection():
    path = write_temp_file("AKIA1234567890ABCDEF\n")
    findings = scan_file_for_patterns(path)
    assert any(f['pattern'] == 'AWS_KEY' for f in findings)
    os.remove(path)

def test_jwt_detection():
    path = write_temp_file("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n")
    findings = scan_file_for_patterns(path)
    assert any(f['pattern'] == 'JWT' for f in findings)
    os.remove(path)

def test_private_key_detection():
    path = write_temp_file("-----BEGIN PRIVATE KEY-----\nMIIBVwIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA\n-----END PRIVATE KEY-----\n")
    findings = scan_file_for_patterns(path)
    assert any(f['pattern'] == 'PRIVATE_KEY' for f in findings)
    os.remove(path)

def test_entropy_detection():
    # This string is high entropy and long
    path = write_temp_file("A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0\n")
    findings = scan_file_for_patterns(path)
    assert any(f['type'] == 'ENTROPY' for f in findings)
    os.remove(path)

def test_scan_directory(tmp_path):
    file1 = tmp_path / "a.txt"
    file2 = tmp_path / "b.txt"
    file1.write_text("alice@example.com\n4111 1111 1111 1111\n")
    file2.write_text("SSN: 123-45-6789\n")
    count = scan_directory_for_pii_phi_pci(str(tmp_path))
    assert count >= 3 