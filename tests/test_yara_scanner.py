import os
import tempfile
import pytest
import yara
from ta_dla.analyzer.yara_scanner import load_yara_rules, scan_file_with_yara, scan_directory_with_yara

def write_temp_file(content):
    fd, path = tempfile.mkstemp()
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(content)
    return path

def test_load_yara_rules(tmp_path):
    rule_path = tmp_path / "test.yar"
    rule_path.write_text('rule test_rule { condition: true }\n')
    rules = load_yara_rules(str(rule_path))
    assert rules is not None
    assert isinstance(rules, yara.Rules)

def test_scan_file_with_yara(tmp_path):
    # Write a YARA rule that matches any file
    rule_path = tmp_path / "test.yar"
    rule_path.write_text('rule test_rule { condition: true }\n')
    rules = load_yara_rules(str(rule_path))
    # Write a test file
    file_path = tmp_path / "sample.txt"
    file_path.write_text("hello world\n")
    findings = scan_file_with_yara(str(file_path), rules)
    assert any(f['rule'] == 'test_rule' for f in findings)

def test_scan_directory_with_yara(tmp_path):
    # Write a YARA rule that matches any file
    rule_path = tmp_path / "test.yar"
    rule_path.write_text('rule test_rule { condition: true }\n')
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "test.yar").write_text('rule test_rule { condition: true }\n')
    # Write test files
    (tmp_path / "a.txt").write_text("foo\n")
    (tmp_path / "b.txt").write_text("bar\n")
    output_csv = tmp_path / "findings.csv"
    count = scan_directory_with_yara(
        directory=str(tmp_path),
        rulesets=None,  # We'll use a direct rules path for this test
        output_csv=str(output_csv),
        case_dir=None,
        logger=None,
        max_workers=2,
        batch_size=1
    )
    assert count >= 2
    with open(output_csv) as f:
        lines = f.readlines()
    assert any('test_rule' in line for line in lines) 