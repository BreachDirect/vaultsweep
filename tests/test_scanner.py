from pathlib import Path

import pytest

from vaultsweep.models import Severity
from vaultsweep.reporter import exit_code_for_report
from vaultsweep.scanner import scan_path

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def test_leaky_fixture_finds_secrets():
    report = scan_path(FIXTURES / "leaky-repo")
    assert report.summary["findings"] >= 4
    rule_ids = {f.rule_id for f in report.findings}
    assert "STELLAR-001" in rule_ids
    assert "MNEMONIC-001" in rule_ids
    assert "DEFAULT-001" in rule_ids


def test_clean_fixture_no_high_findings():
    report = scan_path(FIXTURES / "clean-repo")
    high_plus = [
        f for f in report.findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    assert len(high_plus) == 0


def test_fail_on_high_exit_code():
    report = scan_path(FIXTURES / "leaky-repo")
    assert exit_code_for_report(report, Severity.HIGH) == 1
    assert exit_code_for_report(report, None) == 0


def test_scan_missing_target():
    with pytest.raises(FileNotFoundError):
        scan_path("/nonexistent/path")
