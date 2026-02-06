from audit.models import Finding, Severity
from audit.utils import exit_code_from_findings


def test_exit_code_info_only():
    findings = [
        Finding("scope", "obs", Severity.INFO, "exp", "rec")
    ]
    assert exit_code_from_findings(findings) == 0


def test_exit_code_medium():
    findings = [
        Finding("scope", "obs", Severity.INFO, "exp", "rec"),
        Finding("scope", "obs", Severity.MEDIUM, "exp", "rec"),
    ]
    assert exit_code_from_findings(findings) == 2


def test_exit_code_high():
    findings = [
        Finding("scope", "obs", Severity.HIGH, "exp", "rec"),
    ]
    assert exit_code_from_findings(findings) == 3
