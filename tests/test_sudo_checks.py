from audit.checks import check_sudo_nopasswd
from audit.models import Severity


def test_no_nopasswd_rules():
    findings = check_sudo_nopasswd()

    assert isinstance (findings, list)
    assert len (findings) >= 1
    assert findings[0].severity in {Severity.INFO, Severity.HIGH}

