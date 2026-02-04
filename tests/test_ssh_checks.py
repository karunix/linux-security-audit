from audit.checks import check_permit_root_login
from audit.models import Severity


def test_permit_root_login_not_set(tmp_path):
    """
    If PermitRootLogin is not present in sshd_config,
    the audit should return a MEDIUM severity finding.
    """

    sshd_config = tmp_path / "sshd_config"
    sshd_config.write_text(
        """
# Some comment
Port 22
"""
    )

    findings = check_permit_root_login(sshd_config)

    assert len(findings) == 1
    finding = findings[0]

    assert finding.severity == Severity.MEDIUM
    assert "PermitRootLogin" in finding.observation
