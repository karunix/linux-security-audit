from pathlib import Path
import os
import glob

from audit.models import Finding, Severity


def check_permit_root_login(
    config_path: Path = Path("/etc/ssh/sshd_config"),
) -> list[Finding]:
    """
    Check whether direct root login over SSH is permitted.
    """

    observed_value = "not set"

    if config_path.exists():
        for line in config_path.read_text().splitlines():
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if line.lower().startswith("permitrootlogin"):
                _, value = line.split(maxsplit=1)
                observed_value = value.lower()
                break

    if observed_value == "yes":
        severity = Severity.HIGH
    elif observed_value in {"prohibit-password", "without-password"}:
        severity = Severity.MEDIUM
    elif observed_value == "no":
        severity = Severity.INFO
    else:
        severity = Severity.MEDIUM

    return [
        Finding(
            scope="SSH configuration",
            observation=f"PermitRootLogin is '{observed_value}'",
            severity=severity,
            explanation=(
                "Allowing direct root login over SSH increases the impact of "
                "credential compromise and removes individual accountability. "
                "Attackers commonly target root access during SSH attacks."
            ),
            recommendation=(
                "Set 'PermitRootLogin no' in sshd_config and require administrators "
                "to authenticate as individual users before escalating privileges."
            ),
        )
    ]


def check_ssh_protocol_version(
    config_path: Path = Path("/etc/ssh/sshd_config"),
) -> list[Finding]:
    """
    Check which SSH protocol versions are permitted.
    """

    observed_value = "not set"

    if config_path.exists():
        for line in config_path.read_text().splitlines():
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if line.lower().startswith("protocol"):
                _, value = line.split(maxsplit=1)
                observed_value = value.replace(" ", "")
                break

    severity = Severity.HIGH if "1" in observed_value else Severity.INFO

    return [
        Finding(
            scope="SSH configuration",
            observation=f"SSH Protocol is '{observed_value}'",
            severity=severity,
            explanation=(
                "SSH protocol version 1 is cryptographically weak and vulnerable "
                "to multiple attacks. Allowing SSHv1 exposes systems to downgrade "
                "and man-in-the-middle risks."
            ),
            recommendation=(
                "Explicitly enforce SSH protocol version 2 by setting "
                "'Protocol 2' in sshd_config and restarting the SSH service."
            ),
        )
    ]


def check_password_authentication(
    config_path: Path = Path("/etc/ssh/sshd_config"),
) -> list[Finding]:
    """
    Check whether password-based SSH authentication is enabled.
    """

    observed_value = "not set"

    if config_path.exists():
        for line in config_path.read_text().splitlines():
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if line.lower().startswith("passwordauthentication"):
                _, value = line.split(maxsplit=1)
                observed_value = value.lower()
                break

    if observed_value == "yes":
        severity = Severity.HIGH
    elif observed_value == "no":
        severity = Severity.INFO
    else:
        severity = Severity.MEDIUM

    return [
        Finding(
            scope="SSH configuration",
            observation=f"PasswordAuthentication is '{observed_value}'",
            severity=severity,
            explanation=(
                "Allowing password-based SSH authentication increases exposure "
                "to brute-force and credential-stuffing attacks, especially on "
                "internet-facing systems."
            ),
            recommendation=(
                "Disable password-based SSH authentication and enforce key-based "
                "authentication by setting 'PasswordAuthentication no' in "
                "sshd_config."
            ),
        )
    ]


def check_sudo_nopasswd() -> list[Finding]:
    """
    Check for sudo rules that allow passwordless privilege escalation.
    """

    sudo_files = ["/etc/sudoers"]
    sudo_files.extend(glob.glob("/etc/sudoers.d/*"))

    findings: list[Finding] = []

    for path in sudo_files:
        if not os.path.isfile(path):
            continue

        try:
            with open(path, "r") as f:
                for line in f:
                    stripped = line.strip()

                    if not stripped or stripped.startswith("#"):
                        continue

                    if "NOPASSWD" in stripped:
                        findings.append(
                            Finding(
                                scope="Sudo configuration",
                                observation=f"NOPASSWD rule found in {path}",
                                severity=Severity.HIGH,
                                explanation=(
                                    "Passwordless sudo rules allow users to gain root privileges "
                                    "without authentication. This significantly increases the "
                                    "impact of any local account compromise and bypasses "
                                    "accountability controls."
                                ),
                                recommendation=(
                                    "Remove NOPASSWD rules unless strictly required for automation. "
                                    "Where necessary, restrict them to dedicated service accounts "
                                    "and specific commands."
                                ),
                            )
                        )
        except PermissionError:
            continue

    if not findings:
        findings.append(
            Finding(
                scope="Sudo configuration",
                observation="No NOPASSWD sudo rules found",
                severity=Severity.INFO,
                explanation=(
                    "All sudo operations require authentication, reducing the risk "
                    "of unchecked privilege escalation."
                ),
                recommendation="Continue enforcing password-protected sudo access.",
            )
        )

    return findings
