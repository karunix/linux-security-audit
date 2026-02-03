from audit.checks import (
    check_permit_root_login,
    check_ssh_protocol_version,
    check_password_authentication,
    check_sudo_nopasswd,
)
from audit.models import Severity


def run_audit():
    findings = []

    checks = [
        check_permit_root_login,
        check_ssh_protocol_version,
        check_password_authentication,
        check_sudo_nopasswd,
    ]

    for check in checks:
        result = check()
        if isinstance(result, list):
            findings.extend(result)
        else:
            findings.append(result)

    return findings


def print_report(findings):
    print("Linux Security Audit Report")
    print("=" * 30)

    for finding in findings:
        print(f"\nScope: {finding.scope}")
        print(f"Observation: {finding.observation}")
        print(f"Severity: {finding.severity.value}")
        print("Explanation:")
        print(f"  {finding.explanation}")
        print("Recommendation:")
        print(f"  {finding.recommendation}")

    print("\nSummary:")
    for severity in Severity:
        count = sum(1 for f in findings if f.severity == severity)
        print(f"  {severity.value}: {count}")


if __name__ == "__main__":
    results = run_audit()
    print_report(results)
