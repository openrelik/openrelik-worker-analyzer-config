import re

# TODO(hacktobeer) - Fix when added to common lib
# # from openrelik_worker_common.reporting import Priority
from .openrelik_worker_common import reporting as fmt


def analyse_config(config):
    """Analyses an SSH configuration.

    Args:
      config (str): configuration file content.

    Returns:
      Tuple(
        report_text(str): The report data
        report_priority(int): The priority of the report (0 - 100)
        summary(str): A summary of the report (used for task status)
      )
    """
    findings = []
    permit_root_login_re = re.compile(
        r"^\s*PermitRootLogin\s*(yes|prohibit-password|without-password)",
        re.IGNORECASE | re.MULTILINE,
    )
    password_authentication_re = re.compile(
        r'^\s*PasswordAuthentication[\s"]*yes', re.IGNORECASE | re.MULTILINE
    )
    permit_empty_passwords_re = re.compile(
        r'^\s*PermitEmptyPasswords[\s"]*Yes', re.IGNORECASE | re.MULTILINE
    )

    if re.search(permit_root_login_re, config):
        findings.append(fmt.bullet("Root login enabled."))

    if re.search(password_authentication_re, config):
        findings.append(fmt.bullet("Password authentication enabled."))

    if re.search(permit_empty_passwords_re, config):
        findings.append(fmt.bullet("Empty passwords permitted."))

    if findings:
        summary = "Insecure SSH configuration found."
        findings.insert(0, fmt.heading4(fmt.bold(summary)))
        report = "\n".join(findings)
        return (report, fmt.Priority.HIGH, summary)

    report = "No issues found in SSH configuration"
    return (report, fmt.Priority.LOW, report)
