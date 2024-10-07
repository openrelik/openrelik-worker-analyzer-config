# TODO(hacktobeer) - Fix when added to common lib
# from openrelik_worker_common.reporting import Priority
from .openrelik_worker_common import reporting as fmt


def analyse_config(jupyter_config):
    """Extract security related configs from Jupyter configuration files.

    Args:
      jupyter_config (str): configuration file content.

    Returns:
      Tuple(
        report_text(str): The report data
        report_priority(int): The priority of the report (0 - 100)
        summary(str): A summary of the report (used for task status)
      )
    """
    findings = []
    num_misconfigs = 0
    for line in jupyter_config.split("\n"):

        if all(x in line for x in ["disable_check_xsrf", "True"]):
            findings.append(fmt.bullet("XSRF protection is disabled."))
            num_misconfigs += 1
            continue
        if all(x in line for x in ["allow_root", "True"]):
            findings.append(fmt.bullet("Juypter Notebook allowed to run as root."))
            num_misconfigs += 1
            continue
        if "NotebookApp.password" in line:
            if all(x in line for x in ["required", "False"]):
                findings.append(
                    fmt.bullet(
                        "Password is not required to access this Jupyter Notebook."
                    )
                )
                num_misconfigs += 1
                continue
            if "required" not in line:
                password_hash = line.split("=")
                if len(password_hash) > 1:
                    if password_hash[1].strip() == "''":
                        findings.append(
                            fmt.bullet(
                                "There is no password set for this Jupyter Notebook."
                            )
                        )
                        num_misconfigs += 1
        if all(x in line for x in ["allow_remote_access", "True"]):
            findings.append(
                fmt.bullet("Remote access is enabled on this Jupyter Notebook.")
            )
            num_misconfigs += 1
            continue

    if findings:
        summary = f"Insecure Jupyter Notebook configuration found. Total misconfigs: {num_misconfigs}"
        findings.insert(0, fmt.heading4(fmt.bold(summary)))
        report = "\n".join(findings)
        return (report, fmt.Priority.HIGH, summary)

    report = "No issues found in Jupyter Notebook  configuration."
    return (report, fmt.Priority.LOW, report)
