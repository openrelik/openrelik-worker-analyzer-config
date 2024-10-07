import re

# TODO(hacktobeer) - Fix when added to common lib
# from openrelik_worker_common.reporting import Priority
from .openrelik_worker_common import reporting as fmt


def analyse_config(config):
    """Extract security related configs from Jenkins configuration files.

    Args:
      config (str): configuration file content.

    Returns:
      Tuple(
        report_text(str): The report data
        report_priority(int): The priority of the report (0 - 100)
        summary(str): A summary of the report (used for task status)
      )
    """
    version = None
    credentials = []

    extracted_version = _extract_jenkins_version(config)
    if extracted_version:
        version = extracted_version

    extracted_credentials = _extract_jenkins_credentials(config)
    credentials.extend(extracted_credentials)

    (report, priority, summary) = analyze_jenkins(version, credentials, timeout=None)

    return (report, priority, summary)


def _extract_jenkins_version(config):
    """Extract version from Jenkins configuration files.

    Args:
      config (str): configuration file content.

    Returns:
      str: The version of Jenkins.
    """
    version = None
    version_re = re.compile("<version>(.*)</version>")
    version_match = re.search(version_re, config)

    if version_match:
        version = version_match.group(1)

    return version


def _extract_jenkins_credentials(config):
    """Extract credentials from Jenkins configuration files.

    Args:
      config (str): configuration file content.

    Returns:
      list: of tuples with username and password hash.
    """
    credentials = []
    password_hash_re = re.compile("<passwordHash>#jbcrypt:(.*)</passwordHash>")
    username_re = re.compile("<fullName>(.*)</fullName>")

    password_hash_match = re.search(password_hash_re, config)
    username_match = re.search(username_re, config)

    if username_match and password_hash_match:
        username = username_match.group(1)
        password_hash = password_hash_match.group(1)
        credentials.append((username, password_hash))

    return credentials


def analyze_jenkins(version, credentials, timeout=300):
    """Analyses a Jenkins configuration.

    Args:
      version (str): Version of Jenkins.
      credentials (list): of tuples with username and password hash.
      timeout (int): Time in seconds to run password bruteforcing.

    Returns:
      Tuple(
        report_text(str): The report data
        report_priority(int): The priority of the report (0 - 100)
        summary(str): A summary of the report (used for task status)
      )
    """
    report = []
    summary = ""
    priority = fmt.Priority.LOW
    credentials_registry = {hash: username for username, hash in credentials}

    # '3200' is "bcrypt $2*$, Blowfish (Unix)"
    # weak_passwords = bruteforce_password_hashes(
    #     credentials_registry.keys(), tmp_dir=None, timeout=timeout, extra_args="-m 3200"
    # )
    weak_passwords = []

    if not version:
        version = "Unknown"
    report.append(fmt.bullet(f"Jenkins version: {version:s}"))

    if weak_passwords:
        priority = fmt.Priority.CRITICAL
        summary = "Jenkins analysis found potential issues"
        report.insert(0, fmt.heading4(fmt.bold(summary)))
        line = f"{len(weak_passwords):n} weak password(s) found:"
        report.append(fmt.bullet(fmt.bold(line)))
        for password_hash, plaintext in weak_passwords:
            line = 'User "{0:s}" with password "{1:s}"'.format(
                credentials_registry.get(password_hash), plaintext
            )
            report.append(fmt.bullet(line, level=2))
    elif credentials_registry or version != "Unknown":
        summary = (
            f"Jenkins version {version} found with {len(credentials_registry)} credentials, but no issues "
            "detected"
        )
        report.insert(0, fmt.heading4(summary))
        priority = fmt.Priority.MEDIUM
    else:
        summary = "No Jenkins instance found"
        report.insert(0, fmt.heading4(summary))

    report = "\n".join(report)
    return (report, priority, summary)
