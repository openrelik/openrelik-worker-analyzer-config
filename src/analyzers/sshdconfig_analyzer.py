# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import re

from openrelik_worker_common import reporting as fmt


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
