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

from openrelik_worker_common import reporting as rep


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
    num_misconfigs = 0
    report = rep.TaskReport("SSHD Config Analyzer")
    summary_section = report.add_section()
    section = report.add_section()
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
        section.add_bullet("Root login enabled.")
        num_misconfigs += 1

    if re.search(password_authentication_re, config):
        section.add_bullet(("Password authentication enabled."))
        num_misconfigs += 1

    if re.search(permit_empty_passwords_re, config):
        section.add_bullet("Empty passwords permitted.")
        num_misconfigs += 1

    if num_misconfigs > 0:
        report.summary = (
            f"Insecure SSHD configuration found. Total misconfigs: {num_misconfigs}"
        )
        summary_section.add_paragraph(report.summary)
        return (report.to_markdown(), rep.Priority.HIGH, report.summary)

    report.summary = "No issues found in SSH configuration"
    summary_section.add_paragraph(report.summary)
    return (report.to_markdown(), rep.Priority.LOW, report.summary)
