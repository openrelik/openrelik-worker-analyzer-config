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

from openrelik_worker_common.reporting import Report, Priority


def analyze_config(file_content: str) -> Report:
    """Extract security related configs from Jupyter configuration files.

    Args:
      file_content (str): configuration file content.

    Returns:
        report (Report): The analysis report.
    """
    num_misconfigs = 0
    config = file_content

    report = Report("Jupyter Config Analyzer")
    summary_section = report.add_section()
    details_section = report.add_section()

    for line in config.split("\n"):
        if all(x in line for x in ["disable_check_xsrf", "True"]):
            details_section.add_bullet("XSRF protection is disabled.")
            num_misconfigs += 1
            continue
        if all(x in line for x in ["allow_root", "True"]):
            details_section.add_bullet("Juypter Notebook allowed to run as root.")
            num_misconfigs += 1
            continue
        if "NotebookApp.password" in line:
            if all(x in line for x in ["required", "False"]):
                details_section.add_bullet(
                    "Password is not required to access this Jupyter Notebook."
                )
                num_misconfigs += 1
                continue
            if "required" not in line:
                password_hash = line.split("=")
                if len(password_hash) > 1:
                    if password_hash[1].strip() == "''":
                        details_section.add_bullet(
                            "There is no password set for this Jupyter Notebook."
                        )
                        num_misconfigs += 1
        if all(x in line for x in ["allow_remote_access", "True"]):
            details_section.add_bullet(
                "Remote access is enabled on this Jupyter Notebook."
            )
            num_misconfigs += 1
            continue

    if num_misconfigs > 0:
        report.priority = Priority.HIGH
        report.summary = f"Insecure Jupyter Notebook configuration found. Total misconfigs: {num_misconfigs}"
        summary_section.add_paragraph(report.summary)
        return report

    report.priority = Priority.LOW
    report.summary = "No issues found in Jupyter Notebook configuration."
    summary_section.add_paragraph(report.summary)
    return report
