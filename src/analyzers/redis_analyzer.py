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

from openrelik_worker_common.reporting import Report, Priority


def analyze_config(file_content: str) -> Report:
    """Analyzes a Redis configuration.

    Args:
      file_content (str): configuration file content.

    Returns:
        report (Report): The analysis report.
    """
    num_misconfigs = 0
    config = file_content

    # Create a report with two sections.
    report = Report("Redis Config Analyzer")
    summary_section = report.add_section()
    details_section = report.add_section()

    bind_everywhere_re = re.compile(
        r'^\s*bind[\s"]*0\.0\.0\.0', re.IGNORECASE | re.MULTILINE)
    default_port_re = re.compile(r"port\s+6379\b", re.IGNORECASE)
    missing_logs_re = re.compile(r'^logfile\s+"[^"]+"$', re.MULTILINE)

    if re.search(bind_everywhere_re, config):
      num_misconfigs += 1
      details_section.add_bullet("Redis listening on every IP")

    if re.search(default_port_re, config):
      num_misconfigs += 1
      details_section.add_bullet("Redis configured with default port (6379)")

    if not re.search(missing_logs_re, config):
      num_misconfigs += 1
      details_section.add_bullet("Log destination not configured")

    if num_misconfigs > 0:
        report.summary = (
            f"Insecure Redis configuration found. Total misconfigs: {num_misconfigs}"
        )
        report.priority = Priority.HIGH
        summary_section.add_paragraph(report.summary)
        return report

    report.summary = "No issues found in Redis configuration"
    report.priority = Priority.LOW
    summary_section.add_paragraph(report.summary)
    return report


def create_task_report(file_reports: list = []):
    """Creates a task report from a list of file reports.

    Args:
        file_reports (list): A list of file reports.

    Returns:
        report (Report): The task report.
    """
    pass
