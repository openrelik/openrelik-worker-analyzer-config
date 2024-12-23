# -*- coding: utf-8 -*-
# Copyright 2024 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re

from openrelik_worker_common.reporting import Report, Priority

def analyze_config(file_content: str) -> Report:
    """Analyze a Tomcat file.

    - Search for clear text password entries in user configuration file
    - Search for .war deployment
    - Search for management control panel activity

    Args:
      config (str): Tomcat file content.
    Returns:
      report (Report): The analysis report.
    """
    num_misconfigs = 0
    config = file_content

    # Create a report with two sections.
    report = Report("Tomcat Config Analyzer")
    details_section = report.add_section()
    summary_section = report.add_section()

    tomcat_deploy_re = re.compile(
        "(^.*Deploying web application archive.*)", re.MULTILINE)
    tomcat_manager_activity_re = re.compile(
        "(^.*POST /manager/html/upload.*)", re.MULTILINE)
    tomcat_readonly_re = re.compile(
        "<param-name>readonly</param-name>",
        re.IGNORECASE
    )
    tomcat_readonly_false_re = re.compile(
        r"<param-name>readonly</param-name>\s*<param-value>false</param-value>",
        re.IGNORECASE
    )
    tomcat_user_passwords_re = re.compile("(^.*password.*)", re.MULTILINE)


    for password_entry in re.findall(tomcat_user_passwords_re, config):
        num_misconfigs += 1
        details_section.add_bullet("tomcat user: " + password_entry.strip())

    for deployment_entry in re.findall(tomcat_deploy_re, config):
        num_misconfigs += 1
        details_section.add_bullet(
            "Tomcat App Deployed: " + deployment_entry.strip())

    for mgmt_entry in re.findall(tomcat_manager_activity_re, config):
        num_misconfigs += 1
        details_section.add_bullet("Tomcat Management: " + mgmt_entry.strip())

    if re.search(tomcat_readonly_re, config):
        if re.search(tomcat_readonly_false_re, config):
            num_misconfigs += 1
            details_section.add_bullet("Tomcat servlet IS NOT read-only")

    if num_misconfigs > 0:
        report.summary = (
            f"Tomcat analysis found misconfigs. Total: {num_misconfigs}"
        )
        report.priority = Priority.HIGH
        summary_section.add_paragraph(report.summary)
        return report

    report.summary = "No issues found in Tomcat configuration"
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