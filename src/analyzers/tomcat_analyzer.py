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

#import os
import re

from openrelik_worker_common.reporting import Report, Priority

#from turbinia.evidence import ReportText
#from turbinia.evidence import EvidenceState as state
#from turbinia.lib import text_formatter as fmt
#from turbinia.workers import TurbiniaTask
#from turbinia.workers import Priority

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
  num_misconfigs = []
  config = file_content

  # Create a report with two sections.
  report = Report("Tomcat Config Analyzer")
  summary_section = report.add_section()
  details_section = report.add_section()

  tomcat_user_passwords_re = re.compile("(^.*password.*)", re.MULTILINE)
  tomcat_deploy_re = re.compile(
      "(^.*Deploying web application archive.*)", re.MULTILINE)
  tomcat_manager_activity_re = re.compile(
      "(^.*POST /manager/html/upload.*)", re.MULTILINE)

  for password_entry in re.findall(tomcat_user_passwords_re, config):
    num_misconfigs += 1
    details_section.add("Tomcat user: " + password_entry.strip())

  for deployment_entry in re.findall(tomcat_deploy_re, config):
    num_misconfigs += 1
    details_section.add("Tomcat App Deployed: " + deployment_entry.strip())

  for mgmt_entry in re.findall(tomcat_manager_activity_re, config):
    num_misconfigs += 1
    details_section.add("Tomcat Management: " + mgmt_entry.strip())

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

#class TomcatAnalysisTask(TurbiniaTask):
#  """Task to analyze a Tomcat file."""
#
#  # Input Evidence is ExportedFileArtifact so does not need to be pre-processed.
#  REQUIRED_STATES = []
#
#  def run(self, evidence, result):
#    """Run the Tomcat analysis worker.
#
#    Args:
#        evidence (Evidence object):  The evidence we will process.
#        result (TurbiniaTaskResult): The object to place task results into.
#
#    Returns:
#        TurbiniaTaskResult object.
#    """
#
#    # Where to store the resulting output file.
#    output_file_name = 'tomcat_analysis.txt'
#    output_file_path = os.path.join(self.output_dir, output_file_name)
#    # Set the output file as the data source for the output evidence.
#    output_evidence = ReportText(source_path=output_file_path)
#
#    # Read the input file
#    with open(evidence.local_path, 'r') as input_file:
#      tomcat_file = input_file.read()
#
#    (report, priority, summary) = self.analyse_tomcat_file(tomcat_file)
#    result.report_priority = priority
#    result.report_data = report
#    output_evidence.text_data = report
#
#    # Write the report to the output file.
#    with open(output_file_path, 'w') as fh:
#      fh.write(output_evidence.text_data.encode('utf-8'))
#
#    # Add the resulting evidence to the result object.
#    result.add_evidence(output_evidence, evidence.config)
#    result.close(self, success=True, status=summary)
#    return result

def create_task_report(file_reports: list = []):
    """Creates a task report from a list of file reports.

    Args:
        file_reports (list): A list of file reports.

    Returns:
        report (Report): The task report.
    """
    pass