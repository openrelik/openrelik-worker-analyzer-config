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

import logging

from typing import Callable

from openrelik_worker_common.file_utils import create_output_file
from openrelik_worker_common.task_utils import create_task_result, get_input_files
from openrelik_worker_common.reporting import serialize_file_report
from openrelik_common import telemetry


from .app import celery

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def task_factory(
    task_name: str,
    task_name_short: str,
    compatible_inputs: dict,
    task_metadata: dict,
    analysis_function: Callable,
    task_report_function: Callable = None,
):
    """
    Factory function to create config analyzer Celery tasks.

    Args:
        task_name: Full task name for registration.
        task_name_short: Short task name for display.
        compatible_inputs: Input file compatibility specifications.
        task_metadata: Metadata for registration in the core system.
        analysis_function: The function to use for analyzing the config file.

    Returns:
        A Celery task function.
    """

    @celery.task(bind=True, name=task_name, metadata=task_metadata)
    def config_analyzer(
        self,
        pipe_result: str = None,
        input_files: list = None,
        output_path: str = None,
        workflow_id: str = None,
        task_config: dict = None,
    ) -> str:
        """Run the configuration analyzer on input files."""

        input_files = get_input_files(
            pipe_result, input_files or [], filter=compatible_inputs
        )
        output_files = []
        file_reports = []
        task_report = None

        telemetry.add_attribute_to_current_span("input_files", input_files)
        telemetry.add_attribute_to_current_span("task_config", task_config)

        telemetry.add_event_to_current_span(
                f"Starting {task_name_short} with {len(input_files)} input files")
        for input_file in input_files:
            report_file = create_output_file(
                output_path,
                display_name=f"{input_file.get('display_name')}-{task_name_short}-report.md",
                data_type=f"worker:openrelik:analyzer-config:{task_name_short}:report",
            )

            logger.info(
                "%s '%s', filename: %s, path: %s",
                task_name_short,
                analysis_function.__name__,
                input_file.get("filename"),
                input_file.get("path"),
            )

            # Use the provided analysis function.
            analysis_report = analysis_function(input_file, task_config)
            if analysis_report:
                file_report = serialize_file_report(
                    input_file, report_file, analysis_report
                )

                with open(report_file.path, "w", encoding="utf-8") as fh:
                    fh.write(analysis_report.to_markdown())

                file_reports.append(file_report)
                output_files.append(report_file.to_dict())
            telemetry.add_event_to_current_span(
                    f"{task_name_short} finished analyzing {input_file.get('path')}")

        if task_report_function:
            task_report = task_report_function(file_reports)

        telemetry.add_event_to_current_span(
                f"Completed {task_name_short} with {len(input_files)} input files")
        return create_task_result(
            output_files=output_files,
            workflow_id=workflow_id,
            file_reports=file_reports,
            task_report=task_report,
        )

    return config_analyzer
