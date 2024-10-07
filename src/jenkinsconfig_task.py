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


from openrelik_worker_common.utils import (
    create_output_file,
    get_input_files,
    task_result,
)

from .analyzers.jenkinsconfig_analyzer import analyse_config

from .app import celery

# Task name used to register and route the task to the correct queue.
TASK_NAME = "openrelik-worker-config-analyzer.tasks.jenkins_config_analyser"
SHORT_TASK_NAME = "jenkins_config_analyser"

# Task metadata for registration in the core system.
TASK_METADATA = {
    "display_name": "Jenkins Configuration Analyzer",
    "description": "Analyzes a Jenkins configuration file (JenkinsConfigFile) for weak settings.",
}

EXPECTED_FILENAME = "config.xml"


@celery.task(bind=True, name=TASK_NAME, metadata=TASK_METADATA)
def command(
    self,
    pipe_result: str = None,
    input_files: list = None,
    output_path: str = None,
    workflow_id: str = None,
    task_config: dict = None,
) -> str:
    """Run the Jenkins Configuration Analyzer on input files.

    Args:
        pipe_result: Base64-encoded result from the previous Celery task, if any.
        input_files: List of input file dictionaries (unused if pipe_result exists).
        output_path: Path to the output directory.
        workflow_id: ID of the workflow.
        task_config: User configuration for the task.

    Returns:
        Base64-encoded dictionary containing task results.
    """
    input_files = get_input_files(pipe_result, input_files or [])
    output_files = []

    for input_file in input_files:
        if (
            input_file.get("data_type").lower()
            == f"openrelik.worker.file.{EXPECTED_FILENAME}".lower()
        ):
            output_file = create_output_file(
                output_path,
                filename=f"{input_file.get('filename')}-{SHORT_TASK_NAME}-report",
                file_extension="md",
                data_type=f"openrelik.task.{SHORT_TASK_NAME}.report",
            )

            # Read the input file
            with open(input_file.get("path"), "r", encoding="utf-8") as config_file:
                config = config_file.read()

            (report, priority, summary) = analyse_config(config)

            with open(output_file.path, "w", encoding="utf-8") as file1:
                file1.write(report)

            output_files.append(output_file.to_dict())

    if not output_files:
        raise RuntimeError(
            f"No Jenkins Notebook config file found (filename: {EXPECTED_FILENAME})"
        )

    return task_result(
        output_files=output_files,
        workflow_id=workflow_id,
        command=None,
        meta={"priority": str(priority), "report_summary": str(summary)},
    )
