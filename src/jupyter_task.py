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

from .analyzers.jupyter_analyzer import analyze_config
from .factory import task_factory

# Task name used to register and route the task to the correct queue.
TASK_NAME = "openrelik-worker-analyzer-config.tasks.jupyter_config_analyzer"
TASK_NAME_SHORT = "jupyter_config_analyzer"

COMPATIBLE_INPUTS = {
    "data_types": ["*:artifact:JupyterConfigFile"],
    "mime_types": [],
    "filenames": ["jupyter_notebook_config.py"],
}

# Task metadata for registration in the core system.
TASK_METADATA = {
    "display_name": "Jupyter config analyzer",
    "description": "Analyzes a Jupyter Notebook configuration file for weak settings.",
    "compatible_inputs": COMPATIBLE_INPUTS,
}

task_factory(
    task_name=TASK_NAME,
    task_name_short=TASK_NAME_SHORT,
    compatible_inputs=COMPATIBLE_INPUTS,
    task_metadata=TASK_METADATA,
    analysis_function=analyze_config,
    task_report_function=None,
)
