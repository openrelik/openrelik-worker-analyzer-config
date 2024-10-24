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
import unittest

from src.analyzers.jupyter_analyzer import analyze_config
from openrelik_worker_common.reporting import Priority, TaskReport


class Utils(unittest.TestCase):
    """Test the analyzer functions."""

    def test_analyse_config(self):
        """Test Jupyter Notebook config."""
        config = (
            """c.NotebookApp.disable_check_xsrf = True\n"""
            """c.NotebookApp.allow_root = True\n"""
            """c.NotebookApp.password_required = False\n"""
            """c.NotebookApp.allow_remote_access = True\n"""
        )

        config_report_expected = (
            """# Jupyter Config Analyzer\n"""
            """\n\n"""
            """Insecure Jupyter Notebook configuration found. Total misconfigs: 4\n"""
            """\n"""
            """* XSRF protection is disabled.\n"""
            """* Juypter Notebook allowed to run as root.\n"""
            """* Password is not required to access this Jupyter Notebook.\n"""
            """* Remote access is enabled on this Jupyter Notebook."""
        )
        config_summary_expected = (
            "Insecure Jupyter Notebook configuration found. Total misconfigs: 4"
        )

        result = analyze_config(config)
        self.assertIsInstance(result, TaskReport)
        self.assertEqual(result.priority, Priority.HIGH)
        self.assertEqual(result.summary, config_summary_expected)
        self.assertEqual(result.to_markdown(), config_report_expected)


if __name__ == "__main__":
    unittest.main()
