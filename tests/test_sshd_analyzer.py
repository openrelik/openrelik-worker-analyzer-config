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
from openrelik_worker_common.reporting import Priority, Report

from src.analyzers.sshd_analyzer import analyze_config


class SshdTests(unittest.TestCase):
    """Test the analyzer functions."""

    def test_sshdconfig_empty(self):
        """Test empty sshd config."""
        result = analyze_config("")
        report = (
            """# SSHD Config Analyzer\n"""
            """\n\n"""
            """No issues found in SSH configuration\n\n"""
        )
        summary = "No issues found in SSH configuration"

        self.assertIsInstance(result, Report)
        self.assertEqual(result.priority, Priority.LOW)
        self.assertEqual(result.summary, summary)
        self.assertEqual(result.to_markdown(), report)

    def test_sshdconfig_weak(self):
        """Test sshd config with weak settings."""
        sshd_config_weak = """PermitRootLogin yes
        PasswordAuthentication yes
        PermitEmptyPasswords yes"""
        report_expected = (
            """# SSHD Config Analyzer\n"""
            """\n\n"""
            """Insecure SSHD configuration found. Total misconfigs: 3\n"""
            """\n"""
            """* Root login enabled.\n"""
            """* Password authentication enabled.\n"""
            """* Empty passwords permitted."""
        )
        summary_expected = "Insecure SSHD configuration found. Total misconfigs: 3"

        result = analyze_config(sshd_config_weak)
        self.assertIsInstance(result, Report)
        self.assertEqual(result.priority, Priority.HIGH)
        self.assertEqual(result.summary, summary_expected)
        self.assertEqual(result.to_markdown(), report_expected)


if __name__ == "__main__":
    unittest.main()
