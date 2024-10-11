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

from src.analyzers.sshdconfig_analyzer import analyse_config


class Utils(unittest.TestCase):
    """Test the analyzer functions."""

    def test_sshdconfig_empty(self):
        """Test empty sshd config."""
        result = analyse_config("")
        report = "No issues found in SSH configuration"
        expected = (report, 80, report)
        self.assertTupleEqual(result, expected)

    def test_sshdconfig_weak(self):
        """Test sshd config with weak settings."""
        sshd_config_weak = """PermitRootLogin yes
        PasswordAuthentication yes
        PermitEmptyPasswords yes"""
        sshd_config_report_expected = (
            """#### **Insecure SSH configuration found.**\n"""
            """* Root login enabled.\n"""
            """* Password authentication enabled.\n"""
            """* Empty passwords permitted."""
        )
        sshd_config_summary_expected = "Insecure SSH configuration found."
        result = analyse_config(sshd_config_weak)
        expected = (sshd_config_report_expected, 20, sshd_config_summary_expected)
        self.assertTupleEqual(result, expected)


if __name__ == "__main__":
    unittest.main()
