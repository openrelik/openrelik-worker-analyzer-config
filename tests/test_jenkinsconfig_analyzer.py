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
from unittest.mock import patch

from src.analyzers.jenkinsconfig_analyzer import (
    analyse_config,
    _extract_jenkins_credentials,
    _extract_jenkins_version,
)


class Utils(unittest.TestCase):
    """Test the analyzer functions."""

    def test_jenkins_extract_versions(self):
        """Test Jenkins version extraction."""
        config = "<version>1.29.2</version>"
        result = _extract_jenkins_version(config)
        expected = "1.29.2"
        self.assertEqual(result, expected)

    def test_jenkins_extract_credentials(self):
        """Test Jenkins credential extraction."""
        config = (
            """<fullName>Ramses de Beer</fullName>"""
            """<passwordHash>#jbcrypt:$2a$10$razd3L1aXndFfBNHO95aj.IVrFydsxkcQCcLmujmFQzll3hcUrY7S</passwordHash>"""
        )
        result = _extract_jenkins_credentials(config)
        expected = [
            (
                "Ramses de Beer",
                "$2a$10$razd3L1aXndFfBNHO95aj.IVrFydsxkcQCcLmujmFQzll3hcUrY7S",
            )
        ]
        self.assertEqual(result, expected)

    @patch("src.analyzers.jenkinsconfig_analyzer.bruteforce_password_hashes")
    def test_analyze_config(self, bruteforce):
        """Test Jenkins config analysis."""
        bruteforce.return_value = [
            ("$2a$10$razd3L1aXndFfBNHO95aj.IVrFydsxkcQCcLmujmFQzll3hcUrY7S", "test")
        ]
        config = (
            """<version>1.29.2</version>"""
            """<fullName>Ramses de Beer</fullName>"""
            """<passwordHash>#jbcrypt:$2a$10$razd3L1aXndFfBNHO95aj.IVrFydsxkcQCcLmujmFQzll3hcUrY7S</passwordHash>"""
        )
        jenkins_config_report_expected = (
            """#### **Jenkins analysis found potential issues**\n"""
            """* Jenkins version: 1.29.2\n"""
            """* **1 weak password(s) found:**\n"""
            """    * User "Ramses de Beer" with password \"test\""""
        )
        jenkins_config_summary_expected = "Jenkins analysis found potential issues"
        result = analyse_config(config)
        expected = (jenkins_config_report_expected, 10, jenkins_config_summary_expected)
        self.assertTupleEqual(result, expected)


if __name__ == "__main__":
    unittest.main()
