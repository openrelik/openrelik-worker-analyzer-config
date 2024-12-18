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

from src.analyzers.redis_analyzer import analyze_config


class Utils(unittest.TestCase):
    """Test the analyzer functions."""

    def test_redisconfig_empty(self):
        """Test empty Redis config."""
        result = analyze_config("")
        report = (
            """# Redis Config Analyzer\n"""
            """\n\n"""
<<<<<<< HEAD
            """No Redis config found\n\n"""
        )
        summary = "No Redis config found"
=======
            """No issues found in Redis configuration\n\n"""
        )
        summary = "No issues found in Redis configuration"
>>>>>>> 0700bc7 (additional commits)

        self.assertIsInstance(result, Report)
        self.assertEqual(result.priority, Priority.LOW)
        self.assertEqual(result.summary, summary)
        self.assertEqual(result.to_markdown(), report)

    def test_redisconfig_weak(self):
        """Test Redis config with weak settings."""
        redis_config_weak = """bind 0.0.0.0
        port 6379
        logfile"""
        report_expected = (
            """# Redis Config Analyzer"""
            """\n\n\n"""
            """Insecure Redis configuration found. Total misconfigs: 3"""
            """\n\n"""
            """* Redis listening on every IP\n"""
            """* Redis configured with default port (6379)\n"""
            """* Log destination not configured"""
        )
        summary_expected = "Insecure Redis configuration found. Total misconfigs: 3"

        result = analyze_config(redis_config_weak)
        self.assertIsInstance(result, Report)
        self.assertEqual(result.priority, Priority.HIGH)
        self.assertEqual(result.summary, summary_expected)
        self.assertEqual(result.to_markdown(), report_expected)


if __name__ == "__main__":
    unittest.main()
