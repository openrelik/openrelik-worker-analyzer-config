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

from src.analyzers.tomcat_analyzer import analyze_config


class TomCatTests(unittest.TestCase):
    """Test the TomCat analyzer functions."""

    def test_tomcat_password_file(self):
        """Test Tomcat password file."""

        # Arrange
        TOMCAT_PASSWORD_FILE = """
        <?xml version='1.0' encoding='utf-8'?>
            <tomcat-users>
                <role rolename="tomcat"/>
                <role rolename="role1"/>
                <user username="tomcat" password="tomcat" roles="tomcat"/>
                <user username="both" password="tomcat" roles="tomcat,role1"/>
            </tomcat-users>
        """
        report = (
            '''# Tomcat Config Analyzer\n\n'''
            '''* tomcat user: <user username="tomcat" password="tomcat" roles="tomcat"/>\n'''
            '''* tomcat user: <user username="both" password="tomcat" roles="tomcat,role1"/>\n\n'''
            '''Tomcat analysis found misconfigs. Total: 2\n'''
        )
        summary = """Tomcat analysis found misconfigs. Total: 2"""

        # Act
        result = analyze_config(TOMCAT_PASSWORD_FILE)
      
        # Assert
        self.assertIsInstance(result, Report)
        self.assertEqual(result.priority, Priority.HIGH)
        self.assertEqual(result.summary, summary)
        self.assertEqual(result.to_markdown(), report)

    def test_tomcat_app_deploy_log(self):
        """Test Tomcat for app deployment logs."""

        # Arrange
        TOMCAT_APP_DEPLOY_LOG = (
            r"""21-Mar-2017 19:21:08.140 INFO [localhost-startStop-2] org.apache.catalina.startup.HostConfig.deployWAR Deploying web application archive C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\MyAwesomeApp.war"""
            """10-Sep-2012 11:41:12.283 INFO [localhost-startStop-1] org.apache.catalina.startup.HostConfig.deployWAR Deploying web application archive /opt/apache-tomcat-8.0.32/webapps/badboy.war"""
        )
        report = (
            """# Tomcat Config Analyzer\n\n"""
            """* Tomcat App Deployed: """
            r"""21-Mar-2017 19:21:08.140 INFO [localhost-startStop-2] org.apache.catalina.startup.HostConfig.deployWAR Deploying web application archive C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\MyAwesomeApp.war"""
            """10-Sep-2012 11:41:12.283 INFO [localhost-startStop-1] org.apache.catalina.startup.HostConfig.deployWAR Deploying web application archive /opt/apache-tomcat-8.0.32/webapps/badboy.war\n\n"""
            """Tomcat analysis found misconfigs. Total: 1\n"""
        )
        summary = """Tomcat analysis found misconfigs. Total: 1"""

        # Act
        result = analyze_config(TOMCAT_APP_DEPLOY_LOG)

        # Assert
        self.assertIsInstance(result, Report)
        self.assertEqual(result.priority, Priority.HIGH)
        self.assertEqual(result.summary, summary)
        self.assertEqual(result.to_markdown(), report)

    def test_tomcat_access_log(self):
        """Test Tomcat access log."""

        # Arrange
        TOMCAT_ACCESS_LOG = (
            '''1.2.3.4 - - [12/Apr/2018:14:01:08 -0100] "GET /manager/html HTTP/1.1" 401 2001'''
            '''1.2.3.4 - admin [12/Apr/2018:14:01:09 -0100] "GET /manager/html HTTP/1.1" 200 22130'''
            '''1.2.3.4 - admin [12/Apr/2018:14:01:39 -0100] "POST /manager/html/upload?org.apache.catalina.filters.CSRF_NONCE=1ABCDEFGKLMONPQRSTIRQKD240384739 HTTP/1.1" 200 27809'''
        )
        report = (
            '''# Tomcat Config Analyzer\n\n'''
            '''* Tomcat Management: '''
            '''1.2.3.4 - - [12/Apr/2018:14:01:08 -0100] "GET /manager/html HTTP/1.1" 401 2001'''
            '''1.2.3.4 - admin [12/Apr/2018:14:01:09 -0100] "GET /manager/html HTTP/1.1" 200 22130'''
            '''1.2.3.4 - admin [12/Apr/2018:14:01:39 -0100] "POST /manager/html/upload?org.apache.catalina.filters.CSRF_NONCE=1ABCDEFGKLMONPQRSTIRQKD240384739 HTTP/1.1" 200 27809\n\n'''
            '''Tomcat analysis found misconfigs. Total: 1\n'''
        )
        summary = """Tomcat analysis found misconfigs. Total: 1"""

        # Act
        result = analyze_config(TOMCAT_ACCESS_LOG)

        # Assert
        self.assertIsInstance(result, Report)
        self.assertEqual(result.priority, Priority.HIGH)
        self.assertEqual(result.summary, summary)
        self.assertEqual(result.to_markdown(), report)



if __name__ == "__main__":
    unittest.main()
