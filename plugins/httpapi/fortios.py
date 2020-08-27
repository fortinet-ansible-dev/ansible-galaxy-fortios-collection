# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# (c) 2019 Fortinet, Inc
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
---
author:
    - Miguel Angel Munoz (@magonzalez)
httpapi : fortios
short_description: HttpApi Plugin for Fortinet FortiOS Appliance or VM
description:
  - This HttpApi plugin provides methods to connect to Fortinet FortiOS Appliance or VM via REST API
version_added: "2.9"
"""

import json
from ansible.plugins.httpapi import HttpApiBase
from ansible.module_utils.basic import to_text
from ansible.module_utils.six.moves import urllib
import re
from datetime import datetime


class HttpApi(HttpApiBase):
    def __init__(self, connection):
        super(HttpApi, self).__init__(connection)

        self._ccsrftoken = ''
        self._system_version = None
        self._ansible_fos_version = 'v6.0.0'
        self._ansible_galaxy_version = '1.0.15'
        self._log = open("/tmp/fortios.ansible.log", "a")

    def log(self, msg):
        log_message = str(datetime.now())
        log_message += ": " + str(msg) + '\n'
        self._log.write(log_message)
        self._log.flush()

    def set_become(self, become_context):
        """
        Elevation is not required on Fortinet devices - Skipped
        :param become_context: Unused input.
        :return: None
        """
        return None

    def login(self, username, password):
        """Call a defined login endpoint to receive an authentication token."""

        data = "username=" + urllib.parse.quote(username) + "&secretkey=" + urllib.parse.quote(password) + "&ajax=1"
        dummy, result_data = self.send_request(url='/logincheck', data=data, method='POST')
        self.log('login with user: %s %s' % (username, 'succeeds' if result_data[0] == '1' else 'fails'))
        if result_data[0] != '1':
            raise Exception('Wrong credentials. Please check')
        # If we succeed to login, we retrieve the system status first
        self.update_system_version()

    def logout(self):
        """ Call to implement session logout."""
        self.log('logout')
        self.send_request(url='/logout', method="POST")

    def update_auth(self, response, response_text):
        """
        Get cookies and obtain value for csrftoken that will be used on next requests
        :param response: Response given by the server.
        :param response_text Unused_input.
        :return: Dictionary containing headers
        """

        headers = {}

        for attr, val in response.getheaders():
            if attr == 'Set-Cookie' and 'APSCOOKIE_' in val:
                headers['Cookie'] = val

            elif attr == 'Set-Cookie' and 'ccsrftoken=' in val:
                csrftoken_search = re.search('\"(.*)\"', val)
                if csrftoken_search:
                    self._ccsrftoken = csrftoken_search.group(1)

        headers['x-csrftoken'] = self._ccsrftoken
        self.log('update x-csrftoken: %s' % (self._ccsrftoken))
        return headers

    def handle_httperror(self, exc):
        """
        Not required on Fortinet devices - Skipped
        :param exc: Unused input.
        :return: exc
        """
        return exc

    def send_request(self, **message_kwargs):
        """
        Responsible for actual sending of data to the connection httpapi base plugin.
        :param message_kwargs: A formatted dictionary containing request info: url, data, method

        :return: Status code and response data.
        """
        url = message_kwargs.get('url', '/')
        data = message_kwargs.get('data', '')
        method = message_kwargs.get('method', 'GET')

        try:
            response, response_data = self.connection.send(url, data, method=method)

            return response.status, to_text(response_data.getvalue())
        except Exception as err:
            raise Exception(err)

    def update_system_version(self):
        """
        retrieve the system status of fortigate device
        """
        url = '/api/v2/cmdb/non/existing/path'
        status, result = self.send_request(url=url)
        self._system_version = json.loads(result)['version']
        self.log('system version: %s' % (self._system_version))
        self.log('ansible version: %s' % (self._ansible_fos_version))

    def get_system_version(self):
        if not self._system_version:
            raise Exception('Wrong calling stack, httpapi must login!')
        system_version_words = self._system_version.split('.')
        ansible_version_words = self._ansible_fos_version.split('.')
        result = dict()
        result['system_version'] = self._system_version
        result['ansible_collection_version'] = self._ansible_fos_version + ' (galaxy: %s)' % (self._ansible_galaxy_version)
        result['matched'] = system_version_words[0] == ansible_version_words[0] and system_version_words[1] == ansible_version_words[1]
        if not result['matched']:
            result['message'] = 'Please follow steps in FortiOS versioning notes: https://ansible-galaxy-fortios-docs.readthedocs.io/en/latest/version.html'
        else:
            result['message'] = 'versions match'
        return result
