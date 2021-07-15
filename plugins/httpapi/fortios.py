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

        self._conn = connection
        self._ccsrftoken = ''
        self._system_version = None
        self._ansible_fos_version = 'v6.0.0'
        self._ansible_galaxy_version = '2.1.2'
        self._log = None

    def log(self, msg):
        log_enabled = self._conn.get_option('enable_log')
        if not log_enabled:
            return
        if not self._log:
            self._log = open("/tmp/fortios.ansible.log", "a")
        log_message = str(datetime.now())
        log_message += ": " + str(msg) + '\n'
        self._log.write(log_message)
        self._log.flush()

    def get_access_token(self):
        '''this is only available after a module is initialized'''
        token = self._conn.get_option('access_token') if 'access_token' in self._conn._options else None

        return token

    def set_become(self, become_context):
        """
        Elevation is not required on Fortinet devices - Skipped
        :param become_context: Unused input.
        :return: None
        """
        return None

    def login(self, username, password):
        """Call a defined login endpoint to receive an authentication token."""
        if (username is None or password is None) and self.get_access_token() is None:
            raise Exception('Please provide access token or username/password to login')

        if self.get_access_token() is None:
            self.log('login with username and password')
            data = "username=" + urllib.parse.quote(username) + "&secretkey=" + urllib.parse.quote(password) + "&ajax=1"
            dummy, result_data = self.send_request(url='/logincheck', data=data, method='POST')
            self.log('login with user: %s %s' % (username, 'succeeds' if result_data[0] == '1' else 'fails'))
            if result_data[0] != '1':
                raise Exception('Wrong credentials. Please check')
        # If we succeed to login, we retrieve the system status first
        else:
            self.log('login with access token')
            self.send_request(url='/logincheck')
            status, dummy = self.send_request(url='/api/v2/cmdb/system/interface?vdom=root&action=schema')

            if status == 401:
                raise Exception('Invalid access token. Please check')

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

        if self.get_access_token() is None:
            headers = {}

            for attr, val in response.getheaders():
                if attr.lower() == 'set-cookie' and 'APSCOOKIE_' in val:
                    headers['Cookie'] = val

                elif attr.lower() == 'set-cookie' and 'ccsrftoken=' in val:
                    csrftoken_search = re.search('\"(.*)\"', val)
                    if csrftoken_search:
                        self._ccsrftoken = csrftoken_search.group(1)

            headers['x-csrftoken'] = self._ccsrftoken
            self.log('update x-csrftoken: %s' % (self._ccsrftoken))
            return headers
        else:
            self.log('using access token - setting header')

            return {
                "Accept": "application/json"
            }

    def handle_httperror(self, exc):
        """
        propogate exceptions to users
        :param exc: Exception
        """
        self.log('Exception thrown from handling http: ' + to_text(exc))

        return exc

    def _concat_token(self, url):
        if self.get_access_token():
            token_pair = 'access_token=' + self.get_access_token()
            return url + '&' + token_pair if '?' in url else url + '?' + token_pair
        return url

    def _concat_params(self, url, params):
        if not params or not len(params):
            return url
        url = url + '?' if '?' not in url else url
        for param_key in params:
            param_value = params[param_key]
            if url[-1] == '?':
                url += '%s=%s' % (param_key, param_value)
            else:
                url += '&%s=%s' % (param_key, param_value)
        return url

    def send_request(self, **message_kwargs):
        """
        Responsible for actual sending of data to the connection httpapi base plugin.
        :param message_kwargs: A formatted dictionary containing request info: url, data, method

        :return: Status code and response data.
        """

        url = message_kwargs.get('url', '/')
        if self.get_access_token() is not None:
            url = self._concat_token(message_kwargs.get('url', '/'))
        data = message_kwargs.get('data', '')
        method = message_kwargs.get('method', 'GET')
        params = message_kwargs.get('params', {})

        url = self._concat_params(url, params)
        self.log('send request: METHOD:%s URL:%s DATA:%s' % (method, url, data))
        try:
            response, response_data = self.connection.send(url, data, method=method)

            json_formatted = to_text(response_data.getvalue())

            self.log("response data: %s" % (json_formatted))
            return response.status, json_formatted
        except Exception as err:
            raise Exception(err)

    def update_system_version(self):
        """
        retrieve the system status of fortigate device
        """
        check_system_status = self._conn.get_option('check_system_status') if 'check_system_status' in self._conn._options else True
        if not check_system_status or self._system_version:
            return
        url = '/api/v2/cmdb/system/interface?vdom=root&action=schema'
        status, result = self.send_request(url=url)
        result_json = json.loads(result)
        self._system_version = result_json.get('version', 'undefined')
        self.log('system version: %s' % (self._system_version))
        self.log('ansible version: %s' % (self._ansible_fos_version))

    def get_system_version(self):
        self.update_system_version()
        return self._system_version
