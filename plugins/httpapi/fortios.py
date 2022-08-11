# Copyright (c) 2022 Fortinet
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

from __future__ import (absolute_import, division, print_function)
from urllib import response
__metaclass__ = type

DOCUMENTATION = """
---
module: fortios
short_description: HttpApi Plugin for Fortinet FortiOS Appliance or VM
description:
  - This HttpApi plugin provides methods to connect to Fortinet FortiOS Appliance or VM via REST API
author:
  - Miguel Angel Munoz (@magonzalez)
version_added: "2.0.0"
"""

import json
from ansible.plugins.httpapi import HttpApiBase
from ansible.module_utils.basic import to_text
from ansible.module_utils.six.moves import urllib
import re
# import requests
from datetime import datetime


class HttpApi(HttpApiBase):
    def __init__(self, connection):
        super(HttpApi, self).__init__(connection)

        self._conn = connection
        self._ccsrftoken = ''
        self._system_version = None
        self._ansible_fos_version = 'v6.0.0'
        self._ansible_galaxy_version = '2.1.7'
        self._log = None

        # workaround for HttApiBase: it always tries to do a basic auth for the first request to update auth headers
        # for token based auth, we need the Accept header to request the right data format
        self._conn._auth = {"Accept": "application/json"}

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
            self.log('Calling Fortios with access tokens, no login needed')
            url = '/api/v2/cmdb/system/interface?vdom=root&action=schema'
            status, response = self.send_request(url=url)
            if status == 401:
                raise Exception('Invalid access token. Please check')

    def logout(self):
        """ Call to implement session logout."""
        self.log('logout')
        if not self.get_access_token():
            self.send_request(url='/logout', method="POST")

    def update_auth(self, response, response_text):
        """
        Get cookies and obtain value for csrftoken that will be used on next requests
        :param response: Response given by the server.
        :param response_text Unused_input.
        :return: Dictionary containing headers
        """
        self.log('update_auth')
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
        headers = dict(message_kwargs.get('headers', {}))
        headers.update({'Accept': 'application/json'})

        url = self._concat_params(url, params)
        self.log('send request: METHOD:[%s] URL:[%s] DATA:[%s], headers:[%s]' % (method, url, data, headers))

        try:
            response, response_data = self.connection.send(url, data, method=method, headers=headers)

            json_formatted = to_text(response_data.getvalue())

            self.log("response data: %s..." % (json_formatted[:200]))
            return response.status, json_formatted
        except Exception as err:
            raise Exception(err)

    def update_system_version(self):
        """
        retrieve the system status of fortigate device
        """
        self.log('checking system_version')
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
