#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
# Copyright 2019-2020 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# the lib use python logging can get it if the following is set in your
# Ansible config.
# log_path = /var/tmp/ansible.log in your conf..

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fortios_system_config_backup_restore
short_description: Backup/restore fortigate configuration
description:
    - This module is able to backup or restore the global or particial settings of the fortigate
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.0
version_added: "2.10"
author:
    - Link Zheng (@chillancezen)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@frankshen01)
    - Jie Xue (@JieX19)
    - Miguel Angel Munoz (@mamunozgonzalez)
    - Nicolas Thomas (@thomnico)
notes:
    - Legacy fortiosapi has been deprecated, httpapi is the preferred way to run playbooks
requirements:
    - ansible>=2.9.0
'''

EXAMPLES = '''
- hosts: fortigates
  connection: httpapi
  collections:
    - fortinet.fortios
  vars:
    vdom: "root"
    ansible_httpapi_use_ssl: yes
    ansible_httpapi_validate_certs: no
    ansible_httpapi_port: 443
  tasks:
  - name: backup a_specific_vdom settings
    fortios_system_config_backup_restore:
     config: "system config backup"
     vdom: "{{ vdom }}"
     backup: "yes"
     scope: "vdom"
     filename: "/tmp/backup_vdom"

  - name: backup global settings
    fortios_system_config_backup_restore:
     config: "system config backup"
     vdom: "{{ vdom }}"
     backup: "yes"
     scope: "global"
     filename: "/tmp/backup_global"

  - name: Restore a_specific_vdom settings
    fortios_system_config_backup_restore:
     config: "system config restore"
     vdom:  "{{ vdom }}"
     scope: "vdom"
     filename: "/tmp/backup_vdom"

  - name: Restore global settings
    fortios_system_config_backup_restore:
     config: "system config restore"
     vdom:  "{{ vdom }}"
     scope: "global"
     filename: "/tmp/backup_global"

'''

import json
from argparse import Namespace
import logging
import difflib
import re
import base64
from ansible.module_utils.basic import *
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import FortiOSHandler
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import FAIL_SOCKET_MSG

formatter = logging.Formatter(
    '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
logger = logging.getLogger('fortiosapi')
hdlr = logging.FileHandler('/var/tmp/ansible-fortiosconfig.log')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)

CONFIG_CALLS = []

# Note most "monitor calls" are not idempotent due to its own operational nature. They are
# 'one shot' operations that do not fit well as Ansible. However they are included here
# for certain scenarios where using Ansible is mandatory for everything

MONITOR_CALLS = [
    'system config backup',
    'system config restore',
]


def check_diff(data):

    # get the scope ['global' | 'vdom']
    scope = data['vdom']

    # check diff for specific scope
    parameters = {'destination': 'file',
                  'scope': scope}

    resp = fos.monitor('system',
                       'config/backup',
                       vdom=data['vdom'],
                       parameters=parameters)

    if resp['status'] != 'success':
        return True, False, {
            'status': resp['status'],
            'results': resp['results']
        }

    remote_filename = resp['results']['DOWNLOAD_SOURCE_FILE']
    # download for specific scope
    parameters = {'scope': scope}

    resp = fos.download('system/config',
                        'backup' + remote_filename,
                        vdom=data['vdom'],
                        parameters=parameters)

    if resp.status_code == 200:
        filtered_remote_config_file = remove_sensitive_data(resp.content)
        filtered_local_config_file = remove_sensitive_data(open(data['filename'], 'r').read())

        remote_config_file = filtered_remote_config_file.strip().splitlines()
        local_config_file = filtered_local_config_file.strip().splitlines()

        differences = ""
        for line in difflib.unified_diff(local_config_file, remote_config_file, fromfile='local', tofile='fortigate',
                                         lineterm=''):
            differences += line + '\n'

        return False, True, {
            'status': resp.status_code,
            'diff': differences
        }
    else:
        return True, False, {
            'status': resp.status_code,
        }


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortigate_backup(fos, data):
    functions = data['config'].split()

    # backup config for specific scope
    parameters = {
        'destination': 'file',
        'scope': data['scope'],
    }

    resp = fos.monitor(functions[0] + '/' + functions[1],
                       functions[2],
                       vdom=data['vdom'],
                       parameters=parameters)

    backup_content = ""

    if resp['http_status'] == 200:
        backup_content = resp['text']
    else:
        return True, False, {
            'status': 500,
            'resp': resp
        }

    file = open(data['filename'], 'w')
    file.write(backup_content)
    file.close()

    return False, False, {
        'status': 200,
        'backup': backup_content
    }


# Make sure the specific VDOM exists in the fortigate before restoring it. Using fortios_system_vdom module to create a VDOM.
def fortigate_upload(fos, data):
    if data['diff'] == True:
        return check_diff(data)

    # get the scope ['global' | 'VDOM']
    scope = data['scope']
    functions = data['config'].split()

    upload_data = {
        'source': 'upload',
        'scope': scope,
        'vdom': data['vdom'],
        'file_content': base64.b64encode(str.encode(open(data['filename'], 'r').read())).decode(),
    }

    # files = {'file': ('backup_data', open(data['filename'], 'r'), 'text/plain')}
    # If 'vdom' scope specified, the name of VDOM to restore configuration
    resp = fos.monitor(
        functions[0] + '/' + functions[1], functions[2],
        data=upload_data,
        vdom=data['vdom'],
        # files=files,
        method='POST',
    )

    if is_successful_status(resp):
        return False, True, {
            'status': resp['status'],
            'result': resp
        }
    else:
        return True, False, {
            'status': resp['status'],
            'result': resp
        }


def main():
    mkeyname = 'name'
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "host": {"required": False, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "username": {"required": False, "type": "str"},
        "description": {"required": False, "type": "str"},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "config": {"required": False, "choices": CONFIG_CALLS + MONITOR_CALLS, "type": "str"},
        "mkey": {"required": False, "type": "str"},
        "https": {"required": False, "type": "bool", "default": "True"},
        "ssl_verify": {"required": False, "type": "bool", "default": "True"},
        "backup": {"required": False, "type": "str"},
        "scope": {"required": True, "type": "str"},
        "filename": {"required": True, "type": "str"},
        "commands": {"required": False, "type": "str"}
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    if module._socket_path:
        connection = Connection(module._socket_path)
        if 'access_token' in module.params:
            connection.set_option('access_token', module.params['access_token'])

        fos = FortiOSHandler(connection, module, mkeyname)
    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    module.params['diff'] = False
    try:
        module.params['diff'] = module._diff
    except BaseException:
        logger.warning("Diff mode is only available on Ansible 2.1 and later versions")
        pass

    if module.params['backup']:
        is_error, has_changed, result = fortigate_backup(fos, module.params)
    else:
        is_error, has_changed, result = fortigate_upload(fos, module.params)

    if not is_error:
        if module.params['diff']:
            module.exit_json(changed=has_changed, meta=result, diff={'prepared': result['diff']})
        else:
            module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error", meta=result)


if __name__ == '__main__':
    main()
