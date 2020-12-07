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
    - But this module relies on fortiosapi, please make sure fortiosapi is installed before using it
options:
    host:
        type: str
        required: false
        description:
            - host of fortigate
    password:
        type: str
        required: false
        description:
            - password of fortigate
    username:
        type: str
        required: false
        description:
            - username of fortigate
    description:
        type: str
        required: false
        description:
            -  descriptive text
    vdom:
        type: str
        required: false
        default: root
        description:
            - vdom to operate on
    config:
        type: str
        required: false
        description:
            - configuration to restore
    mkey:
        type: str
        required: false
        description:
            - primary key
    https:
        type: bool
        required: false
        default: true
        description:
            - use https or not
    ssl_verify:
        type: bool
        required: false
        default: true
        description:
            - enable ssl verification or not
    backup:
        type: str
        required: false
        description:
            - content to backup
    scope:
        type: str
        required: true
        description:
            - scope to operation on
    filename:
        type: str
        required: true
        description:
            - the file name
    commands:
        type: str
        required: false
        description:
            - the command
requirements:
    - ansible>=2.9.0
'''

EXAMPLES = '''
- hosts: localhost
  connection: httpapi
  collections:
    - fortinet.fortios
  vars:
    vdom: "root"
    host: "192.168.122.60"
    username: "admin"
    password: ""
  tasks:
  - name: backup global or a_specific_vdom settings
    fortios_system_config_backup_restore:
     config: "system config backup"
     host:  "{{ host }}"
     username: "{{ username }}"
     password: "{{ password }}"
     vdom: "{{ vdom }}"
     backup: "yes"
     https: True
     ssl_verify: False
     scope: "global or vdom"
     filename: "/tmp/backup_test"
  - name: Restore global or a_specific_vdom settings
    fortios_system_config_backup_restore:
     config: "system config restore"
     host:  "{{ host }}"
     username: "{{ username }}"
     password: "{{ password }}"
     vdom:  "{{ vdom }}"
     https: True
     ssl_verify: False
     scope: "global or vdom"
     filename: "/tmp/backup_test"

'''

RETURN = '''
build:
  description: Build number of the fortigate image
  returned: always
  type: str
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: str
  sample: 'PUT'
http_status:
  description: Last result given by FortiGate on last operation applied
  returned: always
  type: str
  sample: "200"
mkey:
  description: Master key (id) used in the last call to FortiGate
  returned: success
  type: str
  sample: "id"
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: str
  sample: "urlfilter"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "webfilter"
revision:
  description: Internal revision number
  returned: always
  type: str
  sample: "17.0.2.10658"
serial:
  description: Serial number of the unit
  returned: always
  type: str
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: str
  sample: "success"
vdom:
  description: Virtual domain used
  returned: always
  type: str
  sample: "root"
version:
  description: Version of the FortiGate
  returned: always
  type: str
  sample: "v5.6.3"

'''
from ansible.module_utils.basic import *
# from fortiosapi import FortiOSAPI
import json
from argparse import Namespace
import logging
import difflib
import re
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import FortiOSHandler
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import FAIL_SOCKET_MSG

# fos = FortiOSAPI()
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


def login(fos, data):
    host = data['host']
    username = data['username']
    password = data['password']
    ssl_verify = data['ssl_verify']
    if 'https' in data and not data['https']:
        fos.https('off')
    else:
        fos.https('on')
    fos.debug('on')
    fos.login(host, username, password, verify=ssl_verify)


def logout(fos):
    fos.logout()


def check_diff(data):

    # get the scope ['global' | 'vdom']
    scope = data['vdom']

    # check diff for specific scope
    parameters = {'destination': 'file',
                  'scope': scope}

    resp = fos.monitor('system/config',
                       'backup',
                       vdom=data['vdom'],
                       parameters=parameters)

    if resp['status'] != 'success':
        return True, False, {
            'status': resp['status'],
            # 'version': resp['version'],
            'results': resp['results']
        }

    remote_filename = resp['results']['DOWNLOAD_SOURCE_FILE']
    # download for specific scope
    parameters = {'scope': scope}

    resp = fos.download('system/config',
                        'backup' + remote_filename,
                        vdom=data['vdom'],
                        parameters=parameters)
    # version = fos.get_version()

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
            # 'version': version,
            'diff': differences
        }
    else:
        return True, False, {
            'status': resp.status_code,
            # 'version': version
        }


def fortigate_backup(fos, data):
    functions = data['config'].split()

    # backup config for specific scope
    parameters = {'destination': 'file',
                  'scope': data['scope']}

    resp = fos.monitor(functions[0] + '/' + functions[1],
                       functions[2],
                       vdom=data['vdom'],
                       parameters=parameters)

    # version = fos.get_version()
    backup_content = ""

    if 'status' in resp:  # Old versions use this mechanism
        if resp['status'] != 'success':
            return True, False, {
                'status': resp['status'],
                # 'version': resp['version'],
                'results': resp['results']
            }

        remote_filename = '/download?mkey=' + resp['results']['DOWNLOAD_SOURCE_FILE']
        parameters = {'scope': data['scope']}
        resp = fos.download(functions[0] + '/' + functions[1],
                            functions[2] + remote_filename,
                            vdom=data['vdom'],
                            parameters=parameters)
        if resp.status_code == 200:
            backup_content = resp.content

    elif 'status_code' in dir(resp):
        if resp.status_code == 200:
            backup_content = resp.text

    else:
        return True, False, {
            'status': 500,
            # 'version': version
        }

    file = open(data['filename'], 'w')
    file.write(backup_content)
    file.close()

    return False, False, {
        'status': 200,
        # 'version': version,
        'backup': backup_content
    }


# Make sure the specific VDOM exists in the fortigate before restoring it. Using fortios_system_vdom module to create a VDOM.
def fortigate_upload(fos, data):
    if data['diff']:
        return check_diff(data)

    # get the scope ['global' | 'VDOM']
    scope = data['scope']
    functions = data['config'].split()

    # paramters for global_restore | VDOM_restore
    parameters = {'global': '1'} if scope == 'global' else {'vdom': data['vdom']}
    upload_data = {'source': 'upload', 'scope': scope}
    files = {'file': ('backup_data', open(data['filename'], 'r'), 'text/plain')}

    # If 'vdom' scope specified, the name of VDOM to restore configuration
    resp = fos.upload(functions[0] + '/' + functions[1], functions[2],
                      data=upload_data,
                      parameters=parameters,
                      vdom=data['vdom'],
                      files=files)
    # version = fos.get_version()

    if resp.status_code == 200:
        return False, True, {
            'status': resp.status_code,
            # 'version': version,
            'result': resp.content
        }
    else:
        return True, False, {
            'status': resp.status_code,
            # 'version': version,
            'result': resp.content
        }


def main():
    fields = {
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

    # legacy_mode refers to using fortiosapi instead of HTTPAPI
    legacy_mode = 'host' in module.params and module.params['host'] is not None and \
                  'username' in module.params and module.params['username'] is not None and \
                  'password' in module.params and module.params['password'] is not None

    versions_check_result = None
    if not legacy_mode:
        if module._socket_path:
            connection = Connection(module._socket_path)
            fos = FortiOSHandler(connection)
        else:
            module.fail_json(**FAIL_SOCKET_MSG)
    else:
        try:
            from fortiosapi import FortiOSAPI
        except ImportError:
            module.fail_json(msg="fortiosapi module is required")

        fos = FortiOSAPI()
        login(fos, module.params)

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

    logout(fos)


if __name__ == '__main__':
    main()
