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

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fortios_system_automation_action
short_description: Action for automation stitches in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and automation_action category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.0
version_added: "2.9"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@frankshen01)
    - Miguel Angel Munoz (@mamunozgonzalez)
    - Nicolas Thomas (@thomnico)
notes:
    - Legacy fortiosapi has been deprecated, httpapi is the preferred way to run playbooks

requirements:
    - ansible>=2.9.0
options:
    access_token:
        description:
            - Token-based authentication.
              Generated from GUI of Fortigate.
        type: str
        required: false
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - present
            - absent
    system_automation_action:
        description:
            - Action for automation stitches.
        default: null
        type: dict
        suboptions:
            action_type:
                description:
                    - Action type.
                type: str
                choices:
                    - email
                    - ios-notification
                    - alert
                    - disable-ssid
                    - quarantine
                    - quarantine-forticlient
                    - ban-ip
                    - aws-lambda
                    - webhook
            aws_api_id:
                description:
                    - AWS API Gateway ID.
                type: str
            aws_api_key:
                description:
                    - AWS API Gateway API key.
                type: str
            aws_api_path:
                description:
                    - AWS API Gateway path.
                type: str
            aws_api_stage:
                description:
                    - AWS API Gateway deployment stage name.
                type: str
            aws_region:
                description:
                    - AWS region.
                type: str
            email_subject:
                description:
                    - Email subject.
                type: str
            email_to:
                description:
                    - Email addresses.
                type: list
                suboptions:
                    name:
                        description:
                            - Email address.
                        required: true
                        type: str
            headers:
                description:
                    - Request headers.
                type: list
                suboptions:
                    header:
                        description:
                            - Request header.
                        required: true
                        type: str
            http_body:
                description:
                    - Request body (if necessary). Should be serialized json string.
                type: str
            method:
                description:
                    - Request method (GET, POST or PUT).
                type: str
                choices:
                    - post
                    - put
                    - get
            minimum_interval:
                description:
                    - Limit execution to no more than once in this interval (in seconds).
                type: int
            name:
                description:
                    - Name.
                required: true
                type: str
            port:
                description:
                    - Protocol port.
                type: int
            protocol:
                description:
                    - Request protocol.
                type: str
                choices:
                    - http
                    - https
            uri:
                description:
                    - Request API URI.
                type: str
'''

EXAMPLES = '''
- hosts: fortigates
  collections:
    - fortinet.fortios
  connection: httpapi
  vars:
   vdom: "root"
   ansible_httpapi_use_ssl: yes
   ansible_httpapi_validate_certs: no
   ansible_httpapi_port: 443
  tasks:
  - name: Action for automation stitches.
    fortios_system_automation_action:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      system_automation_action:
        action_type: "email"
        aws_api_id: "<your_own_value>"
        aws_api_key: "<your_own_value>"
        aws_api_path: "<your_own_value>"
        aws_api_stage: "<your_own_value>"
        aws_region: "<your_own_value>"
        email_subject: "<your_own_value>"
        email_to:
         -
            name: "default_name_11"
        headers:
         -
            header: "<your_own_value>"
        http_body: "<your_own_value>"
        method: "post"
        minimum_interval: "16"
        name: "default_name_17"
        port: "18"
        protocol: "http"
        uri: "<your_own_value>"

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

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import FortiOSHandler
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import check_legacy_fortiosapi
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import FAIL_SOCKET_MSG


def filter_system_automation_action_data(json):
    option_list = ['action_type', 'aws_api_id', 'aws_api_key',
                   'aws_api_path', 'aws_api_stage', 'aws_region',
                   'email_subject', 'email_to', 'headers',
                   'http_body', 'method', 'minimum_interval',
                   'name', 'port', 'protocol',
                   'uri']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def underscore_to_hyphen(data):
    if isinstance(data, list):
        for i, elem in enumerate(data):
            data[i] = underscore_to_hyphen(elem)
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace('_', '-')] = underscore_to_hyphen(v)
        data = new_data

    return data


def system_automation_action(data, fos):
    vdom = data['vdom']
    state = data['state']
    system_automation_action_data = data['system_automation_action']
    filtered_data = underscore_to_hyphen(filter_system_automation_action_data(system_automation_action_data))

    if state == "present":
        return fos.set('system',
                       'automation-action',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('system',
                          'automation-action',
                          mkey=filtered_data['name'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_system(data, fos):

    if data['system_automation_action']:
        resp = system_automation_action(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_automation_action'))

    return not is_successful_status(resp), \
        resp['status'] == "success" and \
        (resp['revision_changed'] if 'revision_changed' in resp else True), \
        resp


def main():
    mkeyname = 'name'
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "state": {"required": True, "type": "str",
                  "choices": ["present", "absent"]},
        "system_automation_action": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "action_type": {"required": False, "type": "str",
                                "choices": ["email",
                                            "ios-notification",
                                            "alert",
                                            "disable-ssid",
                                            "quarantine",
                                            "quarantine-forticlient",
                                            "ban-ip",
                                            "aws-lambda",
                                            "webhook"]},
                "aws_api_id": {"required": False, "type": "str"},
                "aws_api_key": {"required": False, "type": "str"},
                "aws_api_path": {"required": False, "type": "str"},
                "aws_api_stage": {"required": False, "type": "str"},
                "aws_region": {"required": False, "type": "str"},
                "email_subject": {"required": False, "type": "str"},
                "email_to": {"required": False, "type": "list",
                             "options": {
                                 "name": {"required": True, "type": "str"}
                             }},
                "headers": {"required": False, "type": "list",
                            "options": {
                                "header": {"required": True, "type": "str"}
                            }},
                "http_body": {"required": False, "type": "str"},
                "method": {"required": False, "type": "str",
                           "choices": ["post",
                                       "put",
                                       "get"]},
                "minimum_interval": {"required": False, "type": "int"},
                "name": {"required": True, "type": "str"},
                "port": {"required": False, "type": "int"},
                "protocol": {"required": False, "type": "str",
                             "choices": ["http",
                                         "https"]},
                "uri": {"required": False, "type": "str"}

            }
        }
    }

    check_legacy_fortiosapi()
    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if 'access_token' in module.params:
            connection.set_option('access_token', module.params['access_token'])

        fos = FortiOSHandler(connection, module, mkeyname)

        is_error, has_changed, result = fortios_system(module.params, fos)
        versions_check_result = connection.get_system_version()
    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result['matched'] is False:
        module.warn("Ansible has detected version mismatch between FortOS system and galaxy, see more details by specifying option -vvv")

    if not is_error:
        if versions_check_result and versions_check_result['matched'] is False:
            module.exit_json(changed=has_changed, version_check_warning=versions_check_result, meta=result)
        else:
            module.exit_json(changed=has_changed, meta=result)
    else:
        if versions_check_result and versions_check_result['matched'] is False:
            module.fail_json(msg="Error in repo", version_check_warning=versions_check_result, meta=result)
        else:
            module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
