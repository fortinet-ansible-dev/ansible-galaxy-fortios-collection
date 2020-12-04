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
module: fortios_report_dataset
short_description: Report dataset configuration in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify report feature and dataset category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.0
version_added: "2.8"
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
              This attribute was present already in previous version in a deeper level.
              It has been moved out to this outer level.
        type: str
        required: false
        choices:
            - present
            - absent
        version_added: 2.9
    report_dataset:
        description:
            - Report dataset configuration.
        default: null
        type: dict
        suboptions:
            state:
                description:
                    - B(Deprecated)
                    - Starting with Ansible 2.9 we recommend using the top-level 'state' parameter.
                    - HORIZONTALLINE
                    - Indicates whether to create or remove the object.
                type: str
                required: false
                choices:
                    - present
                    - absent
            field:
                description:
                    - Fields.
                type: list
                suboptions:
                    displayname:
                        description:
                            - Display name.
                        type: str
                    id:
                        description:
                            - Field ID (1 to number of columns in SQL result).
                        required: true
                        type: int
                    name:
                        description:
                            - Name.
                        type: str
                    type:
                        description:
                            - Field type.
                        type: str
                        choices:
                            - text
                            - integer
                            - double
            name:
                description:
                    - Name.
                required: true
                type: str
            parameters:
                description:
                    - Parameters.
                type: list
                suboptions:
                    data_type:
                        description:
                            - Data type.
                        type: str
                        choices:
                            - text
                            - integer
                            - double
                            - long-integer
                            - date-time
                    display_name:
                        description:
                            - Display name.
                        type: str
                    field:
                        description:
                            - SQL field name.
                        type: str
                    id:
                        description:
                            - Parameter ID (1 to number of columns in SQL result).
                        required: true
                        type: int
            policy:
                description:
                    - Used by monitor policy.
                type: int
            query:
                description:
                    - SQL query statement.
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
  - name: Report dataset configuration.
    fortios_report_dataset:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      report_dataset:
        field:
         -
            displayname: "<your_own_value>"
            id:  "5"
            name: "default_name_6"
            type: "text"
        name: "default_name_8"
        parameters:
         -
            data_type: "text"
            display_name: "<your_own_value>"
            field: "<your_own_value>"
            id:  "13"
        policy: "14"
        query: "<your_own_value>"

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


def filter_report_dataset_data(json):
    option_list = ['field', 'name', 'parameters',
                   'policy', 'query']
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


def report_dataset(data, fos):
    vdom = data['vdom']
    if 'state' in data and data['state']:
        state = data['state']
    elif 'state' in data['report_dataset'] and data['report_dataset']['state']:
        state = data['report_dataset']['state']
    else:
        state = True
    report_dataset_data = data['report_dataset']
    filtered_data = underscore_to_hyphen(filter_report_dataset_data(report_dataset_data))

    if state == "present":
        return fos.set('report',
                       'dataset',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('report',
                          'dataset',
                          mkey=filtered_data['name'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_report(data, fos):

    if data['report_dataset']:
        resp = report_dataset(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('report_dataset'))

    return not is_successful_status(resp), \
        resp['status'] == "success" and \
        (resp['revision_changed'] if 'revision_changed' in resp else True), \
        resp


def main():
    mkeyname = 'name'
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "state": {"required": False, "type": "str",
                  "choices": ["present", "absent"]},
        "report_dataset": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "state": {"required": False, "type": "str",
                          "choices": ["present", "absent"]},
                "field": {"required": False, "type": "list",
                          "options": {
                              "displayname": {"required": False, "type": "str"},
                              "id": {"required": True, "type": "int"},
                              "name": {"required": False, "type": "str"},
                              "type": {"required": False, "type": "str",
                                       "choices": ["text",
                                                   "integer",
                                                   "double"]}
                          }},
                "name": {"required": True, "type": "str"},
                "parameters": {"required": False, "type": "list",
                               "options": {
                                   "data_type": {"required": False, "type": "str",
                                                 "choices": ["text",
                                                             "integer",
                                                             "double",
                                                             "long-integer",
                                                             "date-time"]},
                                   "display_name": {"required": False, "type": "str"},
                                   "field": {"required": False, "type": "str"},
                                   "id": {"required": True, "type": "int"}
                               }},
                "policy": {"required": False, "type": "int"},
                "query": {"required": False, "type": "str"}

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

        is_error, has_changed, result = fortios_report(module.params, fos)
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
