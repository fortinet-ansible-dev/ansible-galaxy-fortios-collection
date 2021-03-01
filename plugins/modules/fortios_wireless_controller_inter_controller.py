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
module: fortios_wireless_controller_inter_controller
short_description: Configure inter wireless controller operation in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify wireless_controller feature and inter_controller category.
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

    wireless_controller_inter_controller:
        description:
            - Configure inter wireless controller operation.
        default: null
        type: dict
        suboptions:
            fast_failover_max:
                description:
                    - Maximum number of retransmissions for fast failover HA messages between peer wireless controllers (3 - 64).
                type: int
            fast_failover_wait:
                description:
                    - Minimum wait time before an AP transitions from secondary controller to primary controller (10 - 86400 sec).
                type: int
            inter_controller_key:
                description:
                    - Secret key for inter-controller communications.
                type: str
            inter_controller_mode:
                description:
                    - Configure inter-controller mode (disable, l2-roaming, 1+1).
                type: str
                choices:
                    - disable
                    - l2-roaming
                    - 1+1
            inter_controller_peer:
                description:
                    - Fast failover peer wireless controller list.
                type: list
                suboptions:
                    id:
                        description:
                            - ID.
                        required: true
                        type: int
                    peer_ip:
                        description:
                            - Peer wireless controller"s IP address.
                        type: str
                    peer_port:
                        description:
                            - Port used by the wireless controller"s for inter-controller communications (1024 - 49150).
                        type: int
                    peer_priority:
                        description:
                            - Peer wireless controller"s priority (primary or secondary).
                        type: str
                        choices:
                            - primary
                            - secondary
            inter_controller_pri:
                description:
                    - Configure inter-controller"s priority (primary or secondary).
                type: str
                choices:
                    - primary
                    - secondary
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
  - name: Configure inter wireless controller operation.
    fortios_wireless_controller_inter_controller:
      vdom:  "{{ vdom }}"
      wireless_controller_inter_controller:
        fast_failover_max: "3"
        fast_failover_wait: "4"
        inter_controller_key: "<your_own_value>"
        inter_controller_mode: "disable"
        inter_controller_peer:
         -
            id:  "8"
            peer_ip: "<your_own_value>"
            peer_port: "10"
            peer_priority: "primary"
        inter_controller_pri: "primary"

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


def filter_wireless_controller_inter_controller_data(json):
    option_list = ['fast_failover_max', 'fast_failover_wait', 'inter_controller_key',
                   'inter_controller_mode', 'inter_controller_peer', 'inter_controller_pri']
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


def wireless_controller_inter_controller(data, fos):
    vdom = data['vdom']
    wireless_controller_inter_controller_data = data['wireless_controller_inter_controller']
    filtered_data = underscore_to_hyphen(filter_wireless_controller_inter_controller_data(wireless_controller_inter_controller_data))

    return fos.set('wireless-controller',
                   'inter-controller',
                   data=filtered_data,
                   vdom=vdom)


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_wireless_controller(data, fos):

    if data['wireless_controller_inter_controller']:
        resp = wireless_controller_inter_controller(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('wireless_controller_inter_controller'))

    return not is_successful_status(resp), \
        resp['status'] == "success" and \
        (resp['revision_changed'] if 'revision_changed' in resp else True), \
        resp


def main():
    mkeyname = None
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "wireless_controller_inter_controller": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "fast_failover_max": {"required": False, "type": "int"},
                "fast_failover_wait": {"required": False, "type": "int"},
                "inter_controller_key": {"required": False, "type": "str"},
                "inter_controller_mode": {"required": False, "type": "str",
                                          "choices": ["disable",
                                                      "l2-roaming",
                                                      "1+1"]},
                "inter_controller_peer": {"required": False, "type": "list",
                                          "options": {
                                              "id": {"required": True, "type": "int"},
                                              "peer_ip": {"required": False, "type": "str"},
                                              "peer_port": {"required": False, "type": "int"},
                                              "peer_priority": {"required": False, "type": "str",
                                                                "choices": ["primary",
                                                                            "secondary"]}
                                          }},
                "inter_controller_pri": {"required": False, "type": "str",
                                         "choices": ["primary",
                                                     "secondary"]}

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

        is_error, has_changed, result = fortios_wireless_controller(module.params, fos)
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
