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
module: fortios_wireless_controller_qos_profile
short_description: Configure WiFi quality of service (QoS) profiles in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify wireless_controller feature and qos_profile category.
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
    wireless_controller_qos_profile:
        description:
            - Configure WiFi quality of service (QoS) profiles.
        default: null
        type: dict
        suboptions:
            bandwidth_admission_control:
                description:
                    - Enable/disable WMM bandwidth admission control.
                type: str
                choices:
                    - enable
                    - disable
            bandwidth_capacity:
                description:
                    - Maximum bandwidth capacity allowed (1 - 600000 Kbps).
                type: int
            burst:
                description:
                    - Enable/disable client rate burst.
                type: str
                choices:
                    - enable
                    - disable
            call_admission_control:
                description:
                    - Enable/disable WMM call admission control.
                type: str
                choices:
                    - enable
                    - disable
            call_capacity:
                description:
                    - Maximum number of Voice over WLAN (VoWLAN) phones allowed (0 - 60).
                type: int
            comment:
                description:
                    - Comment.
                type: str
            downlink:
                description:
                    - Maximum downlink bandwidth for Virtual Access Points (VAPs) (0 - 2097152 Kbps).
                type: int
            downlink_sta:
                description:
                    - Maximum downlink bandwidth for clients (0 - 2097152 Kbps).
                type: int
            dscp_wmm_be:
                description:
                    - DSCP mapping for best effort access .
                type: list
                suboptions:
                    id:
                        description:
                            - DSCP WMM mapping numbers (0 - 63).
                        required: true
                        type: int
            dscp_wmm_bk:
                description:
                    - DSCP mapping for background access .
                type: list
                suboptions:
                    id:
                        description:
                            - DSCP WMM mapping numbers (0 - 63).
                        required: true
                        type: int
            dscp_wmm_mapping:
                description:
                    - Enable/disable Differentiated Services Code Point (DSCP) mapping.
                type: str
                choices:
                    - enable
                    - disable
            dscp_wmm_vi:
                description:
                    - DSCP mapping for video access .
                type: list
                suboptions:
                    id:
                        description:
                            - DSCP WMM mapping numbers (0 - 63).
                        required: true
                        type: int
            dscp_wmm_vo:
                description:
                    - DSCP mapping for voice access .
                type: list
                suboptions:
                    id:
                        description:
                            - DSCP WMM mapping numbers (0 - 63).
                        required: true
                        type: int
            name:
                description:
                    - WiFi QoS profile name.
                required: true
                type: str
            uplink:
                description:
                    - Maximum uplink bandwidth for Virtual Access Points (VAPs) (0 - 2097152 Kbps).
                type: int
            uplink_sta:
                description:
                    - Maximum uplink bandwidth for clients (0 - 2097152 Kbps).
                type: int
            wmm:
                description:
                    - Enable/disable WiFi multi-media (WMM) control.
                type: str
                choices:
                    - enable
                    - disable
            wmm_uapsd:
                description:
                    - Enable/disable WMM Unscheduled Automatic Power Save Delivery (U-APSD) power save mode.
                type: str
                choices:
                    - enable
                    - disable
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
  - name: Configure WiFi quality of service (QoS) profiles.
    fortios_wireless_controller_qos_profile:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      wireless_controller_qos_profile:
        bandwidth_admission_control: "enable"
        bandwidth_capacity: "4"
        burst: "enable"
        call_admission_control: "enable"
        call_capacity: "7"
        comment: "Comment."
        downlink: "9"
        downlink_sta: "10"
        dscp_wmm_be:
         -
            id:  "12"
        dscp_wmm_bk:
         -
            id:  "14"
        dscp_wmm_mapping: "enable"
        dscp_wmm_vi:
         -
            id:  "17"
        dscp_wmm_vo:
         -
            id:  "19"
        name: "default_name_20"
        uplink: "21"
        uplink_sta: "22"
        wmm: "enable"
        wmm_uapsd: "enable"

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


def filter_wireless_controller_qos_profile_data(json):
    option_list = ['bandwidth_admission_control', 'bandwidth_capacity', 'burst',
                   'call_admission_control', 'call_capacity', 'comment',
                   'downlink', 'downlink_sta', 'dscp_wmm_be',
                   'dscp_wmm_bk', 'dscp_wmm_mapping', 'dscp_wmm_vi',
                   'dscp_wmm_vo', 'name', 'uplink',
                   'uplink_sta', 'wmm', 'wmm_uapsd']
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


def wireless_controller_qos_profile(data, fos):
    vdom = data['vdom']
    state = data['state']
    wireless_controller_qos_profile_data = data['wireless_controller_qos_profile']
    filtered_data = underscore_to_hyphen(filter_wireless_controller_qos_profile_data(wireless_controller_qos_profile_data))

    if state == "present":
        return fos.set('wireless-controller',
                       'qos-profile',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('wireless-controller',
                          'qos-profile',
                          mkey=filtered_data['name'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_wireless_controller(data, fos):

    if data['wireless_controller_qos_profile']:
        resp = wireless_controller_qos_profile(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('wireless_controller_qos_profile'))

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
        "wireless_controller_qos_profile": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "bandwidth_admission_control": {"required": False, "type": "str",
                                                "choices": ["enable",
                                                            "disable"]},
                "bandwidth_capacity": {"required": False, "type": "int"},
                "burst": {"required": False, "type": "str",
                          "choices": ["enable",
                                      "disable"]},
                "call_admission_control": {"required": False, "type": "str",
                                           "choices": ["enable",
                                                       "disable"]},
                "call_capacity": {"required": False, "type": "int"},
                "comment": {"required": False, "type": "str"},
                "downlink": {"required": False, "type": "int"},
                "downlink_sta": {"required": False, "type": "int"},
                "dscp_wmm_be": {"required": False, "type": "list",
                                "options": {
                                    "id": {"required": True, "type": "int"}
                                }},
                "dscp_wmm_bk": {"required": False, "type": "list",
                                "options": {
                                    "id": {"required": True, "type": "int"}
                                }},
                "dscp_wmm_mapping": {"required": False, "type": "str",
                                     "choices": ["enable",
                                                 "disable"]},
                "dscp_wmm_vi": {"required": False, "type": "list",
                                "options": {
                                    "id": {"required": True, "type": "int"}
                                }},
                "dscp_wmm_vo": {"required": False, "type": "list",
                                "options": {
                                    "id": {"required": True, "type": "int"}
                                }},
                "name": {"required": True, "type": "str"},
                "uplink": {"required": False, "type": "int"},
                "uplink_sta": {"required": False, "type": "int"},
                "wmm": {"required": False, "type": "str",
                        "choices": ["enable",
                                    "disable"]},
                "wmm_uapsd": {"required": False, "type": "str",
                              "choices": ["enable",
                                          "disable"]}

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
