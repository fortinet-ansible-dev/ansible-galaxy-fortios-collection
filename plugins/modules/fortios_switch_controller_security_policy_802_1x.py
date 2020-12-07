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
module: fortios_switch_controller_security_policy_802_1x
short_description: Configure 802.1x MAC Authentication Bypass (MAB) policies in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify switch_controller_security_policy feature and 802_1x category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.0
version_added: "2.10"
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
    switch_controller_security_policy_802_1x:
        description:
            - Configure 802.1x MAC Authentication Bypass (MAB) policies.
        default: null
        type: dict
        suboptions:
            auth_fail_vlan:
                description:
                    - Enable to allow limited access to clients that cannot authenticate.
                type: str
                choices:
                    - disable
                    - enable
            auth_fail_vlan_id:
                description:
                    - VLAN ID on which authentication failed. Source system.interface.name.
                type: str
            auth_fail_vlanid:
                description:
                    - VLAN ID on which authentication failed.
                type: int
            eap_passthru:
                description:
                    - Enable/disable EAP pass-through mode, allowing protocols (such as LLDP) to pass through ports for more flexible authentication.
                type: str
                choices:
                    - disable
                    - enable
            guest_auth_delay:
                description:
                    - Guest authentication delay (1 - 900  sec).
                type: int
            guest_vlan:
                description:
                    - Enable the guest VLAN feature to allow limited access to non-802.1X-compliant clients.
                type: str
                choices:
                    - disable
                    - enable
            guest_vlan_id:
                description:
                    - Guest VLAN name. Source system.interface.name.
                type: str
            guest_vlanid:
                description:
                    - Guest VLAN ID.
                type: int
            mac_auth_bypass:
                description:
                    - Enable/disable MAB for this policy.
                type: str
                choices:
                    - disable
                    - enable
            name:
                description:
                    - Policy name.
                required: true
                type: str
            policy_type:
                description:
                    - Policy type.
                type: str
                choices:
                    - 802.1X
            radius_timeout_overwrite:
                description:
                    - Enable to override the global RADIUS session timeout.
                type: str
                choices:
                    - disable
                    - enable
            security_mode:
                description:
                    - Port or MAC based 802.1X security mode.
                type: str
                choices:
                    - 802.1X
                    - 802.1X-mac-based
            user_group:
                description:
                    - Name of user-group to assign to this MAC Authentication Bypass (MAB) policy.
                type: list
                suboptions:
                    name:
                        description:
                            - Group name. Source user.group.name.
                        required: true
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
  - name: Configure 802.1x MAC Authentication Bypass (MAB) policies.
    fortios_switch_controller_security_policy_802_1x:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      switch_controller_security_policy_802_1x:
        auth_fail_vlan: "disable"
        auth_fail_vlan_id: "<your_own_value> (source system.interface.name)"
        auth_fail_vlanid: "5"
        eap_passthru: "disable"
        guest_auth_delay: "7"
        guest_vlan: "disable"
        guest_vlan_id: "<your_own_value> (source system.interface.name)"
        guest_vlanid: "10"
        mac_auth_bypass: "disable"
        name: "default_name_12"
        policy_type: "802.1X"
        radius_timeout_overwrite: "disable"
        security_mode: "802.1X"
        user_group:
         -
            name: "default_name_17 (source user.group.name)"

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


def filter_switch_controller_security_policy_802_1x_data(json):
    option_list = ['auth_fail_vlan', 'auth_fail_vlan_id', 'auth_fail_vlanid',
                   'eap_passthru', 'guest_auth_delay', 'guest_vlan',
                   'guest_vlan_id', 'guest_vlanid', 'mac_auth_bypass',
                   'name', 'policy_type', 'radius_timeout_overwrite',
                   'security_mode', 'user_group']
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


def switch_controller_security_policy_802_1x(data, fos):
    vdom = data['vdom']
    state = data['state']
    switch_controller_security_policy_802_1x_data = data['switch_controller_security_policy_802_1x']
    filtered_data = underscore_to_hyphen(filter_switch_controller_security_policy_802_1x_data(switch_controller_security_policy_802_1x_data))

    if state == "present":
        return fos.set('switch-controller.security-policy',
                       '802-1X',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('switch-controller.security-policy',
                          '802-1X',
                          mkey=filtered_data['name'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_switch_controller_security_policy(data, fos):

    if data['switch_controller_security_policy_802_1x']:
        resp = switch_controller_security_policy_802_1x(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('switch_controller_security_policy_802_1x'))

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
        "switch_controller_security_policy_802_1x": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "auth_fail_vlan": {"required": False, "type": "str",
                                   "choices": ["disable",
                                               "enable"]},
                "auth_fail_vlan_id": {"required": False, "type": "str"},
                "auth_fail_vlanid": {"required": False, "type": "int"},
                "eap_passthru": {"required": False, "type": "str",
                                 "choices": ["disable",
                                             "enable"]},
                "guest_auth_delay": {"required": False, "type": "int"},
                "guest_vlan": {"required": False, "type": "str",
                               "choices": ["disable",
                                           "enable"]},
                "guest_vlan_id": {"required": False, "type": "str"},
                "guest_vlanid": {"required": False, "type": "int"},
                "mac_auth_bypass": {"required": False, "type": "str",
                                    "choices": ["disable",
                                                "enable"]},
                "name": {"required": True, "type": "str"},
                "policy_type": {"required": False, "type": "str",
                                "choices": ["802.1X"]},
                "radius_timeout_overwrite": {"required": False, "type": "str",
                                             "choices": ["disable",
                                                         "enable"]},
                "security_mode": {"required": False, "type": "str",
                                  "choices": ["802.1X",
                                              "802.1X-mac-based"]},
                "user_group": {"required": False, "type": "list",
                               "options": {
                                   "name": {"required": True, "type": "str"}
                               }}

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

        is_error, has_changed, result = fortios_switch_controller_security_policy(module.params, fos)
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
