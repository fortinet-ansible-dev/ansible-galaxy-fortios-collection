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
module: fortios_system_vxlan
short_description: Configure VXLAN devices in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and vxlan category.
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
    system_vxlan:
        description:
            - Configure VXLAN devices.
        default: null
        type: dict
        suboptions:
            dstport:
                description:
                    - VXLAN destination port (1 - 65535).
                type: int
            interface:
                description:
                    - Outgoing interface for VXLAN encapsulated traffic. Source system.interface.name.
                type: str
            ip_version:
                description:
                    - IP version to use for the VXLAN interface and so for communication over the VXLAN. IPv4 or IPv6 unicast or multicast.
                type: str
                choices:
                    - ipv4-unicast
                    - ipv6-unicast
                    - ipv4-multicast
                    - ipv6-multicast
            multicast_ttl:
                description:
                    - VXLAN multicast TTL (1-255).
                type: int
            name:
                description:
                    - VXLAN device or interface name. Must be a unique interface name.
                required: true
                type: str
            remote_ip:
                description:
                    - IPv4 address of the VXLAN interface on the device at the remote end of the VXLAN.
                type: list
                suboptions:
                    ip:
                        description:
                            - IPv4 address.
                        required: true
                        type: str
            remote_ip6:
                description:
                    - IPv6 IP address of the VXLAN interface on the device at the remote end of the VXLAN.
                type: list
                suboptions:
                    ip6:
                        description:
                            - IPv6 address.
                        required: true
                        type: str
            vni:
                description:
                    - VXLAN network ID.
                type: int
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
  - name: Configure VXLAN devices.
    fortios_system_vxlan:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      system_vxlan:
        dstport: "3"
        interface: "<your_own_value> (source system.interface.name)"
        ip_version: "ipv4-unicast"
        multicast_ttl: "6"
        name: "default_name_7"
        remote_ip:
         -
            ip: "<your_own_value>"
        remote_ip6:
         -
            ip6: "<your_own_value>"
        vni: "12"

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


def filter_system_vxlan_data(json):
    option_list = ['dstport', 'interface', 'ip_version',
                   'multicast_ttl', 'name', 'remote_ip',
                   'remote_ip6', 'vni']
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


def system_vxlan(data, fos):
    vdom = data['vdom']
    state = data['state']
    system_vxlan_data = data['system_vxlan']
    filtered_data = underscore_to_hyphen(filter_system_vxlan_data(system_vxlan_data))

    if state == "present":
        return fos.set('system',
                       'vxlan',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('system',
                          'vxlan',
                          mkey=filtered_data['name'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_system(data, fos):

    if data['system_vxlan']:
        resp = system_vxlan(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_vxlan'))

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
        "system_vxlan": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "dstport": {"required": False, "type": "int"},
                "interface": {"required": False, "type": "str"},
                "ip_version": {"required": False, "type": "str",
                               "choices": ["ipv4-unicast",
                                           "ipv6-unicast",
                                           "ipv4-multicast",
                                           "ipv6-multicast"]},
                "multicast_ttl": {"required": False, "type": "int"},
                "name": {"required": True, "type": "str"},
                "remote_ip": {"required": False, "type": "list",
                              "options": {
                                  "ip": {"required": True, "type": "str"}
                              }},
                "remote_ip6": {"required": False, "type": "list",
                               "options": {
                                   "ip6": {"required": True, "type": "str"}
                               }},
                "vni": {"required": False, "type": "int"}

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
