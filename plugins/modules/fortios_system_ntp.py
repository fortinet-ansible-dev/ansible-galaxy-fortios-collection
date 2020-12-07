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
module: fortios_system_ntp
short_description: Configure system NTP information in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and ntp category.
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

    system_ntp:
        description:
            - Configure system NTP information.
        default: null
        type: dict
        suboptions:
            interface:
                description:
                    - FortiGate interface(s) with NTP server mode enabled. Devices on your network can contact these interfaces for NTP services.
                type: list
                suboptions:
                    interface_name:
                        description:
                            - Interface name. Source system.interface.name.
                        type: str
            ntpserver:
                description:
                    - Configure the FortiGate to connect to any available third-party NTP server.
                type: list
                suboptions:
                    authentication:
                        description:
                            - Enable/disable MD5 authentication.
                        type: str
                        choices:
                            - enable
                            - disable
                    id:
                        description:
                            - NTP server ID.
                        required: true
                        type: int
                    key:
                        description:
                            - Key for MD5 authentication.
                        type: str
                    key_id:
                        description:
                            - Key ID for authentication.
                        type: int
                    ntpv3:
                        description:
                            - Enable to use NTPv3 instead of NTPv4.
                        type: str
                        choices:
                            - enable
                            - disable
                    server:
                        description:
                            - IP address or hostname of the NTP Server.
                        type: str
            ntpsync:
                description:
                    - Enable/disable setting the FortiGate system time by synchronizing with an NTP Server.
                type: str
                choices:
                    - enable
                    - disable
            server_mode:
                description:
                    - Enable/disable FortiGate NTP Server Mode. Your FortiGate becomes an NTP server for other devices on your network. The FortiGate relays
                       NTP requests to its configured NTP server.
                type: str
                choices:
                    - enable
                    - disable
            source_ip:
                description:
                    - Source IP for communications to the NTP server.
                type: str
            syncinterval:
                description:
                    - NTP synchronization interval (1 - 1440 min).
                type: int
            type:
                description:
                    - Use the FortiGuard NTP server or any other available NTP Server.
                type: str
                choices:
                    - fortiguard
                    - custom
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
  - name: Configure system NTP information.
    fortios_system_ntp:
      vdom:  "{{ vdom }}"
      system_ntp:
        interface:
         -
            interface_name: "<your_own_value> (source system.interface.name)"
        ntpserver:
         -
            authentication: "enable"
            id:  "7"
            key: "<your_own_value>"
            key_id: "9"
            ntpv3: "enable"
            server: "192.168.100.40"
        ntpsync: "enable"
        server_mode: "enable"
        source_ip: "84.230.14.43"
        syncinterval: "15"
        type: "fortiguard"

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


def filter_system_ntp_data(json):
    option_list = ['interface', 'ntpserver', 'ntpsync',
                   'server_mode', 'source_ip', 'syncinterval',
                   'type']
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


def system_ntp(data, fos):
    vdom = data['vdom']
    system_ntp_data = data['system_ntp']
    filtered_data = underscore_to_hyphen(filter_system_ntp_data(system_ntp_data))

    return fos.set('system',
                   'ntp',
                   data=filtered_data,
                   vdom=vdom)


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_system(data, fos):

    if data['system_ntp']:
        resp = system_ntp(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_ntp'))

    return not is_successful_status(resp), \
        resp['status'] == "success" and \
        (resp['revision_changed'] if 'revision_changed' in resp else True), \
        resp


def main():
    mkeyname = None
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "system_ntp": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "interface": {"required": False, "type": "list",
                              "options": {
                                  "interface_name": {"required": False, "type": "str"}
                              }},
                "ntpserver": {"required": False, "type": "list",
                              "options": {
                                  "authentication": {"required": False, "type": "str",
                                                     "choices": ["enable",
                                                                 "disable"]},
                                  "id": {"required": True, "type": "int"},
                                  "key": {"required": False, "type": "str"},
                                  "key_id": {"required": False, "type": "int"},
                                  "ntpv3": {"required": False, "type": "str",
                                            "choices": ["enable",
                                                        "disable"]},
                                  "server": {"required": False, "type": "str"}
                              }},
                "ntpsync": {"required": False, "type": "str",
                            "choices": ["enable",
                                        "disable"]},
                "server_mode": {"required": False, "type": "str",
                                "choices": ["enable",
                                            "disable"]},
                "source_ip": {"required": False, "type": "str"},
                "syncinterval": {"required": False, "type": "int"},
                "type": {"required": False, "type": "str",
                         "choices": ["fortiguard",
                                     "custom"]}

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
