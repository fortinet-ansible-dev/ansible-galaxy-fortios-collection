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
module: fortios_system_sso_admin
short_description: Configure SSO admin users in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and sso_admin category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.2.0
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
options:
    host:
        description:
            - FortiOS or FortiGate IP address.
        type: str
        required: false
    username:
        description:
            - FortiOS or FortiGate username.
        type: str
        required: false
    password:
        description:
            - FortiOS or FortiGate password.
        type: str
        default: ""
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root
    https:
        description:
            - Indicates if the requests towards FortiGate must use HTTPS protocol.
        type: bool
        default: true
    ssl_verify:
        description:
            - Ensures FortiGate certificate must be verified by a proper CA.
        type: bool
        default: true
    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - present
            - absent
    system_sso_admin:
        description:
            - Configure SSO admin users.
        default: null
        type: dict
        suboptions:
            accprofile:
                description:
                    - SSO admin user access profile. Source system.accprofile.name.
                type: str
            gui_dashboard:
                description:
                    - GUI dashboards.
                type: list
                suboptions:
                    columns:
                        description:
                            - Number of columns.
                        type: int
                    id:
                        description:
                            - Dashboard ID.
                        required: true
                        type: int
                    layout_type:
                        description:
                            - Layout type.
                        type: str
                        choices:
                            - responsive
                            - fixed
                    name:
                        description:
                            - Dashboard name.
                        type: str
                    permanent:
                        description:
                            - Permanent dashboard (can"t be removed via the GUI).
                        type: str
                        choices:
                            - disable
                            - enable
                    vdom:
                        description:
                            - Virtual domain. Source system.vdom.name.
                        type: str
                    widget:
                        description:
                            - Dashboard widgets.
                        type: list
                        suboptions:
                            fabric_device:
                                description:
                                    - Fabric device to monitor.
                                type: str
                            fabric_device_widget_name:
                                description:
                                    - Fabric device widget name.
                                type: str
                            fabric_device_widget_visualization_type:
                                description:
                                    - Visualization type for fabric device widget.
                                type: str
                            fortiview_device:
                                description:
                                    - FortiView device.
                                type: str
                            fortiview_filters:
                                description:
                                    - FortiView filters.
                                type: list
                                suboptions:
                                    id:
                                        description:
                                            - FortiView Filter ID.
                                        required: true
                                        type: int
                                    key:
                                        description:
                                            - Filter key.
                                        type: str
                                    value:
                                        description:
                                            - Filter value.
                                        type: str
                            fortiview_sort_by:
                                description:
                                    - FortiView sort by.
                                type: str
                            fortiview_timeframe:
                                description:
                                    - FortiView timeframe.
                                type: str
                            fortiview_type:
                                description:
                                    - FortiView type.
                                type: str
                            fortiview_visualization:
                                description:
                                    - FortiView visualization.
                                type: str
                            height:
                                description:
                                    - Height.
                                type: int
                            id:
                                description:
                                    - Widget ID.
                                required: true
                                type: int
                            industry:
                                description:
                                    - Security Audit Rating industry.
                                type: str
                                choices:
                                    - default
                                    - custom
                            interface:
                                description:
                                    - Interface to monitor. Source system.interface.name.
                                type: str
                            region:
                                description:
                                    - Security Audit Rating region.
                                type: str
                                choices:
                                    - default
                                    - custom
                            title:
                                description:
                                    - Widget title.
                                type: str
                            type:
                                description:
                                    - Widget type.
                                type: str
                                choices:
                                    - sysinfo
                                    - licinfo
                                    - vminfo
                                    - forticloud
                                    - cpu-usage
                                    - memory-usage
                                    - disk-usage
                                    - log-rate
                                    - sessions
                                    - session-rate
                                    - tr-history
                                    - analytics
                                    - usb-modem
                                    - admins
                                    - security-fabric
                                    - security-fabric-ranking
                                    - ha-status
                                    - vulnerability-summary
                                    - host-scan-summary
                                    - fortiview
                                    - botnet-activity
                                    - fabric-device
                            width:
                                description:
                                    - Width.
                                type: int
                            x_pos:
                                description:
                                    - X position.
                                type: int
                            y_pos:
                                description:
                                    - Y position.
                                type: int
            gui_global_menu_favorites:
                description:
                    - Favorite GUI menu IDs for the global VDOM.
                type: list
                suboptions:
                    id:
                        description:
                            - Select menu ID.
                        required: true
                        type: str
            gui_new_feature_acknowledge:
                description:
                    - Acknowledgement of new features.
                type: list
                suboptions:
                    id:
                        description:
                            - Select menu ID.
                        required: true
                        type: str
            gui_vdom_menu_favorites:
                description:
                    - Favorite GUI menu IDs for VDOMs.
                type: list
                suboptions:
                    id:
                        description:
                            - Select menu ID.
                        required: true
                        type: str
            name:
                description:
                    - SSO admin name.
                required: true
                type: str
            vdom:
                description:
                    - Virtual domain(s) that the administrator can access.
                type: list
                suboptions:
                    name:
                        description:
                            - Virtual domain name. Source system.vdom.name.
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
  - name: Configure SSO admin users.
    fortios_system_sso_admin:
      vdom:  "{{ vdom }}"
      state: "present"
      system_sso_admin:
        accprofile: "<your_own_value> (source system.accprofile.name)"
        gui_dashboard:
         -
            columns: "5"
            id:  "6"
            layout_type: "responsive"
            name: "default_name_8"
            permanent: "disable"
            vdom: "<your_own_value> (source system.vdom.name)"
            widget:
             -
                fabric_device: "<your_own_value>"
                fabric_device_widget_name: "<your_own_value>"
                fabric_device_widget_visualization_type: "<your_own_value>"
                fortiview_device: "<your_own_value>"
                fortiview_filters:
                 -
                    id:  "17"
                    key: "<your_own_value>"
                    value: "<your_own_value>"
                fortiview_sort_by: "<your_own_value>"
                fortiview_timeframe: "<your_own_value>"
                fortiview_type: "<your_own_value>"
                fortiview_visualization: "<your_own_value>"
                height: "24"
                id:  "25"
                industry: "default"
                interface: "<your_own_value> (source system.interface.name)"
                region: "default"
                title: "<your_own_value>"
                type: "sysinfo"
                width: "31"
                x_pos: "32"
                y_pos: "33"
        gui_global_menu_favorites:
         -
            id:  "35"
        gui_new_feature_acknowledge:
         -
            id:  "37"
        gui_vdom_menu_favorites:
         -
            id:  "39"
        name: "default_name_40"
        vdom:
         -
            name: "default_name_42 (source system.vdom.name)"
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
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import FAIL_SOCKET_MSG


def login(data, fos):
    host = data['host']
    username = data['username']
    password = data['password']
    ssl_verify = data['ssl_verify']

    fos.debug('on')
    if 'https' in data and not data['https']:
        fos.https('off')
    else:
        fos.https('on')

    fos.login(host, username, password, verify=ssl_verify)


def filter_system_sso_admin_data(json):
    option_list = ['accprofile', 'gui_dashboard', 'gui_global_menu_favorites',
                   'gui_new_feature_acknowledge', 'gui_vdom_menu_favorites', 'name',
                   'vdom']
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


def system_sso_admin(data, fos):
    vdom = data['vdom']
    state = data['state']
    system_sso_admin_data = data['system_sso_admin']
    filtered_data = underscore_to_hyphen(filter_system_sso_admin_data(system_sso_admin_data))

    if state == "present":
        return fos.set('system',
                       'sso-admin',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('system',
                          'sso-admin',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_system(data, fos):

    if data['system_sso_admin']:
        resp = system_sso_admin(data, fos)

    return not is_successful_status(resp), \
        resp['status'] == "success" and \
        (resp['revision_changed'] if 'revision_changed' in resp else True), \
        resp


def main():
    fields = {
        "host": {"required": False, "type": "str"},
        "username": {"required": False, "type": "str"},
        "password": {"required": False, "type": "str", "default": "", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "ssl_verify": {"required": False, "type": "bool", "default": True},
        "state": {"required": True, "type": "str",
                  "choices": ["present", "absent"]},
        "system_sso_admin": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "accprofile": {"required": False, "type": "str"},
                "gui_dashboard": {"required": False, "type": "list",
                                  "options": {
                                      "columns": {"required": False, "type": "int"},
                                      "id": {"required": True, "type": "int"},
                                      "layout_type": {"required": False, "type": "str",
                                                      "choices": ["responsive",
                                                                  "fixed"]},
                                      "name": {"required": False, "type": "str"},
                                      "permanent": {"required": False, "type": "str",
                                                    "choices": ["disable",
                                                                "enable"]},
                                      "vdom": {"required": False, "type": "str"},
                                      "widget": {"required": False, "type": "list",
                                                 "options": {
                                                     "fabric_device": {"required": False, "type": "str"},
                                                     "fabric_device_widget_name": {"required": False, "type": "str"},
                                                     "fabric_device_widget_visualization_type": {"required": False, "type": "str"},
                                                     "fortiview_device": {"required": False, "type": "str"},
                                                     "fortiview_filters": {"required": False, "type": "list",
                                                                           "options": {
                                                                               "id": {"required": True, "type": "int"},
                                                                               "key": {"required": False, "type": "str"},
                                                                               "value": {"required": False, "type": "str"}
                                                                           }},
                                                     "fortiview_sort_by": {"required": False, "type": "str"},
                                                     "fortiview_timeframe": {"required": False, "type": "str"},
                                                     "fortiview_type": {"required": False, "type": "str"},
                                                     "fortiview_visualization": {"required": False, "type": "str"},
                                                     "height": {"required": False, "type": "int"},
                                                     "id": {"required": True, "type": "int"},
                                                     "industry": {"required": False, "type": "str",
                                                                  "choices": ["default",
                                                                              "custom"]},
                                                     "interface": {"required": False, "type": "str"},
                                                     "region": {"required": False, "type": "str",
                                                                "choices": ["default",
                                                                            "custom"]},
                                                     "title": {"required": False, "type": "str"},
                                                     "type": {"required": False, "type": "str",
                                                              "choices": ["sysinfo",
                                                                          "licinfo",
                                                                          "vminfo",
                                                                          "forticloud",
                                                                          "cpu-usage",
                                                                          "memory-usage",
                                                                          "disk-usage",
                                                                          "log-rate",
                                                                          "sessions",
                                                                          "session-rate",
                                                                          "tr-history",
                                                                          "analytics",
                                                                          "usb-modem",
                                                                          "admins",
                                                                          "security-fabric",
                                                                          "security-fabric-ranking",
                                                                          "ha-status",
                                                                          "vulnerability-summary",
                                                                          "host-scan-summary",
                                                                          "fortiview",
                                                                          "botnet-activity",
                                                                          "fabric-device"]},
                                                     "width": {"required": False, "type": "int"},
                                                     "x_pos": {"required": False, "type": "int"},
                                                     "y_pos": {"required": False, "type": "int"}
                                                 }}
                                  }},
                "gui_global_menu_favorites": {"required": False, "type": "list",
                                              "options": {
                                                  "id": {"required": True, "type": "str"}
                                              }},
                "gui_new_feature_acknowledge": {"required": False, "type": "list",
                                                "options": {
                                                    "id": {"required": True, "type": "str"}
                                                }},
                "gui_vdom_menu_favorites": {"required": False, "type": "list",
                                            "options": {
                                                "id": {"required": True, "type": "str"}
                                            }},
                "name": {"required": True, "type": "str"},
                "vdom": {"required": False, "type": "list",
                         "options": {
                             "name": {"required": True, "type": "str"}
                         }}

            }
        }
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

            is_error, has_changed, result = fortios_system(module.params, fos)
            versions_check_result = connection.get_system_version()
        else:
            module.fail_json(**FAIL_SOCKET_MSG)
    else:
        try:
            from fortiosapi import FortiOSAPI
        except ImportError:
            module.fail_json(msg="fortiosapi module is required")

        fos = FortiOSAPI()

        login(module.params, fos)
        is_error, has_changed, result = fortios_system(module.params, fos)
        fos.logout()

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
