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
module: fortios_system_admin
short_description: Configure admin users in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and admin category.
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
    system_admin:
        description:
            - Configure admin users.
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
            accprofile:
                description:
                    - Access profile for this administrator. Access profiles control administrator access to FortiGate features. Source system.accprofile.name.
                type: str
            accprofile_override:
                description:
                    - Enable to use the name of an access profile provided by the remote authentication server to control the FortiGate features that this
                       administrator can access.
                type: str
                choices:
                    - enable
                    - disable
            allow_remove_admin_session:
                description:
                    - Enable/disable allow admin session to be removed by privileged admin users.
                type: str
                choices:
                    - enable
                    - disable
            comments:
                description:
                    - Comment.
                type: str
            email_to:
                description:
                    - This administrator"s email address.
                type: str
            force_password_change:
                description:
                    - Enable/disable force password change on next login.
                type: str
                choices:
                    - enable
                    - disable
            fortitoken:
                description:
                    - This administrator"s FortiToken serial number.
                type: str
            guest_auth:
                description:
                    - Enable/disable guest authentication.
                type: str
                choices:
                    - disable
                    - enable
            guest_lang:
                description:
                    - Guest management portal language. Source system.custom-language.name.
                type: str
            guest_usergroups:
                description:
                    - Select guest user groups.
                type: list
                suboptions:
                    name:
                        description:
                            - Select guest user groups.
                        required: true
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
                    scope:
                        description:
                            - Dashboard scope.
                        type: str
                        choices:
                            - global
                            - vdom
                    widget:
                        description:
                            - Dashboard widgets.
                        type: list
                        suboptions:
                            fabric_device:
                                description:
                                    - Fabric device to monitor.
                                type: str
                            filters:
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
                            report_by:
                                description:
                                    - Field to aggregate the data by.
                                type: str
                                choices:
                                    - source
                                    - destination
                                    - country
                                    - intfpair
                                    - srcintf
                                    - dstintf
                                    - policy
                                    - wificlient
                                    - shaper
                                    - endpoint-vulnerability
                                    - endpoint-device
                                    - application
                                    - cloud-app
                                    - cloud-user
                                    - web-domain
                                    - web-category
                                    - web-search-phrase
                                    - threat
                                    - system
                                    - unauth
                                    - admin
                                    - vpn
                            sort_by:
                                description:
                                    - Field to sort the data by.
                                type: str
                            timeframe:
                                description:
                                    - Timeframe period of reported data.
                                type: str
                                choices:
                                    - realtime
                                    - 5min
                                    - hour
                                    - day
                                    - week
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
                                    - fortimail
                            visualization:
                                description:
                                    - Visualization to use.
                                type: str
                                choices:
                                    - table
                                    - bubble
                                    - country
                                    - chord
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
            hidden:
                description:
                    - Admin user hidden attribute.
                type: int
            history0:
                description:
                    - history0
                type: str
            history1:
                description:
                    - history1
                type: str
            ip6_trusthost1:
                description:
                    - Any IPv6 address from which the administrator can connect to the FortiGate unit. Default allows access from any IPv6 address.
                type: str
            ip6_trusthost10:
                description:
                    - Any IPv6 address from which the administrator can connect to the FortiGate unit. Default allows access from any IPv6 address.
                type: str
            ip6_trusthost2:
                description:
                    - Any IPv6 address from which the administrator can connect to the FortiGate unit. Default allows access from any IPv6 address.
                type: str
            ip6_trusthost3:
                description:
                    - Any IPv6 address from which the administrator can connect to the FortiGate unit. Default allows access from any IPv6 address.
                type: str
            ip6_trusthost4:
                description:
                    - Any IPv6 address from which the administrator can connect to the FortiGate unit. Default allows access from any IPv6 address.
                type: str
            ip6_trusthost5:
                description:
                    - Any IPv6 address from which the administrator can connect to the FortiGate unit. Default allows access from any IPv6 address.
                type: str
            ip6_trusthost6:
                description:
                    - Any IPv6 address from which the administrator can connect to the FortiGate unit. Default allows access from any IPv6 address.
                type: str
            ip6_trusthost7:
                description:
                    - Any IPv6 address from which the administrator can connect to the FortiGate unit. Default allows access from any IPv6 address.
                type: str
            ip6_trusthost8:
                description:
                    - Any IPv6 address from which the administrator can connect to the FortiGate unit. Default allows access from any IPv6 address.
                type: str
            ip6_trusthost9:
                description:
                    - Any IPv6 address from which the administrator can connect to the FortiGate unit. Default allows access from any IPv6 address.
                type: str
            login_time:
                description:
                    - Record user login time.
                type: list
                suboptions:
                    last_failed_login:
                        description:
                            - Last failed login time.
                        type: str
                    last_login:
                        description:
                            - Last successful login time.
                        type: str
                    usr_name:
                        description:
                            - User name.
                        type: str
            name:
                description:
                    - User name.
                required: true
                type: str
            password:
                description:
                    - Admin user password.
                type: str
            password_expire:
                description:
                    - Password expire time.
                type: str
            peer_auth:
                description:
                    - Set to enable peer certificate authentication (for HTTPS admin access).
                type: str
                choices:
                    - enable
                    - disable
            peer_group:
                description:
                    - Name of peer group defined under config user group which has PKI members. Used for peer certificate authentication (for HTTPS admin
                       access).
                type: str
            radius_vdom_override:
                description:
                    - Enable to use the names of VDOMs provided by the remote authentication server to control the VDOMs that this administrator can access.
                type: str
                choices:
                    - enable
                    - disable
            remote_auth:
                description:
                    - Enable/disable authentication using a remote RADIUS, LDAP, or TACACS+ server.
                type: str
                choices:
                    - enable
                    - disable
            remote_group:
                description:
                    - User group name used for remote auth.
                type: str
            schedule:
                description:
                    - Firewall schedule used to restrict when the administrator can log in. No schedule means no restrictions.
                type: str
            sms_custom_server:
                description:
                    - Custom SMS server to send SMS messages to. Source system.sms-server.name.
                type: str
            sms_phone:
                description:
                    - Phone number on which the administrator receives SMS messages.
                type: str
            sms_server:
                description:
                    - Send SMS messages using the FortiGuard SMS server or a custom server.
                type: str
                choices:
                    - fortiguard
                    - custom
            ssh_certificate:
                description:
                    - Select the certificate to be used by the FortiGate for authentication with an SSH client. Source certificate.local.name.
                type: str
            ssh_public_key1:
                description:
                    - Public key of an SSH client. The client is authenticated without being asked for credentials. Create the public-private key pair in the
                       SSH client application.
                type: str
            ssh_public_key2:
                description:
                    - Public key of an SSH client. The client is authenticated without being asked for credentials. Create the public-private key pair in the
                       SSH client application.
                type: str
            ssh_public_key3:
                description:
                    - Public key of an SSH client. The client is authenticated without being asked for credentials. Create the public-private key pair in the
                       SSH client application.
                type: str
            trusthost1:
                description:
                    - Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit. Default allows access
                       from any IPv4 address.
                type: str
            trusthost10:
                description:
                    - Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit. Default allows access
                       from any IPv4 address.
                type: str
            trusthost2:
                description:
                    - Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit. Default allows access
                       from any IPv4 address.
                type: str
            trusthost3:
                description:
                    - Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit. Default allows access
                       from any IPv4 address.
                type: str
            trusthost4:
                description:
                    - Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit. Default allows access
                       from any IPv4 address.
                type: str
            trusthost5:
                description:
                    - Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit. Default allows access
                       from any IPv4 address.
                type: str
            trusthost6:
                description:
                    - Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit. Default allows access
                       from any IPv4 address.
                type: str
            trusthost7:
                description:
                    - Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit. Default allows access
                       from any IPv4 address.
                type: str
            trusthost8:
                description:
                    - Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit. Default allows access
                       from any IPv4 address.
                type: str
            trusthost9:
                description:
                    - Any IPv4 address or subnet address and netmask from which the administrator can connect to the FortiGate unit. Default allows access
                       from any IPv4 address.
                type: str
            two_factor:
                description:
                    - Enable/disable two-factor authentication.
                type: str
                choices:
                    - disable
                    - fortitoken
                    - email
                    - sms
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
            wildcard:
                description:
                    - Enable/disable wildcard RADIUS authentication.
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
  - name: Configure admin users.
    fortios_system_admin:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      system_admin:
        accprofile: "<your_own_value> (source system.accprofile.name)"
        accprofile_override: "enable"
        allow_remove_admin_session: "enable"
        comments: "<your_own_value>"
        email_to: "<your_own_value>"
        force_password_change: "enable"
        fortitoken: "<your_own_value>"
        guest_auth: "disable"
        guest_lang: "<your_own_value> (source system.custom-language.name)"
        guest_usergroups:
         -
            name: "default_name_13"
        gui_dashboard:
         -
            columns: "15"
            id:  "16"
            layout_type: "responsive"
            name: "default_name_18"
            scope: "global"
            widget:
             -
                fabric_device: "<your_own_value>"
                filters:
                 -
                    id:  "23"
                    key: "<your_own_value>"
                    value: "<your_own_value>"
                height: "26"
                id:  "27"
                industry: "default"
                interface: "<your_own_value> (source system.interface.name)"
                region: "default"
                report_by: "source"
                sort_by: "<your_own_value>"
                timeframe: "realtime"
                title: "<your_own_value>"
                type: "sysinfo"
                visualization: "table"
                width: "37"
                x_pos: "38"
                y_pos: "39"
        gui_global_menu_favorites:
         -
            id:  "41"
        gui_vdom_menu_favorites:
         -
            id:  "43"
        hidden: "44"
        history0: "<your_own_value>"
        history1: "<your_own_value>"
        ip6_trusthost1: "<your_own_value>"
        ip6_trusthost10: "<your_own_value>"
        ip6_trusthost2: "<your_own_value>"
        ip6_trusthost3: "<your_own_value>"
        ip6_trusthost4: "<your_own_value>"
        ip6_trusthost5: "<your_own_value>"
        ip6_trusthost6: "<your_own_value>"
        ip6_trusthost7: "<your_own_value>"
        ip6_trusthost8: "<your_own_value>"
        ip6_trusthost9: "<your_own_value>"
        login_time:
         -
            last_failed_login: "<your_own_value>"
            last_login: "<your_own_value>"
            usr_name: "<your_own_value>"
        name: "default_name_61"
        password: "<your_own_value>"
        password_expire: "<your_own_value>"
        peer_auth: "enable"
        peer_group: "<your_own_value>"
        radius_vdom_override: "enable"
        remote_auth: "enable"
        remote_group: "<your_own_value>"
        schedule: "<your_own_value>"
        sms_custom_server: "<your_own_value> (source system.sms-server.name)"
        sms_phone: "<your_own_value>"
        sms_server: "fortiguard"
        ssh_certificate: "<your_own_value> (source certificate.local.name)"
        ssh_public_key1: "<your_own_value>"
        ssh_public_key2: "<your_own_value>"
        ssh_public_key3: "<your_own_value>"
        trusthost1: "<your_own_value>"
        trusthost10: "<your_own_value>"
        trusthost2: "<your_own_value>"
        trusthost3: "<your_own_value>"
        trusthost4: "<your_own_value>"
        trusthost5: "<your_own_value>"
        trusthost6: "<your_own_value>"
        trusthost7: "<your_own_value>"
        trusthost8: "<your_own_value>"
        trusthost9: "<your_own_value>"
        two_factor: "disable"
        vdom:
         -
            name: "default_name_89 (source system.vdom.name)"
        wildcard: "enable"

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


def filter_system_admin_data(json):
    option_list = ['accprofile', 'accprofile_override', 'allow_remove_admin_session',
                   'comments', 'email_to', 'force_password_change',
                   'fortitoken', 'guest_auth', 'guest_lang',
                   'guest_usergroups', 'gui_dashboard', 'gui_global_menu_favorites',
                   'gui_vdom_menu_favorites', 'hidden', 'history0',
                   'history1', 'ip6_trusthost1', 'ip6_trusthost10',
                   'ip6_trusthost2', 'ip6_trusthost3', 'ip6_trusthost4',
                   'ip6_trusthost5', 'ip6_trusthost6', 'ip6_trusthost7',
                   'ip6_trusthost8', 'ip6_trusthost9', 'login_time',
                   'name', 'password', 'password_expire',
                   'peer_auth', 'peer_group', 'radius_vdom_override',
                   'remote_auth', 'remote_group', 'schedule',
                   'sms_custom_server', 'sms_phone', 'sms_server',
                   'ssh_certificate', 'ssh_public_key1', 'ssh_public_key2',
                   'ssh_public_key3', 'trusthost1', 'trusthost10',
                   'trusthost2', 'trusthost3', 'trusthost4',
                   'trusthost5', 'trusthost6', 'trusthost7',
                   'trusthost8', 'trusthost9', 'two_factor',
                   'vdom', 'wildcard']
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


def system_admin(data, fos):
    vdom = data['vdom']
    if 'state' in data and data['state']:
        state = data['state']
    elif 'state' in data['system_admin'] and data['system_admin']['state']:
        state = data['system_admin']['state']
    else:
        state = True
    system_admin_data = data['system_admin']
    filtered_data = underscore_to_hyphen(filter_system_admin_data(system_admin_data))

    if state == "present":
        return fos.set('system',
                       'admin',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('system',
                          'admin',
                          mkey=filtered_data['name'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_system(data, fos):

    if data['system_admin']:
        resp = system_admin(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_admin'))

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
        "system_admin": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "state": {"required": False, "type": "str",
                          "choices": ["present", "absent"]},
                "accprofile": {"required": False, "type": "str"},
                "accprofile_override": {"required": False, "type": "str",
                                        "choices": ["enable",
                                                    "disable"]},
                "allow_remove_admin_session": {"required": False, "type": "str",
                                               "choices": ["enable",
                                                           "disable"]},
                "comments": {"required": False, "type": "str"},
                "email_to": {"required": False, "type": "str"},
                "force_password_change": {"required": False, "type": "str",
                                          "choices": ["enable",
                                                      "disable"]},
                "fortitoken": {"required": False, "type": "str"},
                "guest_auth": {"required": False, "type": "str",
                               "choices": ["disable",
                                           "enable"]},
                "guest_lang": {"required": False, "type": "str"},
                "guest_usergroups": {"required": False, "type": "list",
                                     "options": {
                                         "name": {"required": True, "type": "str"}
                                     }},
                "gui_dashboard": {"required": False, "type": "list",
                                  "options": {
                                      "columns": {"required": False, "type": "int"},
                                      "id": {"required": True, "type": "int"},
                                      "layout_type": {"required": False, "type": "str",
                                                      "choices": ["responsive",
                                                                  "fixed"]},
                                      "name": {"required": False, "type": "str"},
                                      "scope": {"required": False, "type": "str",
                                                "choices": ["global",
                                                            "vdom"]},
                                      "widget": {"required": False, "type": "list",
                                                 "options": {
                                                     "fabric_device": {"required": False, "type": "str"},
                                                     "filters": {"required": False, "type": "list",
                                                                 "options": {
                                                                     "id": {"required": True, "type": "int"},
                                                                     "key": {"required": False, "type": "str"},
                                                                     "value": {"required": False, "type": "str"}
                                                                 }},
                                                     "height": {"required": False, "type": "int"},
                                                     "id": {"required": True, "type": "int"},
                                                     "industry": {"required": False, "type": "str",
                                                                  "choices": ["default",
                                                                              "custom"]},
                                                     "interface": {"required": False, "type": "str"},
                                                     "region": {"required": False, "type": "str",
                                                                "choices": ["default",
                                                                            "custom"]},
                                                     "report_by": {"required": False, "type": "str",
                                                                   "choices": ["source",
                                                                               "destination",
                                                                               "country",
                                                                               "intfpair",
                                                                               "srcintf",
                                                                               "dstintf",
                                                                               "policy",
                                                                               "wificlient",
                                                                               "shaper",
                                                                               "endpoint-vulnerability",
                                                                               "endpoint-device",
                                                                               "application",
                                                                               "cloud-app",
                                                                               "cloud-user",
                                                                               "web-domain",
                                                                               "web-category",
                                                                               "web-search-phrase",
                                                                               "threat",
                                                                               "system",
                                                                               "unauth",
                                                                               "admin",
                                                                               "vpn"]},
                                                     "sort_by": {"required": False, "type": "str"},
                                                     "timeframe": {"required": False, "type": "str",
                                                                   "choices": ["realtime",
                                                                               "5min",
                                                                               "hour",
                                                                               "day",
                                                                               "week"]},
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
                                                                          "fortimail"]},
                                                     "visualization": {"required": False, "type": "str",
                                                                       "choices": ["table",
                                                                                   "bubble",
                                                                                   "country",
                                                                                   "chord"]},
                                                     "width": {"required": False, "type": "int"},
                                                     "x_pos": {"required": False, "type": "int"},
                                                     "y_pos": {"required": False, "type": "int"}
                                                 }}
                                  }},
                "gui_global_menu_favorites": {"required": False, "type": "list",
                                              "options": {
                                                  "id": {"required": True, "type": "str"}
                                              }},
                "gui_vdom_menu_favorites": {"required": False, "type": "list",
                                            "options": {
                                                "id": {"required": True, "type": "str"}
                                            }},
                "hidden": {"required": False, "type": "int"},
                "history0": {"required": False, "type": "str"},
                "history1": {"required": False, "type": "str"},
                "ip6_trusthost1": {"required": False, "type": "str"},
                "ip6_trusthost10": {"required": False, "type": "str"},
                "ip6_trusthost2": {"required": False, "type": "str"},
                "ip6_trusthost3": {"required": False, "type": "str"},
                "ip6_trusthost4": {"required": False, "type": "str"},
                "ip6_trusthost5": {"required": False, "type": "str"},
                "ip6_trusthost6": {"required": False, "type": "str"},
                "ip6_trusthost7": {"required": False, "type": "str"},
                "ip6_trusthost8": {"required": False, "type": "str"},
                "ip6_trusthost9": {"required": False, "type": "str"},
                "login_time": {"required": False, "type": "list",
                               "options": {
                                   "last_failed_login": {"required": False, "type": "str"},
                                   "last_login": {"required": False, "type": "str"},
                                   "usr_name": {"required": False, "type": "str"}
                               }},
                "name": {"required": True, "type": "str"},
                "password": {"required": False, "type": "str"},
                "password_expire": {"required": False, "type": "str"},
                "peer_auth": {"required": False, "type": "str",
                              "choices": ["enable",
                                          "disable"]},
                "peer_group": {"required": False, "type": "str"},
                "radius_vdom_override": {"required": False, "type": "str",
                                         "choices": ["enable",
                                                     "disable"]},
                "remote_auth": {"required": False, "type": "str",
                                "choices": ["enable",
                                            "disable"]},
                "remote_group": {"required": False, "type": "str"},
                "schedule": {"required": False, "type": "str"},
                "sms_custom_server": {"required": False, "type": "str"},
                "sms_phone": {"required": False, "type": "str"},
                "sms_server": {"required": False, "type": "str",
                               "choices": ["fortiguard",
                                           "custom"]},
                "ssh_certificate": {"required": False, "type": "str"},
                "ssh_public_key1": {"required": False, "type": "str"},
                "ssh_public_key2": {"required": False, "type": "str"},
                "ssh_public_key3": {"required": False, "type": "str"},
                "trusthost1": {"required": False, "type": "str"},
                "trusthost10": {"required": False, "type": "str"},
                "trusthost2": {"required": False, "type": "str"},
                "trusthost3": {"required": False, "type": "str"},
                "trusthost4": {"required": False, "type": "str"},
                "trusthost5": {"required": False, "type": "str"},
                "trusthost6": {"required": False, "type": "str"},
                "trusthost7": {"required": False, "type": "str"},
                "trusthost8": {"required": False, "type": "str"},
                "trusthost9": {"required": False, "type": "str"},
                "two_factor": {"required": False, "type": "str",
                               "choices": ["disable",
                                           "fortitoken",
                                           "email",
                                           "sms"]},
                "vdom": {"required": False, "type": "list",
                         "options": {
                             "name": {"required": True, "type": "str"}
                         }},
                "wildcard": {"required": False, "type": "str",
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
