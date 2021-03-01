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
module: fortios_vpn_ssl_web_user_group_bookmark
short_description: Configure SSL VPN user group bookmark in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify vpn_ssl_web feature and user_group_bookmark category.
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
    vpn_ssl_web_user_group_bookmark:
        description:
            - Configure SSL VPN user group bookmark.
        default: null
        type: dict
        suboptions:
            bookmarks:
                description:
                    - Bookmark table.
                type: list
                suboptions:
                    additional_params:
                        description:
                            - Additional parameters.
                        type: str
                    apptype:
                        description:
                            - Application type.
                        type: str
                        choices:
                            - citrix
                            - ftp
                            - portforward
                            - rdp
                            - smb
                            - ssh
                            - telnet
                            - vnc
                            - web
                    description:
                        description:
                            - Description.
                        type: str
                    folder:
                        description:
                            - Network shared file folder parameter.
                        type: str
                    form_data:
                        description:
                            - Form data.
                        type: list
                        suboptions:
                            name:
                                description:
                                    - Name.
                                required: true
                                type: str
                            value:
                                description:
                                    - Value.
                                type: str
                    host:
                        description:
                            - Host name/IP parameter.
                        type: str
                    listening_port:
                        description:
                            - Listening port (0 - 65535).
                        type: int
                    logon_password:
                        description:
                            - Logon password.
                        type: str
                    logon_user:
                        description:
                            - Logon user.
                        type: str
                    name:
                        description:
                            - Bookmark name.
                        required: true
                        type: str
                    port:
                        description:
                            - Remote port.
                        type: int
                    remote_port:
                        description:
                            - Remote port (0 - 65535).
                        type: int
                    security:
                        description:
                            - Security mode for RDP connection.
                        type: str
                        choices:
                            - rdp
                            - nla
                            - tls
                            - any
                    server_layout:
                        description:
                            - Server side keyboard layout.
                        type: str
                        choices:
                            - en-us-qwerty
                            - de-de-qwertz
                            - fr-fr-azerty
                            - it-it-qwerty
                            - sv-se-qwerty
                            - failsafe
                    show_status_window:
                        description:
                            - Enable/disable showing of status window.
                        type: str
                        choices:
                            - enable
                            - disable
                    sso:
                        description:
                            - Single Sign-On.
                        type: str
                        choices:
                            - disable
                            - static
                            - auto
                    sso_credential:
                        description:
                            - Single sign-on credentials.
                        type: str
                        choices:
                            - sslvpn-login
                            - alternative
                    sso_credential_sent_once:
                        description:
                            - Single sign-on credentials are only sent once to remote server.
                        type: str
                        choices:
                            - enable
                            - disable
                    sso_password:
                        description:
                            - SSO password.
                        type: str
                    sso_username:
                        description:
                            - SSO user name.
                        type: str
                    url:
                        description:
                            - URL parameter.
                        type: str
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
  - name: Configure SSL VPN user group bookmark.
    fortios_vpn_ssl_web_user_group_bookmark:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      vpn_ssl_web_user_group_bookmark:
        bookmarks:
         -
            additional_params: "<your_own_value>"
            apptype: "citrix"
            description: "<your_own_value>"
            folder: "<your_own_value>"
            form_data:
             -
                name: "default_name_9"
                value: "<your_own_value>"
            host: "<your_own_value>"
            listening_port: "12"
            logon_password: "<your_own_value>"
            logon_user: "<your_own_value>"
            name: "default_name_15"
            port: "16"
            remote_port: "17"
            security: "rdp"
            server_layout: "en-us-qwerty"
            show_status_window: "enable"
            sso: "disable"
            sso_credential: "sslvpn-login"
            sso_credential_sent_once: "enable"
            sso_password: "<your_own_value>"
            sso_username: "<your_own_value>"
            url: "myurl.com"
        name: "default_name_27 (source user.group.name)"

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


def filter_vpn_ssl_web_user_group_bookmark_data(json):
    option_list = ['bookmarks', 'name']
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


def vpn_ssl_web_user_group_bookmark(data, fos):
    vdom = data['vdom']
    state = data['state']
    vpn_ssl_web_user_group_bookmark_data = data['vpn_ssl_web_user_group_bookmark']
    filtered_data = underscore_to_hyphen(filter_vpn_ssl_web_user_group_bookmark_data(vpn_ssl_web_user_group_bookmark_data))

    if state == "present":
        return fos.set('vpn.ssl.web',
                       'user-group-bookmark',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('vpn.ssl.web',
                          'user-group-bookmark',
                          mkey=filtered_data['name'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_vpn_ssl_web(data, fos):

    if data['vpn_ssl_web_user_group_bookmark']:
        resp = vpn_ssl_web_user_group_bookmark(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('vpn_ssl_web_user_group_bookmark'))

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
        "vpn_ssl_web_user_group_bookmark": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "bookmarks": {"required": False, "type": "list",
                              "options": {
                                  "additional_params": {"required": False, "type": "str"},
                                  "apptype": {"required": False, "type": "str",
                                              "choices": ["citrix",
                                                          "ftp",
                                                          "portforward",
                                                          "rdp",
                                                          "smb",
                                                          "ssh",
                                                          "telnet",
                                                          "vnc",
                                                          "web"]},
                                  "description": {"required": False, "type": "str"},
                                  "folder": {"required": False, "type": "str"},
                                  "form_data": {"required": False, "type": "list",
                                                "options": {
                                                    "name": {"required": True, "type": "str"},
                                                    "value": {"required": False, "type": "str"}
                                                }},
                                  "host": {"required": False, "type": "str"},
                                  "listening_port": {"required": False, "type": "int"},
                                  "logon_password": {"required": False, "type": "str"},
                                  "logon_user": {"required": False, "type": "str"},
                                  "name": {"required": True, "type": "str"},
                                  "port": {"required": False, "type": "int"},
                                  "remote_port": {"required": False, "type": "int"},
                                  "security": {"required": False, "type": "str",
                                               "choices": ["rdp",
                                                           "nla",
                                                           "tls",
                                                           "any"]},
                                  "server_layout": {"required": False, "type": "str",
                                                    "choices": ["en-us-qwerty",
                                                                "de-de-qwertz",
                                                                "fr-fr-azerty",
                                                                "it-it-qwerty",
                                                                "sv-se-qwerty",
                                                                "failsafe"]},
                                  "show_status_window": {"required": False, "type": "str",
                                                         "choices": ["enable",
                                                                     "disable"]},
                                  "sso": {"required": False, "type": "str",
                                          "choices": ["disable",
                                                      "static",
                                                      "auto"]},
                                  "sso_credential": {"required": False, "type": "str",
                                                     "choices": ["sslvpn-login",
                                                                 "alternative"]},
                                  "sso_credential_sent_once": {"required": False, "type": "str",
                                                               "choices": ["enable",
                                                                           "disable"]},
                                  "sso_password": {"required": False, "type": "str"},
                                  "sso_username": {"required": False, "type": "str"},
                                  "url": {"required": False, "type": "str"}
                              }},
                "name": {"required": True, "type": "str"}

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

        is_error, has_changed, result = fortios_vpn_ssl_web(module.params, fos)
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
