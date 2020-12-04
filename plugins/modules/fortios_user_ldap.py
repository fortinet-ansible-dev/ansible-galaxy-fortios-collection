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
module: fortios_user_ldap
short_description: Configure LDAP server entries in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify user feature and ldap category.
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
    user_ldap:
        description:
            - Configure LDAP server entries.
        default: null
        type: dict
        suboptions:
            account_key_filter:
                description:
                    - Account key filter, using the UPN as the search filter.
                type: str
            account_key_processing:
                description:
                    - Account key processing operation, either keep or strip domain string of UPN in the token.
                type: str
                choices:
                    - same
                    - strip
            ca_cert:
                description:
                    - CA certificate name. Source vpn.certificate.ca.name.
                type: str
            cnid:
                description:
                    - Common name identifier for the LDAP server. The common name identifier for most LDAP servers is "cn".
                type: str
            dn:
                description:
                    - Distinguished name used to look up entries on the LDAP server.
                type: str
            group_filter:
                description:
                    - Filter used for group matching.
                type: str
            group_member_check:
                description:
                    - Group member checking methods.
                type: str
                choices:
                    - user-attr
                    - group-object
                    - posix-group-object
            group_object_filter:
                description:
                    - Filter used for group searching.
                type: str
            group_search_base:
                description:
                    - Search base used for group searching.
                type: str
            member_attr:
                description:
                    - Name of attribute from which to get group membership.
                type: str
            name:
                description:
                    - LDAP server entry name.
                required: true
                type: str
            password:
                description:
                    - Password for initial binding.
                type: str
            password_expiry_warning:
                description:
                    - Enable/disable password expiry warnings.
                type: str
                choices:
                    - enable
                    - disable
            password_renewal:
                description:
                    - Enable/disable online password renewal.
                type: str
                choices:
                    - enable
                    - disable
            port:
                description:
                    - Port to be used for communication with the LDAP server .
                type: int
            secondary_server:
                description:
                    - Secondary LDAP server CN domain name or IP.
                type: str
            secure:
                description:
                    - Port to be used for authentication.
                type: str
                choices:
                    - disable
                    - starttls
                    - ldaps
            server:
                description:
                    - LDAP server CN domain name or IP.
                type: str
            source_ip:
                description:
                    - Source IP for communications to LDAP server.
                type: str
            tertiary_server:
                description:
                    - Tertiary LDAP server CN domain name or IP.
                type: str
            type:
                description:
                    - Authentication type for LDAP searches.
                type: str
                choices:
                    - simple
                    - anonymous
                    - regular
            username:
                description:
                    - Username (full DN) for initial binding.
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
  - name: Configure LDAP server entries.
    fortios_user_ldap:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      user_ldap:
        account_key_filter: "<your_own_value>"
        account_key_processing: "same"
        ca_cert: "<your_own_value> (source vpn.certificate.ca.name)"
        cnid: "<your_own_value>"
        dn: "<your_own_value>"
        group_filter: "<your_own_value>"
        group_member_check: "user-attr"
        group_object_filter: "<your_own_value>"
        group_search_base: "<your_own_value>"
        member_attr: "<your_own_value>"
        name: "default_name_13"
        password: "<your_own_value>"
        password_expiry_warning: "enable"
        password_renewal: "enable"
        port: "17"
        secondary_server: "<your_own_value>"
        secure: "disable"
        server: "192.168.100.40"
        source_ip: "84.230.14.43"
        tertiary_server: "<your_own_value>"
        type: "simple"
        username: "<your_own_value>"

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


def filter_user_ldap_data(json):
    option_list = ['account_key_filter', 'account_key_processing', 'ca_cert',
                   'cnid', 'dn', 'group_filter',
                   'group_member_check', 'group_object_filter', 'group_search_base',
                   'member_attr', 'name', 'password',
                   'password_expiry_warning', 'password_renewal', 'port',
                   'secondary_server', 'secure', 'server',
                   'source_ip', 'tertiary_server', 'type',
                   'username']
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


def user_ldap(data, fos):
    vdom = data['vdom']
    state = data['state']
    user_ldap_data = data['user_ldap']
    filtered_data = underscore_to_hyphen(filter_user_ldap_data(user_ldap_data))

    if state == "present":
        return fos.set('user',
                       'ldap',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('user',
                          'ldap',
                          mkey=filtered_data['name'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_user(data, fos):

    if data['user_ldap']:
        resp = user_ldap(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('user_ldap'))

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
        "user_ldap": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "account_key_filter": {"required": False, "type": "str"},
                "account_key_processing": {"required": False, "type": "str",
                                           "choices": ["same",
                                                       "strip"]},
                "ca_cert": {"required": False, "type": "str"},
                "cnid": {"required": False, "type": "str"},
                "dn": {"required": False, "type": "str"},
                "group_filter": {"required": False, "type": "str"},
                "group_member_check": {"required": False, "type": "str",
                                       "choices": ["user-attr",
                                                   "group-object",
                                                   "posix-group-object"]},
                "group_object_filter": {"required": False, "type": "str"},
                "group_search_base": {"required": False, "type": "str"},
                "member_attr": {"required": False, "type": "str"},
                "name": {"required": True, "type": "str"},
                "password": {"required": False, "type": "str"},
                "password_expiry_warning": {"required": False, "type": "str",
                                            "choices": ["enable",
                                                        "disable"]},
                "password_renewal": {"required": False, "type": "str",
                                     "choices": ["enable",
                                                 "disable"]},
                "port": {"required": False, "type": "int"},
                "secondary_server": {"required": False, "type": "str"},
                "secure": {"required": False, "type": "str",
                           "choices": ["disable",
                                       "starttls",
                                       "ldaps"]},
                "server": {"required": False, "type": "str"},
                "source_ip": {"required": False, "type": "str"},
                "tertiary_server": {"required": False, "type": "str"},
                "type": {"required": False, "type": "str",
                         "choices": ["simple",
                                     "anonymous",
                                     "regular"]},
                "username": {"required": False, "type": "str"}

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

        is_error, has_changed, result = fortios_user(module.params, fos)
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
