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
module: fortios_certificate_crl
short_description: Certificate Revocation List as a PEM file in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify certificate feature and crl category.
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
    certificate_crl:
        description:
            - Certificate Revocation List as a PEM file.
        default: null
        type: dict
        suboptions:
            crl:
                description:
                    - Certificate Revocation List as a PEM file.
                type: str
            http_url:
                description:
                    - HTTP server URL for CRL auto-update.
                type: str
            last_updated:
                description:
                    - Time at which CRL was last updated.
                type: int
            ldap_password:
                description:
                    - LDAP server user password.
                type: str
            ldap_server:
                description:
                    - LDAP server name for CRL auto-update.
                type: str
            ldap_username:
                description:
                    - LDAP server user name.
                type: str
            name:
                description:
                    - Name.
                required: true
                type: str
            range:
                description:
                    - Either global or VDOM IP address range for the certificate.
                type: str
                choices:
                    - global
                    - vdom
            scep_cert:
                description:
                    - Local certificate for SCEP communication for CRL auto-update. Source certificate.local.name.
                type: str
            scep_url:
                description:
                    - SCEP server URL for CRL auto-update.
                type: str
            source:
                description:
                    - Certificate source type.
                type: str
                choices:
                    - factory
                    - user
                    - bundle
                    - fortiguard
            source_ip:
                description:
                    - Source IP address for communications to a HTTP or SCEP CA server.
                type: str
            update_interval:
                description:
                    - Time in seconds before the FortiGate checks for an updated CRL. Set to 0 to update only when it expires.
                type: int
            update_vdom:
                description:
                    - VDOM for CRL update. Source system.vdom.name.
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
  - name: Certificate Revocation List as a PEM file.
    fortios_certificate_crl:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      certificate_crl:
        crl: "<your_own_value>"
        http_url: "<your_own_value>"
        last_updated: "5"
        ldap_password: "<your_own_value>"
        ldap_server: "<your_own_value>"
        ldap_username: "<your_own_value>"
        name: "default_name_9"
        range: "global"
        scep_cert: "<your_own_value> (source certificate.local.name)"
        scep_url: "<your_own_value>"
        source: "factory"
        source_ip: "84.230.14.43"
        update_interval: "15"
        update_vdom: "<your_own_value> (source system.vdom.name)"

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


def filter_certificate_crl_data(json):
    option_list = ['crl', 'http_url', 'last_updated',
                   'ldap_password', 'ldap_server', 'ldap_username',
                   'name', 'range', 'scep_cert',
                   'scep_url', 'source', 'source_ip',
                   'update_interval', 'update_vdom']
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


def certificate_crl(data, fos):
    vdom = data['vdom']
    state = data['state']
    certificate_crl_data = data['certificate_crl']
    filtered_data = underscore_to_hyphen(filter_certificate_crl_data(certificate_crl_data))

    if state == "present":
        return fos.set('certificate',
                       'crl',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('certificate',
                          'crl',
                          mkey=filtered_data['name'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_certificate(data, fos):

    if data['certificate_crl']:
        resp = certificate_crl(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('certificate_crl'))

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
        "certificate_crl": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "crl": {"required": False, "type": "str"},
                "http_url": {"required": False, "type": "str"},
                "last_updated": {"required": False, "type": "int"},
                "ldap_password": {"required": False, "type": "str"},
                "ldap_server": {"required": False, "type": "str"},
                "ldap_username": {"required": False, "type": "str"},
                "name": {"required": True, "type": "str"},
                "range": {"required": False, "type": "str",
                          "choices": ["global",
                                      "vdom"]},
                "scep_cert": {"required": False, "type": "str"},
                "scep_url": {"required": False, "type": "str"},
                "source": {"required": False, "type": "str",
                           "choices": ["factory",
                                       "user",
                                       "bundle",
                                       "fortiguard"]},
                "source_ip": {"required": False, "type": "str"},
                "update_interval": {"required": False, "type": "int"},
                "update_vdom": {"required": False, "type": "str"}

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

        is_error, has_changed, result = fortios_certificate(module.params, fos)
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
