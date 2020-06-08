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
module: fortios_wireless_controller_setting
short_description: VDOM wireless controller configuration in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify wireless_controller feature and setting category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.2.0
version_added: "2.8"
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
        version_added: 2.9
    wireless_controller_setting:
        description:
            - VDOM wireless controller configuration.
        default: null
        type: dict
        suboptions:
            account_id:
                description:
                    - FortiCloud customer account ID.
                type: str
            country:
                description:
                    - Country or region in which the FortiGate is located. The country determines the 802.11 bands and channels that are available.
                type: str
                choices:
                    - NA
                    - AL
                    - DZ
                    - AO
                    - AR
                    - AM
                    - AU
                    - AT
                    - AZ
                    - BH
                    - BD
                    - BB
                    - BY
                    - BE
                    - BZ
                    - BO
                    - BA
                    - BR
                    - BN
                    - BG
                    - KH
                    - CL
                    - CN
                    - CO
                    - CR
                    - HR
                    - CY
                    - CZ
                    - DK
                    - DO
                    - EC
                    - EG
                    - SV
                    - EE
                    - FI
                    - FR
                    - GE
                    - DE
                    - GR
                    - GL
                    - GD
                    - GU
                    - GT
                    - HT
                    - HN
                    - HK
                    - HU
                    - IS
                    - IN
                    - ID
                    - IR
                    - IE
                    - IL
                    - IT
                    - JM
                    - JO
                    - KZ
                    - KE
                    - KP
                    - KR
                    - KW
                    - LV
                    - LB
                    - LI
                    - LT
                    - LU
                    - MO
                    - MK
                    - MY
                    - MT
                    - MX
                    - MC
                    - MA
                    - MZ
                    - MM
                    - NP
                    - NL
                    - AN
                    - AW
                    - NZ
                    - NO
                    - OM
                    - PK
                    - PA
                    - PG
                    - PY
                    - PE
                    - PH
                    - PL
                    - PT
                    - PR
                    - QA
                    - RO
                    - RU
                    - RW
                    - SA
                    - RS
                    - ME
                    - SG
                    - SK
                    - SI
                    - ZA
                    - ES
                    - LK
                    - SE
                    - SD
                    - CH
                    - SY
                    - TW
                    - TZ
                    - TH
                    - TT
                    - TN
                    - TR
                    - AE
                    - UA
                    - GB
                    - US
                    - PS
                    - UY
                    - UZ
                    - VE
                    - VN
                    - YE
                    - ZB
                    - ZW
                    - JP
                    - CA
            duplicate_ssid:
                description:
                    - Enable/disable allowing Virtual Access Points (VAPs) to use the same SSID name in the same VDOM.
                type: str
                choices:
                    - enable
                    - disable
            fake_ssid_action:
                description:
                    - Actions taken for detected fake SSID.
                type: str
                choices:
                    - log
                    - suppress
            fapc_compatibility:
                description:
                    - Enable/disable FAP-C series compatibility.
                type: str
                choices:
                    - enable
                    - disable
            offending_ssid:
                description:
                    - Configure offending SSID.
                type: list
                suboptions:
                    action:
                        description:
                            - Actions taken for detected offending SSID.
                        type: str
                        choices:
                            - log
                            - suppress
                    id:
                        description:
                            - ID.
                        required: true
                        type: int
                    ssid_pattern:
                        description:
                            - 'Define offending SSID pattern (case insensitive), eg: word, word*, *word, wo*rd.'
                        type: str
            phishing_ssid_detect:
                description:
                    - Enable/disable phishing SSID detection.
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
  - name: VDOM wireless controller configuration.
    fortios_wireless_controller_setting:
      vdom:  "{{ vdom }}"
      wireless_controller_setting:
        account_id: "<your_own_value>"
        country: "NA"
        duplicate_ssid: "enable"
        fake_ssid_action: "log"
        fapc_compatibility: "enable"
        offending_ssid:
         -
            action: "log"
            id:  "10"
            ssid_pattern: "<your_own_value>"
        phishing_ssid_detect: "enable"
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


def filter_wireless_controller_setting_data(json):
    option_list = ['account_id', 'country', 'duplicate_ssid',
                   'fake_ssid_action', 'fapc_compatibility', 'offending_ssid',
                   'phishing_ssid_detect']
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


def wireless_controller_setting(data, fos):
    vdom = data['vdom']
    wireless_controller_setting_data = data['wireless_controller_setting']
    filtered_data = underscore_to_hyphen(filter_wireless_controller_setting_data(wireless_controller_setting_data))

    return fos.set('wireless-controller',
                   'setting',
                   data=filtered_data,
                   vdom=vdom)


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_wireless_controller(data, fos):

    if data['wireless_controller_setting']:
        resp = wireless_controller_setting(data, fos)

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
        "wireless_controller_setting": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "account_id": {"required": False, "type": "str"},
                "country": {"required": False, "type": "str",
                            "choices": ["NA",
                                        "AL",
                                        "DZ",
                                        "AO",
                                        "AR",
                                        "AM",
                                        "AU",
                                        "AT",
                                        "AZ",
                                        "BH",
                                        "BD",
                                        "BB",
                                        "BY",
                                        "BE",
                                        "BZ",
                                        "BO",
                                        "BA",
                                        "BR",
                                        "BN",
                                        "BG",
                                        "KH",
                                        "CL",
                                        "CN",
                                        "CO",
                                        "CR",
                                        "HR",
                                        "CY",
                                        "CZ",
                                        "DK",
                                        "DO",
                                        "EC",
                                        "EG",
                                        "SV",
                                        "EE",
                                        "FI",
                                        "FR",
                                        "GE",
                                        "DE",
                                        "GR",
                                        "GL",
                                        "GD",
                                        "GU",
                                        "GT",
                                        "HT",
                                        "HN",
                                        "HK",
                                        "HU",
                                        "IS",
                                        "IN",
                                        "ID",
                                        "IR",
                                        "IE",
                                        "IL",
                                        "IT",
                                        "JM",
                                        "JO",
                                        "KZ",
                                        "KE",
                                        "KP",
                                        "KR",
                                        "KW",
                                        "LV",
                                        "LB",
                                        "LI",
                                        "LT",
                                        "LU",
                                        "MO",
                                        "MK",
                                        "MY",
                                        "MT",
                                        "MX",
                                        "MC",
                                        "MA",
                                        "MZ",
                                        "MM",
                                        "NP",
                                        "NL",
                                        "AN",
                                        "AW",
                                        "NZ",
                                        "NO",
                                        "OM",
                                        "PK",
                                        "PA",
                                        "PG",
                                        "PY",
                                        "PE",
                                        "PH",
                                        "PL",
                                        "PT",
                                        "PR",
                                        "QA",
                                        "RO",
                                        "RU",
                                        "RW",
                                        "SA",
                                        "RS",
                                        "ME",
                                        "SG",
                                        "SK",
                                        "SI",
                                        "ZA",
                                        "ES",
                                        "LK",
                                        "SE",
                                        "SD",
                                        "CH",
                                        "SY",
                                        "TW",
                                        "TZ",
                                        "TH",
                                        "TT",
                                        "TN",
                                        "TR",
                                        "AE",
                                        "UA",
                                        "GB",
                                        "US",
                                        "PS",
                                        "UY",
                                        "UZ",
                                        "VE",
                                        "VN",
                                        "YE",
                                        "ZB",
                                        "ZW",
                                        "JP",
                                        "CA"]},
                "duplicate_ssid": {"required": False, "type": "str",
                                   "choices": ["enable",
                                               "disable"]},
                "fake_ssid_action": {"required": False, "type": "str",
                                     "choices": ["log",
                                                 "suppress"]},
                "fapc_compatibility": {"required": False, "type": "str",
                                       "choices": ["enable",
                                                   "disable"]},
                "offending_ssid": {"required": False, "type": "list",
                                   "options": {
                                       "action": {"required": False, "type": "str",
                                                  "choices": ["log",
                                                              "suppress"]},
                                       "id": {"required": True, "type": "int"},
                                       "ssid_pattern": {"required": False, "type": "str"}
                                   }},
                "phishing_ssid_detect": {"required": False, "type": "str",
                                         "choices": ["enable",
                                                     "disable"]}

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

            is_error, has_changed, result = fortios_wireless_controller(module.params, fos)
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
        is_error, has_changed, result = fortios_wireless_controller(module.params, fos)
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
