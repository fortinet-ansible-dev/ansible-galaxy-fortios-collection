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
module: fortios_log_threat_weight
short_description: Configure threat weight settings in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify log feature and threat_weight category.
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

    log_threat_weight:
        description:
            - Configure threat weight settings.
        default: null
        type: dict
        suboptions:
            application:
                description:
                    - Application-control threat weight settings.
                type: list
                suboptions:
                    category:
                        description:
                            - Application category.
                        type: int
                    id:
                        description:
                            - Entry ID.
                        required: true
                        type: int
                    level:
                        description:
                            - Threat weight score for Application events.
                        type: str
                        choices:
                            - disable
                            - low
                            - medium
                            - high
                            - critical
            blocked_connection:
                description:
                    - Threat weight score for blocked connections.
                type: str
                choices:
                    - disable
                    - low
                    - medium
                    - high
                    - critical
            botnet_connection_detected:
                description:
                    - Threat weight score for detected botnet connections.
                type: str
                choices:
                    - disable
                    - low
                    - medium
                    - high
                    - critical
            failed_connection:
                description:
                    - Threat weight score for failed connections.
                type: str
                choices:
                    - disable
                    - low
                    - medium
                    - high
                    - critical
            geolocation:
                description:
                    - Geolocation-based threat weight settings.
                type: list
                suboptions:
                    country:
                        description:
                            - Country code.
                        type: str
                    id:
                        description:
                            - Entry ID.
                        required: true
                        type: int
                    level:
                        description:
                            - Threat weight score for Geolocation-based events.
                        type: str
                        choices:
                            - disable
                            - low
                            - medium
                            - high
                            - critical
            ips:
                description:
                    - IPS threat weight settings.
                type: dict
                suboptions:
                    critical_severity:
                        description:
                            - Threat weight score for IPS critical severity events.
                        type: str
                        choices:
                            - disable
                            - low
                            - medium
                            - high
                            - critical
                    high_severity:
                        description:
                            - Threat weight score for IPS high severity events.
                        type: str
                        choices:
                            - disable
                            - low
                            - medium
                            - high
                            - critical
                    info_severity:
                        description:
                            - Threat weight score for IPS info severity events.
                        type: str
                        choices:
                            - disable
                            - low
                            - medium
                            - high
                            - critical
                    low_severity:
                        description:
                            - Threat weight score for IPS low severity events.
                        type: str
                        choices:
                            - disable
                            - low
                            - medium
                            - high
                            - critical
                    medium_severity:
                        description:
                            - Threat weight score for IPS medium severity events.
                        type: str
                        choices:
                            - disable
                            - low
                            - medium
                            - high
                            - critical
            level:
                description:
                    - Score mapping for threat weight levels.
                type: dict
                suboptions:
                    critical:
                        description:
                            - Critical level score value (1 - 100).
                        type: int
                    high:
                        description:
                            - High level score value (1 - 100).
                        type: int
                    low:
                        description:
                            - Low level score value (1 - 100).
                        type: int
                    medium:
                        description:
                            - Medium level score value (1 - 100).
                        type: int
            malware_detected:
                description:
                    - Threat weight score for detected malware.
                type: str
                choices:
                    - disable
                    - low
                    - medium
                    - high
                    - critical
            status:
                description:
                    - Enable/disable the threat weight feature.
                type: str
                choices:
                    - enable
                    - disable
            url_block_detected:
                description:
                    - Threat weight score for URL blocking.
                type: str
                choices:
                    - disable
                    - low
                    - medium
                    - high
                    - critical
            web:
                description:
                    - Web filtering threat weight settings.
                type: list
                suboptions:
                    category:
                        description:
                            - Threat weight score for web category filtering matches.
                        type: int
                    id:
                        description:
                            - Entry ID.
                        required: true
                        type: int
                    level:
                        description:
                            - Threat weight score for web category filtering matches.
                        type: str
                        choices:
                            - disable
                            - low
                            - medium
                            - high
                            - critical
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
  - name: Configure threat weight settings.
    fortios_log_threat_weight:
      vdom:  "{{ vdom }}"
      log_threat_weight:
        application:
         -
            category: "4"
            id:  "5"
            level: "disable"
        blocked_connection: "disable"
        botnet_connection_detected: "disable"
        failed_connection: "disable"
        geolocation:
         -
            country: "<your_own_value>"
            id:  "12"
            level: "disable"
        ips:
            critical_severity: "disable"
            high_severity: "disable"
            info_severity: "disable"
            low_severity: "disable"
            medium_severity: "disable"
        level:
            critical: "21"
            high: "22"
            low: "23"
            medium: "24"
        malware_detected: "disable"
        status: "enable"
        url_block_detected: "disable"
        web:
         -
            category: "29"
            id:  "30"
            level: "disable"

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


def filter_log_threat_weight_data(json):
    option_list = ['application', 'blocked_connection', 'botnet_connection_detected',
                   'failed_connection', 'geolocation', 'ips',
                   'level', 'malware_detected', 'status',
                   'url_block_detected', 'web']
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


def log_threat_weight(data, fos):
    vdom = data['vdom']
    log_threat_weight_data = data['log_threat_weight']
    filtered_data = underscore_to_hyphen(filter_log_threat_weight_data(log_threat_weight_data))

    return fos.set('log',
                   'threat-weight',
                   data=filtered_data,
                   vdom=vdom)


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_log(data, fos):

    if data['log_threat_weight']:
        resp = log_threat_weight(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('log_threat_weight'))

    return not is_successful_status(resp), \
        resp['status'] == "success" and \
        (resp['revision_changed'] if 'revision_changed' in resp else True), \
        resp


def main():
    mkeyname = None
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "log_threat_weight": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "application": {"required": False, "type": "list",
                                "options": {
                                    "category": {"required": False, "type": "int"},
                                    "id": {"required": True, "type": "int"},
                                    "level": {"required": False, "type": "str",
                                              "choices": ["disable",
                                                          "low",
                                                          "medium",
                                                          "high",
                                                          "critical"]}
                                }},
                "blocked_connection": {"required": False, "type": "str",
                                       "choices": ["disable",
                                                   "low",
                                                   "medium",
                                                   "high",
                                                   "critical"]},
                "botnet_connection_detected": {"required": False, "type": "str",
                                               "choices": ["disable",
                                                           "low",
                                                           "medium",
                                                           "high",
                                                           "critical"]},
                "failed_connection": {"required": False, "type": "str",
                                      "choices": ["disable",
                                                  "low",
                                                  "medium",
                                                  "high",
                                                  "critical"]},
                "geolocation": {"required": False, "type": "list",
                                "options": {
                                    "country": {"required": False, "type": "str"},
                                    "id": {"required": True, "type": "int"},
                                    "level": {"required": False, "type": "str",
                                              "choices": ["disable",
                                                          "low",
                                                          "medium",
                                                          "high",
                                                          "critical"]}
                                }},
                "ips": {"required": False, "type": "dict",
                        "options": {
                            "critical_severity": {"required": False, "type": "str",
                                                  "choices": ["disable",
                                                              "low",
                                                              "medium",
                                                              "high",
                                                              "critical"]},
                            "high_severity": {"required": False, "type": "str",
                                              "choices": ["disable",
                                                          "low",
                                                          "medium",
                                                          "high",
                                                          "critical"]},
                            "info_severity": {"required": False, "type": "str",
                                              "choices": ["disable",
                                                          "low",
                                                          "medium",
                                                          "high",
                                                          "critical"]},
                            "low_severity": {"required": False, "type": "str",
                                             "choices": ["disable",
                                                         "low",
                                                         "medium",
                                                         "high",
                                                         "critical"]},
                            "medium_severity": {"required": False, "type": "str",
                                                "choices": ["disable",
                                                            "low",
                                                            "medium",
                                                            "high",
                                                            "critical"]}
                        }},
                "level": {"required": False, "type": "dict",
                          "options": {
                              "critical": {"required": False, "type": "int"},
                              "high": {"required": False, "type": "int"},
                              "low": {"required": False, "type": "int"},
                              "medium": {"required": False, "type": "int"}
                          }},
                "malware_detected": {"required": False, "type": "str",
                                     "choices": ["disable",
                                                 "low",
                                                 "medium",
                                                 "high",
                                                 "critical"]},
                "status": {"required": False, "type": "str",
                           "choices": ["enable",
                                       "disable"]},
                "url_block_detected": {"required": False, "type": "str",
                                       "choices": ["disable",
                                                   "low",
                                                   "medium",
                                                   "high",
                                                   "critical"]},
                "web": {"required": False, "type": "list",
                        "options": {
                            "category": {"required": False, "type": "int"},
                            "id": {"required": True, "type": "int"},
                            "level": {"required": False, "type": "str",
                                      "choices": ["disable",
                                                  "low",
                                                  "medium",
                                                  "high",
                                                  "critical"]}
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

        is_error, has_changed, result = fortios_log(module.params, fos)
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
