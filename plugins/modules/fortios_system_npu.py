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
module: fortios_system_npu
short_description: Configure NPU attributes in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and npu category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.2.0
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

    system_npu:
        description:
            - Configure NPU attributes.
        default: null
        type: dict
        suboptions:
            fp_anomaly:
                description:
                    - NP6Lite anomaly protection (packet drop or send trap to host).
                type: dict
                suboptions:
                    esp_minlen_err:
                        description:
                            - Invalid IPv4 ESP short packet anomalies.
                        type: str
                        choices:
                            - drop
                            - trap-to-host
                    icmp_csum_err:
                        description:
                            - Invalid IPv4 ICMP packet checksum anomalies.
                        type: str
                        choices:
                            - drop
                            - trap-to-host
                    icmp_minlen_err:
                        description:
                            - Invalid IPv4 ICMP short packet anomalies.
                        type: str
                        choices:
                            - drop
                            - trap-to-host
                    ipv4_csum_err:
                        description:
                            - Invalid IPv4 packet checksum anomalies.
                        type: str
                        choices:
                            - drop
                            - trap-to-host
                    ipv4_ihl_err:
                        description:
                            - Invalid IPv4 header length anomalies.
                        type: str
                        choices:
                            - drop
                            - trap-to-host
                    ipv4_len_err:
                        description:
                            - Invalid IPv4 packet length anomalies.
                        type: str
                        choices:
                            - drop
                            - trap-to-host
                    ipv4_opt_err:
                        description:
                            - Invalid IPv4 option parsing anomalies.
                        type: str
                        choices:
                            - drop
                            - trap-to-host
                    ipv4_ttlzero_err:
                        description:
                            - Invalid IPv4 TTL field zero anomalies.
                        type: str
                        choices:
                            - drop
                            - trap-to-host
                    ipv4_ver_err:
                        description:
                            - Invalid IPv4 header version anomalies.
                        type: str
                        choices:
                            - drop
                            - trap-to-host
                    ipv6_exthdr_len_err:
                        description:
                            - Invalid IPv6 packet chain extension header total length anomalies.
                        type: str
                        choices:
                            - drop
                            - trap-to-host
                    ipv6_exthdr_order_err:
                        description:
                            - Invalid IPv6 packet extension header ordering anomalies.
                        type: str
                        choices:
                            - drop
                            - trap-to-host
                    ipv6_ihl_err:
                        description:
                            - Invalid IPv6 packet length anomalies.
                        type: str
                        choices:
                            - drop
                            - trap-to-host
                    ipv6_plen_zero:
                        description:
                            - Invalid IPv6 packet payload length zero anomalies.
                        type: str
                        choices:
                            - drop
                            - trap-to-host
                    ipv6_ver_err:
                        description:
                            - Invalid IPv6 packet version anomalies.
                        type: str
                        choices:
                            - drop
                            - trap-to-host
                    tcp_csum_err:
                        description:
                            - Invalid IPv4 TCP packet checksum anomalies.
                        type: str
                        choices:
                            - drop
                            - trap-to-host
                    tcp_hlen_err:
                        description:
                            - Invalid IPv4 TCP header length anomalies.
                        type: str
                        choices:
                            - drop
                            - trap-to-host
                    tcp_plen_err:
                        description:
                            - Invalid IPv4 TCP packet length anomalies.
                        type: str
                        choices:
                            - drop
                            - trap-to-host
                    udp_csum_err:
                        description:
                            - Invalid IPv4 UDP packet checksum anomalies.
                        type: str
                        choices:
                            - drop
                            - trap-to-host
                    udp_hlen_err:
                        description:
                            - Invalid IPv4 UDP packet header length anomalies.
                        type: str
                        choices:
                            - drop
                            - trap-to-host
                    udp_len_err:
                        description:
                            - Invalid IPv4 UDP packet length anomalies.
                        type: str
                        choices:
                            - drop
                            - trap-to-host
                    udp_plen_err:
                        description:
                            - Invalid IPv4 UDP packet minimum length anomalies.
                        type: str
                        choices:
                            - drop
                            - trap-to-host
                    udplite_cover_err:
                        description:
                            - Invalid IPv4 UDP-Lite packet coverage anomalies.
                        type: str
                        choices:
                            - drop
                            - trap-to-host
                    udplite_csum_err:
                        description:
                            - Invalid IPv4 UDP-Lite packet checksum anomalies.
                        type: str
                        choices:
                            - drop
                            - trap-to-host
                    unknproto_minlen_err:
                        description:
                            - Invalid IPv4 L4 unknown protocol short packet anomalies.
                        type: str
                        choices:
                            - drop
                            - trap-to-host
            iph_rsvd_re_cksum:
                description:
                    - Enable/disable IP checksum re-calculation for packets with iph.reserved bit set.
                type: str
                choices:
                    - enable
                    - disable
            per_session_accounting:
                description:
                    - Enable/disable per-session accounting.
                type: str
                choices:
                    - disable
                    - traffic-log-only
                    - enable
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
  - name: Configure NPU attributes.
    fortios_system_npu:
      vdom:  "{{ vdom }}"
      system_npu:
        fp_anomaly:
            esp_minlen_err: "drop"
            icmp_csum_err: "drop"
            icmp_minlen_err: "drop"
            ipv4_csum_err: "drop"
            ipv4_ihl_err: "drop"
            ipv4_len_err: "drop"
            ipv4_opt_err: "drop"
            ipv4_ttlzero_err: "drop"
            ipv4_ver_err: "drop"
            ipv6_exthdr_len_err: "drop"
            ipv6_exthdr_order_err: "drop"
            ipv6_ihl_err: "drop"
            ipv6_plen_zero: "drop"
            ipv6_ver_err: "drop"
            tcp_csum_err: "drop"
            tcp_hlen_err: "drop"
            tcp_plen_err: "drop"
            udp_csum_err: "drop"
            udp_hlen_err: "drop"
            udp_len_err: "drop"
            udp_plen_err: "drop"
            udplite_cover_err: "drop"
            udplite_csum_err: "drop"
            unknproto_minlen_err: "drop"
        iph_rsvd_re_cksum: "enable"
        per_session_accounting: "disable"

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


def filter_system_npu_data(json):
    option_list = ['fp_anomaly', 'iph_rsvd_re_cksum', 'per_session_accounting']
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


def system_npu(data, fos):
    vdom = data['vdom']
    system_npu_data = data['system_npu']
    filtered_data = underscore_to_hyphen(filter_system_npu_data(system_npu_data))

    return fos.set('system',
                   'npu',
                   data=filtered_data,
                   vdom=vdom)


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_system(data, fos):

    if data['system_npu']:
        resp = system_npu(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_npu'))

    return not is_successful_status(resp), \
        resp['status'] == "success" and \
        (resp['revision_changed'] if 'revision_changed' in resp else True), \
        resp


def main():
    mkeyname = None
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "system_npu": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "fp_anomaly": {"required": False, "type": "dict",
                               "options": {
                                   "esp_minlen_err": {"required": False, "type": "str",
                                                      "choices": ["drop",
                                                                  "trap-to-host"]},
                                   "icmp_csum_err": {"required": False, "type": "str",
                                                     "choices": ["drop",
                                                                 "trap-to-host"]},
                                   "icmp_minlen_err": {"required": False, "type": "str",
                                                       "choices": ["drop",
                                                                   "trap-to-host"]},
                                   "ipv4_csum_err": {"required": False, "type": "str",
                                                     "choices": ["drop",
                                                                 "trap-to-host"]},
                                   "ipv4_ihl_err": {"required": False, "type": "str",
                                                    "choices": ["drop",
                                                                "trap-to-host"]},
                                   "ipv4_len_err": {"required": False, "type": "str",
                                                    "choices": ["drop",
                                                                "trap-to-host"]},
                                   "ipv4_opt_err": {"required": False, "type": "str",
                                                    "choices": ["drop",
                                                                "trap-to-host"]},
                                   "ipv4_ttlzero_err": {"required": False, "type": "str",
                                                        "choices": ["drop",
                                                                    "trap-to-host"]},
                                   "ipv4_ver_err": {"required": False, "type": "str",
                                                    "choices": ["drop",
                                                                "trap-to-host"]},
                                   "ipv6_exthdr_len_err": {"required": False, "type": "str",
                                                           "choices": ["drop",
                                                                       "trap-to-host"]},
                                   "ipv6_exthdr_order_err": {"required": False, "type": "str",
                                                             "choices": ["drop",
                                                                         "trap-to-host"]},
                                   "ipv6_ihl_err": {"required": False, "type": "str",
                                                    "choices": ["drop",
                                                                "trap-to-host"]},
                                   "ipv6_plen_zero": {"required": False, "type": "str",
                                                      "choices": ["drop",
                                                                  "trap-to-host"]},
                                   "ipv6_ver_err": {"required": False, "type": "str",
                                                    "choices": ["drop",
                                                                "trap-to-host"]},
                                   "tcp_csum_err": {"required": False, "type": "str",
                                                    "choices": ["drop",
                                                                "trap-to-host"]},
                                   "tcp_hlen_err": {"required": False, "type": "str",
                                                    "choices": ["drop",
                                                                "trap-to-host"]},
                                   "tcp_plen_err": {"required": False, "type": "str",
                                                    "choices": ["drop",
                                                                "trap-to-host"]},
                                   "udp_csum_err": {"required": False, "type": "str",
                                                    "choices": ["drop",
                                                                "trap-to-host"]},
                                   "udp_hlen_err": {"required": False, "type": "str",
                                                    "choices": ["drop",
                                                                "trap-to-host"]},
                                   "udp_len_err": {"required": False, "type": "str",
                                                   "choices": ["drop",
                                                               "trap-to-host"]},
                                   "udp_plen_err": {"required": False, "type": "str",
                                                    "choices": ["drop",
                                                                "trap-to-host"]},
                                   "udplite_cover_err": {"required": False, "type": "str",
                                                         "choices": ["drop",
                                                                     "trap-to-host"]},
                                   "udplite_csum_err": {"required": False, "type": "str",
                                                        "choices": ["drop",
                                                                    "trap-to-host"]},
                                   "unknproto_minlen_err": {"required": False, "type": "str",
                                                            "choices": ["drop",
                                                                        "trap-to-host"]}
                               }},
                "iph_rsvd_re_cksum": {"required": False, "type": "str",
                                      "choices": ["enable",
                                                  "disable"]},
                "per_session_accounting": {"required": False, "type": "str",
                                           "choices": ["disable",
                                                       "traffic-log-only",
                                                       "enable"]}

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
