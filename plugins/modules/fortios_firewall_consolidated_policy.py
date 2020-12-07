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
module: fortios_firewall_consolidated_policy
short_description: Configure consolidated IPv4/IPv6 policies in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall_consolidated feature and policy category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.2.0
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
    firewall_consolidated_policy:
        description:
            - Configure consolidated IPv4/IPv6 policies.
        default: null
        type: dict
        suboptions:
            action:
                description:
                    - Policy action (allow/deny/ipsec).
                type: str
                choices:
                    - accept
                    - deny
                    - ipsec
            app_category:
                description:
                    - Application category ID list.
                type: list
                suboptions:
                    id:
                        description:
                            - Category IDs.
                        required: true
                        type: int
            app_group:
                description:
                    - Application group names.
                type: list
                suboptions:
                    name:
                        description:
                            - Application group names. Source application.group.name.
                        required: true
                        type: str
            application:
                description:
                    - Application ID list.
                type: list
                suboptions:
                    id:
                        description:
                            - Application IDs.
                        required: true
                        type: int
            application_list:
                description:
                    - Name of an existing Application list. Source application.list.name.
                type: str
            av_profile:
                description:
                    - Name of an existing Antivirus profile. Source antivirus.profile.name.
                type: str
            cifs_profile:
                description:
                    - Name of an existing CIFS profile. Source cifs.profile.name.
                type: str
            comments:
                description:
                    - Comment.
                type: str
            diffserv_forward:
                description:
                    - Enable to change packet"s DiffServ values to the specified diffservcode-forward value.
                type: str
                choices:
                    - enable
                    - disable
            diffserv_reverse:
                description:
                    - Enable to change packet"s reverse (reply) DiffServ values to the specified diffservcode-rev value.
                type: str
                choices:
                    - enable
                    - disable
            diffservcode_forward:
                description:
                    - Change packet"s DiffServ to this value.
                type: str
            diffservcode_rev:
                description:
                    - Change packet"s reverse (reply) DiffServ to this value.
                type: str
            dlp_sensor:
                description:
                    - Name of an existing DLP sensor. Source dlp.sensor.name.
                type: str
            dnsfilter_profile:
                description:
                    - Name of an existing DNS filter profile. Source dnsfilter.profile.name.
                type: str
            dstaddr4:
                description:
                    - Destination IPv4 address name and address group names.
                type: list
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name firewall.vip.name firewall.vipgrp.name system.external-resource
                              .name.
                        required: true
                        type: str
            dstaddr6:
                description:
                    - Destination IPv6 address name and address group names.
                type: list
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name firewall.addrgrp6.name firewall.vip6.name firewall.vipgrp6.name system
                              .external-resource.name.
                        required: true
                        type: str
            dstintf:
                description:
                    - Outgoing (egress) interface.
                type: list
                suboptions:
                    name:
                        description:
                            - Interface name. Source system.interface.name system.zone.name.
                        required: true
                        type: str
            emailfilter_profile:
                description:
                    - Name of an existing email filter profile. Source emailfilter.profile.name.
                type: str
            fixedport:
                description:
                    - Enable to prevent source NAT from changing a session"s source port.
                type: str
                choices:
                    - enable
                    - disable
            groups:
                description:
                    - Names of user groups that can authenticate with this policy.
                type: list
                suboptions:
                    name:
                        description:
                            - Group name. Source user.group.name.
                        required: true
                        type: str
            http_policy_redirect:
                description:
                    - Redirect HTTP(S) traffic to matching transparent web proxy policy.
                type: str
                choices:
                    - enable
                    - disable
            icap_profile:
                description:
                    - Name of an existing ICAP profile. Source icap.profile.name.
                type: str
            inbound:
                description:
                    - 'Policy-based IPsec VPN: only traffic from the remote network can initiate a VPN.'
                type: str
                choices:
                    - enable
                    - disable
            inspection_mode:
                description:
                    - Inspection mode.
                type: str
                choices:
                    - proxy
                    - flow
            ippool:
                description:
                    - Enable to use IP Pools for source NAT.
                type: str
                choices:
                    - enable
                    - disable
            ips_sensor:
                description:
                    - Name of an existing IPS sensor. Source ips.sensor.name.
                type: str
            logtraffic:
                description:
                    - Enable or disable logging. Log all sessions or security profile sessions.
                type: str
                choices:
                    - all
                    - utm
                    - disable
            logtraffic_start:
                description:
                    - Record logs when a session starts.
                type: str
                choices:
                    - enable
                    - disable
            name:
                description:
                    - Policy name.
                type: str
            nat:
                description:
                    - Enable/disable source NAT.
                type: str
                choices:
                    - enable
                    - disable
            outbound:
                description:
                    - 'Policy-based IPsec VPN: only traffic from the internal network can initiate a VPN.'
                type: str
                choices:
                    - enable
                    - disable
            per_ip_shaper:
                description:
                    - Per-IP traffic shaper. Source firewall.shaper.per-ip-shaper.name.
                type: str
            policyid:
                description:
                    - Policy ID (0 - 4294967294).
                required: true
                type: int
            poolname4:
                description:
                    - IPv4 pool names.
                type: list
                suboptions:
                    name:
                        description:
                            - IPv4 pool name. Source firewall.ippool.name.
                        required: true
                        type: str
            poolname6:
                description:
                    - IPv6 pool names.
                type: list
                suboptions:
                    name:
                        description:
                            - IPv6 pool name. Source firewall.ippool6.name.
                        required: true
                        type: str
            profile_group:
                description:
                    - Name of profile group. Source firewall.profile-group.name.
                type: str
            profile_protocol_options:
                description:
                    - Name of an existing Protocol options profile. Source firewall.profile-protocol-options.name.
                type: str
            profile_type:
                description:
                    - Determine whether the firewall policy allows security profile groups or single profiles only.
                type: str
                choices:
                    - single
                    - group
            schedule:
                description:
                    - Schedule name. Source firewall.schedule.onetime.name firewall.schedule.recurring.name firewall.schedule.group.name.
                type: str
            service:
                description:
                    - Service and service group names.
                type: list
                suboptions:
                    name:
                        description:
                            - Service name. Source firewall.service.custom.name firewall.service.group.name.
                        required: true
                        type: str
            session_ttl:
                description:
                    - TTL in seconds for sessions accepted by this policy (0 means use the system ).
                type: int
            srcaddr4:
                description:
                    - Source IPv4 address name and address group names.
                type: list
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name system.external-resource.name.
                        required: true
                        type: str
            srcaddr6:
                description:
                    - Source IPv6 address name and address group names.
                type: list
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name firewall.addrgrp6.name system.external-resource.name.
                        required: true
                        type: str
            srcintf:
                description:
                    - Incoming (ingress) interface.
                type: list
                suboptions:
                    name:
                        description:
                            - Interface name. Source system.interface.name system.zone.name.
                        required: true
                        type: str
            ssh_filter_profile:
                description:
                    - Name of an existing SSH filter profile. Source ssh-filter.profile.name.
                type: str
            ssh_policy_redirect:
                description:
                    - Redirect SSH traffic to matching transparent proxy policy.
                type: str
                choices:
                    - enable
                    - disable
            ssl_ssh_profile:
                description:
                    - Name of an existing SSL SSH profile. Source firewall.ssl-ssh-profile.name.
                type: str
            status:
                description:
                    - Enable or disable this policy.
                type: str
                choices:
                    - enable
                    - disable
            tcp_mss_receiver:
                description:
                    - Receiver TCP maximum segment size (MSS).
                type: int
            tcp_mss_sender:
                description:
                    - Sender TCP maximum segment size (MSS).
                type: int
            traffic_shaper:
                description:
                    - Traffic shaper. Source firewall.shaper.traffic-shaper.name.
                type: str
            traffic_shaper_reverse:
                description:
                    - Reverse traffic shaper. Source firewall.shaper.traffic-shaper.name.
                type: str
            url_category:
                description:
                    - URL category ID list.
                type: list
                suboptions:
                    id:
                        description:
                            - URL category ID.
                        required: true
                        type: int
            users:
                description:
                    - Names of individual users that can authenticate with this policy.
                type: list
                suboptions:
                    name:
                        description:
                            - User name. Source user.local.name.
                        required: true
                        type: str
            utm_status:
                description:
                    - Enable to add one or more security profiles (AV, IPS, etc.) to the firewall policy.
                type: str
                choices:
                    - enable
                    - disable
            uuid:
                description:
                    - Universally Unique Identifier (UUID; automatically assigned but can be manually reset).
                type: str
            voip_profile:
                description:
                    - Name of an existing VoIP profile. Source voip.profile.name.
                type: str
            vpntunnel:
                description:
                    - 'Policy-based IPsec VPN: name of the IPsec VPN Phase 1. Source vpn.ipsec.phase1.name vpn.ipsec.manualkey.name.'
                type: str
            waf_profile:
                description:
                    - Name of an existing Web application firewall profile. Source waf.profile.name.
                type: str
            webfilter_profile:
                description:
                    - Name of an existing Web filter profile. Source webfilter.profile.name.
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
  - name: Configure consolidated IPv4/IPv6 policies.
    fortios_firewall_consolidated_policy:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_consolidated_policy:
        action: "accept"
        app_category:
         -
            id:  "5"
        app_group:
         -
            name: "default_name_7 (source application.group.name)"
        application:
         -
            id:  "9"
        application_list: "<your_own_value> (source application.list.name)"
        av_profile: "<your_own_value> (source antivirus.profile.name)"
        cifs_profile: "<your_own_value> (source cifs.profile.name)"
        comments: "<your_own_value>"
        diffserv_forward: "enable"
        diffserv_reverse: "enable"
        diffservcode_forward: "<your_own_value>"
        diffservcode_rev: "<your_own_value>"
        dlp_sensor: "<your_own_value> (source dlp.sensor.name)"
        dnsfilter_profile: "<your_own_value> (source dnsfilter.profile.name)"
        dstaddr4:
         -
            name: "default_name_21 (source firewall.address.name firewall.addrgrp.name firewall.vip.name firewall.vipgrp.name system.external-resource.name)"
        dstaddr6:
         -
            name: "default_name_23 (source firewall.address6.name firewall.addrgrp6.name firewall.vip6.name firewall.vipgrp6.name system.external-resource
              .name)"
        dstintf:
         -
            name: "default_name_25 (source system.interface.name system.zone.name)"
        emailfilter_profile: "<your_own_value> (source emailfilter.profile.name)"
        fixedport: "enable"
        groups:
         -
            name: "default_name_29 (source user.group.name)"
        http_policy_redirect: "enable"
        icap_profile: "<your_own_value> (source icap.profile.name)"
        inbound: "enable"
        inspection_mode: "proxy"
        ippool: "enable"
        ips_sensor: "<your_own_value> (source ips.sensor.name)"
        logtraffic: "all"
        logtraffic_start: "enable"
        name: "default_name_38"
        nat: "enable"
        outbound: "enable"
        per_ip_shaper: "<your_own_value> (source firewall.shaper.per-ip-shaper.name)"
        policyid: "42"
        poolname4:
         -
            name: "default_name_44 (source firewall.ippool.name)"
        poolname6:
         -
            name: "default_name_46 (source firewall.ippool6.name)"
        profile_group: "<your_own_value> (source firewall.profile-group.name)"
        profile_protocol_options: "<your_own_value> (source firewall.profile-protocol-options.name)"
        profile_type: "single"
        schedule: "<your_own_value> (source firewall.schedule.onetime.name firewall.schedule.recurring.name firewall.schedule.group.name)"
        service:
         -
            name: "default_name_52 (source firewall.service.custom.name firewall.service.group.name)"
        session_ttl: "53"
        srcaddr4:
         -
            name: "default_name_55 (source firewall.address.name firewall.addrgrp.name system.external-resource.name)"
        srcaddr6:
         -
            name: "default_name_57 (source firewall.address6.name firewall.addrgrp6.name system.external-resource.name)"
        srcintf:
         -
            name: "default_name_59 (source system.interface.name system.zone.name)"
        ssh_filter_profile: "<your_own_value> (source ssh-filter.profile.name)"
        ssh_policy_redirect: "enable"
        ssl_ssh_profile: "<your_own_value> (source firewall.ssl-ssh-profile.name)"
        status: "enable"
        tcp_mss_receiver: "64"
        tcp_mss_sender: "65"
        traffic_shaper: "<your_own_value> (source firewall.shaper.traffic-shaper.name)"
        traffic_shaper_reverse: "<your_own_value> (source firewall.shaper.traffic-shaper.name)"
        url_category:
         -
            id:  "69"
        users:
         -
            name: "default_name_71 (source user.local.name)"
        utm_status: "enable"
        uuid: "<your_own_value>"
        voip_profile: "<your_own_value> (source voip.profile.name)"
        vpntunnel: "<your_own_value> (source vpn.ipsec.phase1.name vpn.ipsec.manualkey.name)"
        waf_profile: "<your_own_value> (source waf.profile.name)"
        webfilter_profile: "<your_own_value> (source webfilter.profile.name)"

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


def filter_firewall_consolidated_policy_data(json):
    option_list = ['action', 'app_category', 'app_group',
                   'application', 'application_list', 'av_profile',
                   'cifs_profile', 'comments', 'diffserv_forward',
                   'diffserv_reverse', 'diffservcode_forward', 'diffservcode_rev',
                   'dlp_sensor', 'dnsfilter_profile', 'dstaddr4',
                   'dstaddr6', 'dstintf', 'emailfilter_profile',
                   'fixedport', 'groups', 'http_policy_redirect',
                   'icap_profile', 'inbound', 'inspection_mode',
                   'ippool', 'ips_sensor', 'logtraffic',
                   'logtraffic_start', 'name', 'nat',
                   'outbound', 'per_ip_shaper', 'policyid',
                   'poolname4', 'poolname6', 'profile_group',
                   'profile_protocol_options', 'profile_type', 'schedule',
                   'service', 'session_ttl', 'srcaddr4',
                   'srcaddr6', 'srcintf', 'ssh_filter_profile',
                   'ssh_policy_redirect', 'ssl_ssh_profile', 'status',
                   'tcp_mss_receiver', 'tcp_mss_sender', 'traffic_shaper',
                   'traffic_shaper_reverse', 'url_category', 'users',
                   'utm_status', 'uuid', 'voip_profile',
                   'vpntunnel', 'waf_profile', 'webfilter_profile']
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


def firewall_consolidated_policy(data, fos):
    vdom = data['vdom']
    state = data['state']
    firewall_consolidated_policy_data = data['firewall_consolidated_policy']
    filtered_data = underscore_to_hyphen(filter_firewall_consolidated_policy_data(firewall_consolidated_policy_data))

    if state == "present":
        return fos.set('firewall.consolidated',
                       'policy',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('firewall.consolidated',
                          'policy',
                          mkey=filtered_data['policyid'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_firewall_consolidated(data, fos):

    if data['firewall_consolidated_policy']:
        resp = firewall_consolidated_policy(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('firewall_consolidated_policy'))

    return not is_successful_status(resp), \
        resp['status'] == "success" and \
        (resp['revision_changed'] if 'revision_changed' in resp else True), \
        resp


def main():
    mkeyname = 'policyid'
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "state": {"required": True, "type": "str",
                  "choices": ["present", "absent"]},
        "firewall_consolidated_policy": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "action": {"required": False, "type": "str",
                           "choices": ["accept",
                                       "deny",
                                       "ipsec"]},
                "app_category": {"required": False, "type": "list",
                                 "options": {
                                     "id": {"required": True, "type": "int"}
                                 }},
                "app_group": {"required": False, "type": "list",
                              "options": {
                                  "name": {"required": True, "type": "str"}
                              }},
                "application": {"required": False, "type": "list",
                                "options": {
                                    "id": {"required": True, "type": "int"}
                                }},
                "application_list": {"required": False, "type": "str"},
                "av_profile": {"required": False, "type": "str"},
                "cifs_profile": {"required": False, "type": "str"},
                "comments": {"required": False, "type": "str"},
                "diffserv_forward": {"required": False, "type": "str",
                                     "choices": ["enable",
                                                 "disable"]},
                "diffserv_reverse": {"required": False, "type": "str",
                                     "choices": ["enable",
                                                 "disable"]},
                "diffservcode_forward": {"required": False, "type": "str"},
                "diffservcode_rev": {"required": False, "type": "str"},
                "dlp_sensor": {"required": False, "type": "str"},
                "dnsfilter_profile": {"required": False, "type": "str"},
                "dstaddr4": {"required": False, "type": "list",
                             "options": {
                                 "name": {"required": True, "type": "str"}
                             }},
                "dstaddr6": {"required": False, "type": "list",
                             "options": {
                                 "name": {"required": True, "type": "str"}
                             }},
                "dstintf": {"required": False, "type": "list",
                            "options": {
                                "name": {"required": True, "type": "str"}
                            }},
                "emailfilter_profile": {"required": False, "type": "str"},
                "fixedport": {"required": False, "type": "str",
                              "choices": ["enable",
                                          "disable"]},
                "groups": {"required": False, "type": "list",
                           "options": {
                               "name": {"required": True, "type": "str"}
                           }},
                "http_policy_redirect": {"required": False, "type": "str",
                                         "choices": ["enable",
                                                     "disable"]},
                "icap_profile": {"required": False, "type": "str"},
                "inbound": {"required": False, "type": "str",
                            "choices": ["enable",
                                        "disable"]},
                "inspection_mode": {"required": False, "type": "str",
                                    "choices": ["proxy",
                                                "flow"]},
                "ippool": {"required": False, "type": "str",
                           "choices": ["enable",
                                       "disable"]},
                "ips_sensor": {"required": False, "type": "str"},
                "logtraffic": {"required": False, "type": "str",
                               "choices": ["all",
                                           "utm",
                                           "disable"]},
                "logtraffic_start": {"required": False, "type": "str",
                                     "choices": ["enable",
                                                 "disable"]},
                "name": {"required": False, "type": "str"},
                "nat": {"required": False, "type": "str",
                        "choices": ["enable",
                                    "disable"]},
                "outbound": {"required": False, "type": "str",
                             "choices": ["enable",
                                         "disable"]},
                "per_ip_shaper": {"required": False, "type": "str"},
                "policyid": {"required": True, "type": "int"},
                "poolname4": {"required": False, "type": "list",
                              "options": {
                                  "name": {"required": True, "type": "str"}
                              }},
                "poolname6": {"required": False, "type": "list",
                              "options": {
                                  "name": {"required": True, "type": "str"}
                              }},
                "profile_group": {"required": False, "type": "str"},
                "profile_protocol_options": {"required": False, "type": "str"},
                "profile_type": {"required": False, "type": "str",
                                 "choices": ["single",
                                             "group"]},
                "schedule": {"required": False, "type": "str"},
                "service": {"required": False, "type": "list",
                            "options": {
                                "name": {"required": True, "type": "str"}
                            }},
                "session_ttl": {"required": False, "type": "int"},
                "srcaddr4": {"required": False, "type": "list",
                             "options": {
                                 "name": {"required": True, "type": "str"}
                             }},
                "srcaddr6": {"required": False, "type": "list",
                             "options": {
                                 "name": {"required": True, "type": "str"}
                             }},
                "srcintf": {"required": False, "type": "list",
                            "options": {
                                "name": {"required": True, "type": "str"}
                            }},
                "ssh_filter_profile": {"required": False, "type": "str"},
                "ssh_policy_redirect": {"required": False, "type": "str",
                                        "choices": ["enable",
                                                    "disable"]},
                "ssl_ssh_profile": {"required": False, "type": "str"},
                "status": {"required": False, "type": "str",
                           "choices": ["enable",
                                       "disable"]},
                "tcp_mss_receiver": {"required": False, "type": "int"},
                "tcp_mss_sender": {"required": False, "type": "int"},
                "traffic_shaper": {"required": False, "type": "str"},
                "traffic_shaper_reverse": {"required": False, "type": "str"},
                "url_category": {"required": False, "type": "list",
                                 "options": {
                                     "id": {"required": True, "type": "int"}
                                 }},
                "users": {"required": False, "type": "list",
                          "options": {
                              "name": {"required": True, "type": "str"}
                          }},
                "utm_status": {"required": False, "type": "str",
                               "choices": ["enable",
                                           "disable"]},
                "uuid": {"required": False, "type": "str"},
                "voip_profile": {"required": False, "type": "str"},
                "vpntunnel": {"required": False, "type": "str"},
                "waf_profile": {"required": False, "type": "str"},
                "webfilter_profile": {"required": False, "type": "str"}

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

        is_error, has_changed, result = fortios_firewall_consolidated(module.params, fos)
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
