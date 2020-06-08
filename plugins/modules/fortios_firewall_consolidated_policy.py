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
      Tested with FOS v6.4.0
version_added: "2.9"
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
            application_list:
                description:
                    - Name of an existing Application list. Source application.list.name.
                type: str
            auto_asic_offload:
                description:
                    - Enable/disable policy traffic ASIC offloading.
                type: str
                choices:
                    - enable
                    - disable
            av_profile:
                description:
                    - Name of an existing Antivirus profile. Source antivirus.profile.name.
                type: str
            captive_portal_exempt:
                description:
                    - Enable exemption of some users from the captive portal.
                type: str
                choices:
                    - enable
                    - disable
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
            dstaddr_negate:
                description:
                    - When enabled dstaddr specifies what the destination address must NOT be.
                type: str
                choices:
                    - enable
                    - disable
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
            fsso_groups:
                description:
                    - Names of FSSO groups.
                type: list
                suboptions:
                    name:
                        description:
                            - Names of FSSO groups. Source user.adgrp.name.
                        required: true
                        type: str
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
                    - Policy inspection mode (Flow/proxy). Default is Flow mode.
                type: str
                choices:
                    - proxy
                    - flow
            internet_service:
                description:
                    - Enable/disable use of Internet Services for this policy. If enabled, destination address and service are not used.
                type: str
                choices:
                    - enable
                    - disable
            internet_service_custom:
                description:
                    - Custom Internet Service name.
                type: list
                suboptions:
                    name:
                        description:
                            - Custom Internet Service name. Source firewall.internet-service-custom.name.
                        required: true
                        type: str
            internet_service_custom_group:
                description:
                    - Custom Internet Service group name.
                type: list
                suboptions:
                    name:
                        description:
                            - Custom Internet Service group name. Source firewall.internet-service-custom-group.name.
                        required: true
                        type: str
            internet_service_group:
                description:
                    - Internet Service group name.
                type: list
                suboptions:
                    name:
                        description:
                            - Internet Service group name. Source firewall.internet-service-group.name.
                        required: true
                        type: str
            internet_service_name:
                description:
                    - Internet Service name.
                type: list
                suboptions:
                    name:
                        description:
                            - Internet Service name. Source firewall.internet-service-name.name.
                        required: true
                        type: str
            internet_service_negate:
                description:
                    - When enabled internet-service specifies what the service must NOT be.
                type: str
                choices:
                    - enable
                    - disable
            internet_service_src:
                description:
                    - Enable/disable use of Internet Services in source for this policy. If enabled, source address is not used.
                type: str
                choices:
                    - enable
                    - disable
            internet_service_src_custom:
                description:
                    - Custom Internet Service source name.
                type: list
                suboptions:
                    name:
                        description:
                            - Custom Internet Service name. Source firewall.internet-service-custom.name.
                        required: true
                        type: str
            internet_service_src_custom_group:
                description:
                    - Custom Internet Service source group name.
                type: list
                suboptions:
                    name:
                        description:
                            - Custom Internet Service group name. Source firewall.internet-service-custom-group.name.
                        required: true
                        type: str
            internet_service_src_group:
                description:
                    - Internet Service source group name.
                type: list
                suboptions:
                    name:
                        description:
                            - Internet Service group name. Source firewall.internet-service-group.name.
                        required: true
                        type: str
            internet_service_src_name:
                description:
                    - Internet Service source name.
                type: list
                suboptions:
                    name:
                        description:
                            - Internet Service name. Source firewall.internet-service-name.name.
                        required: true
                        type: str
            internet_service_src_negate:
                description:
                    - When enabled internet-service-src specifies what the service must NOT be.
                type: str
                choices:
                    - enable
                    - disable
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
            service_negate:
                description:
                    - When enabled service specifies what the service must NOT be.
                type: str
                choices:
                    - enable
                    - disable
            session_ttl:
                description:
                    - TTL in seconds for sessions accepted by this policy (0 means use the system ).
                type: int
            srcaddr_negate:
                description:
                    - When enabled srcaddr specifies what the source address must NOT be.
                type: str
                choices:
                    - enable
                    - disable
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
            wanopt:
                description:
                    - Enable/disable WAN optimization.
                type: str
                choices:
                    - enable
                    - disable
            wanopt_detection:
                description:
                    - WAN optimization auto-detection mode.
                type: str
                choices:
                    - active
                    - passive
                    - off
            wanopt_passive_opt:
                description:
                    - WAN optimization passive mode options. This option decides what IP address will be used to connect to server.
                type: str
                choices:
                    - default
                    - transparent
                    - non-transparent
            wanopt_peer:
                description:
                    - WAN optimization peer. Source wanopt.peer.peer-host-id.
                type: str
            wanopt_profile:
                description:
                    - WAN optimization profile. Source wanopt.profile.name.
                type: str
            webcache:
                description:
                    - Enable/disable web cache.
                type: str
                choices:
                    - enable
                    - disable
            webcache_https:
                description:
                    - Enable/disable web cache for HTTPS.
                type: str
                choices:
                    - disable
                    - enable
            webfilter_profile:
                description:
                    - Name of an existing Web filter profile. Source webfilter.profile.name.
                type: str
            webproxy_forward_server:
                description:
                    - Webproxy forward server name. Source web-proxy.forward-server.name web-proxy.forward-server-group.name.
                type: str
            webproxy_profile:
                description:
                    - Webproxy profile name. Source web-proxy.profile.name.
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
      firewall_consolidated_policy:
        action: "accept"
        application_list: "<your_own_value> (source application.list.name)"
        auto_asic_offload: "enable"
        av_profile: "<your_own_value> (source antivirus.profile.name)"
        captive_portal_exempt: "enable"
        cifs_profile: "<your_own_value> (source cifs.profile.name)"
        comments: "<your_own_value>"
        diffserv_forward: "enable"
        diffserv_reverse: "enable"
        diffservcode_forward: "<your_own_value>"
        diffservcode_rev: "<your_own_value>"
        dlp_sensor: "<your_own_value> (source dlp.sensor.name)"
        dnsfilter_profile: "<your_own_value> (source dnsfilter.profile.name)"
        dstaddr_negate: "enable"
        dstaddr4:
         -
            name: "default_name_18 (source firewall.address.name firewall.addrgrp.name firewall.vip.name firewall.vipgrp.name system.external-resource.name)"
        dstaddr6:
         -
            name: "default_name_20 (source firewall.address6.name firewall.addrgrp6.name firewall.vip6.name firewall.vipgrp6.name system.external-resource
              .name)"
        dstintf:
         -
            name: "default_name_22 (source system.interface.name system.zone.name)"
        emailfilter_profile: "<your_own_value> (source emailfilter.profile.name)"
        fixedport: "enable"
        fsso_groups:
         -
            name: "default_name_26 (source user.adgrp.name)"
        groups:
         -
            name: "default_name_28 (source user.group.name)"
        http_policy_redirect: "enable"
        icap_profile: "<your_own_value> (source icap.profile.name)"
        inbound: "enable"
        inspection_mode: "proxy"
        internet_service: "enable"
        internet_service_custom:
         -
            name: "default_name_35 (source firewall.internet-service-custom.name)"
        internet_service_custom_group:
         -
            name: "default_name_37 (source firewall.internet-service-custom-group.name)"
        internet_service_group:
         -
            name: "default_name_39 (source firewall.internet-service-group.name)"
        internet_service_name:
         -
            name: "default_name_41 (source firewall.internet-service-name.name)"
        internet_service_negate: "enable"
        internet_service_src: "enable"
        internet_service_src_custom:
         -
            name: "default_name_45 (source firewall.internet-service-custom.name)"
        internet_service_src_custom_group:
         -
            name: "default_name_47 (source firewall.internet-service-custom-group.name)"
        internet_service_src_group:
         -
            name: "default_name_49 (source firewall.internet-service-group.name)"
        internet_service_src_name:
         -
            name: "default_name_51 (source firewall.internet-service-name.name)"
        internet_service_src_negate: "enable"
        ippool: "enable"
        ips_sensor: "<your_own_value> (source ips.sensor.name)"
        logtraffic: "all"
        logtraffic_start: "enable"
        name: "default_name_57"
        nat: "enable"
        outbound: "enable"
        per_ip_shaper: "<your_own_value> (source firewall.shaper.per-ip-shaper.name)"
        policyid: "61"
        poolname4:
         -
            name: "default_name_63 (source firewall.ippool.name)"
        poolname6:
         -
            name: "default_name_65 (source firewall.ippool6.name)"
        profile_group: "<your_own_value> (source firewall.profile-group.name)"
        profile_protocol_options: "<your_own_value> (source firewall.profile-protocol-options.name)"
        profile_type: "single"
        schedule: "<your_own_value> (source firewall.schedule.onetime.name firewall.schedule.recurring.name firewall.schedule.group.name)"
        service:
         -
            name: "default_name_71 (source firewall.service.custom.name firewall.service.group.name)"
        service_negate: "enable"
        session_ttl: "73"
        srcaddr_negate: "enable"
        srcaddr4:
         -
            name: "default_name_76 (source firewall.address.name firewall.addrgrp.name system.external-resource.name)"
        srcaddr6:
         -
            name: "default_name_78 (source firewall.address6.name firewall.addrgrp6.name system.external-resource.name)"
        srcintf:
         -
            name: "default_name_80 (source system.interface.name system.zone.name)"
        ssh_filter_profile: "<your_own_value> (source ssh-filter.profile.name)"
        ssh_policy_redirect: "enable"
        ssl_ssh_profile: "<your_own_value> (source firewall.ssl-ssh-profile.name)"
        status: "enable"
        tcp_mss_receiver: "85"
        tcp_mss_sender: "86"
        traffic_shaper: "<your_own_value> (source firewall.shaper.traffic-shaper.name)"
        traffic_shaper_reverse: "<your_own_value> (source firewall.shaper.traffic-shaper.name)"
        users:
         -
            name: "default_name_90 (source user.local.name)"
        utm_status: "enable"
        uuid: "<your_own_value>"
        voip_profile: "<your_own_value> (source voip.profile.name)"
        vpntunnel: "<your_own_value> (source vpn.ipsec.phase1.name vpn.ipsec.manualkey.name)"
        waf_profile: "<your_own_value> (source waf.profile.name)"
        wanopt: "enable"
        wanopt_detection: "active"
        wanopt_passive_opt: "default"
        wanopt_peer: "<your_own_value> (source wanopt.peer.peer-host-id)"
        wanopt_profile: "<your_own_value> (source wanopt.profile.name)"
        webcache: "enable"
        webcache_https: "disable"
        webfilter_profile: "<your_own_value> (source webfilter.profile.name)"
        webproxy_forward_server: "<your_own_value> (source web-proxy.forward-server.name web-proxy.forward-server-group.name)"
        webproxy_profile: "<your_own_value> (source web-proxy.profile.name)"
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


def filter_firewall_consolidated_policy_data(json):
    option_list = ['action', 'application_list', 'auto_asic_offload',
                   'av_profile', 'captive_portal_exempt', 'cifs_profile',
                   'comments', 'diffserv_forward', 'diffserv_reverse',
                   'diffservcode_forward', 'diffservcode_rev', 'dlp_sensor',
                   'dnsfilter_profile', 'dstaddr_negate', 'dstaddr4',
                   'dstaddr6', 'dstintf', 'emailfilter_profile',
                   'fixedport', 'fsso_groups', 'groups',
                   'http_policy_redirect', 'icap_profile', 'inbound',
                   'inspection_mode', 'internet_service', 'internet_service_custom',
                   'internet_service_custom_group', 'internet_service_group', 'internet_service_name',
                   'internet_service_negate', 'internet_service_src', 'internet_service_src_custom',
                   'internet_service_src_custom_group', 'internet_service_src_group', 'internet_service_src_name',
                   'internet_service_src_negate', 'ippool', 'ips_sensor',
                   'logtraffic', 'logtraffic_start', 'name',
                   'nat', 'outbound', 'per_ip_shaper',
                   'policyid', 'poolname4', 'poolname6',
                   'profile_group', 'profile_protocol_options', 'profile_type',
                   'schedule', 'service', 'service_negate',
                   'session_ttl', 'srcaddr_negate', 'srcaddr4',
                   'srcaddr6', 'srcintf', 'ssh_filter_profile',
                   'ssh_policy_redirect', 'ssl_ssh_profile', 'status',
                   'tcp_mss_receiver', 'tcp_mss_sender', 'traffic_shaper',
                   'traffic_shaper_reverse', 'users', 'utm_status',
                   'uuid', 'voip_profile', 'vpntunnel',
                   'waf_profile', 'wanopt', 'wanopt_detection',
                   'wanopt_passive_opt', 'wanopt_peer', 'wanopt_profile',
                   'webcache', 'webcache_https', 'webfilter_profile',
                   'webproxy_forward_server', 'webproxy_profile']
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


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_firewall_consolidated(data, fos):

    if data['firewall_consolidated_policy']:
        resp = firewall_consolidated_policy(data, fos)

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
        "firewall_consolidated_policy": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "action": {"required": False, "type": "str",
                           "choices": ["accept",
                                       "deny",
                                       "ipsec"]},
                "application_list": {"required": False, "type": "str"},
                "auto_asic_offload": {"required": False, "type": "str",
                                      "choices": ["enable",
                                                  "disable"]},
                "av_profile": {"required": False, "type": "str"},
                "captive_portal_exempt": {"required": False, "type": "str",
                                          "choices": ["enable",
                                                      "disable"]},
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
                "dstaddr_negate": {"required": False, "type": "str",
                                   "choices": ["enable",
                                               "disable"]},
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
                "fsso_groups": {"required": False, "type": "list",
                                "options": {
                                    "name": {"required": True, "type": "str"}
                                }},
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
                "internet_service": {"required": False, "type": "str",
                                     "choices": ["enable",
                                                 "disable"]},
                "internet_service_custom": {"required": False, "type": "list",
                                            "options": {
                                                "name": {"required": True, "type": "str"}
                                            }},
                "internet_service_custom_group": {"required": False, "type": "list",
                                                  "options": {
                                                      "name": {"required": True, "type": "str"}
                                                  }},
                "internet_service_group": {"required": False, "type": "list",
                                           "options": {
                                               "name": {"required": True, "type": "str"}
                                           }},
                "internet_service_name": {"required": False, "type": "list",
                                          "options": {
                                              "name": {"required": True, "type": "str"}
                                          }},
                "internet_service_negate": {"required": False, "type": "str",
                                            "choices": ["enable",
                                                        "disable"]},
                "internet_service_src": {"required": False, "type": "str",
                                         "choices": ["enable",
                                                     "disable"]},
                "internet_service_src_custom": {"required": False, "type": "list",
                                                "options": {
                                                    "name": {"required": True, "type": "str"}
                                                }},
                "internet_service_src_custom_group": {"required": False, "type": "list",
                                                      "options": {
                                                          "name": {"required": True, "type": "str"}
                                                      }},
                "internet_service_src_group": {"required": False, "type": "list",
                                               "options": {
                                                   "name": {"required": True, "type": "str"}
                                               }},
                "internet_service_src_name": {"required": False, "type": "list",
                                              "options": {
                                                  "name": {"required": True, "type": "str"}
                                              }},
                "internet_service_src_negate": {"required": False, "type": "str",
                                                "choices": ["enable",
                                                            "disable"]},
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
                "service_negate": {"required": False, "type": "str",
                                   "choices": ["enable",
                                               "disable"]},
                "session_ttl": {"required": False, "type": "int"},
                "srcaddr_negate": {"required": False, "type": "str",
                                   "choices": ["enable",
                                               "disable"]},
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
                "wanopt": {"required": False, "type": "str",
                           "choices": ["enable",
                                       "disable"]},
                "wanopt_detection": {"required": False, "type": "str",
                                     "choices": ["active",
                                                 "passive",
                                                 "off"]},
                "wanopt_passive_opt": {"required": False, "type": "str",
                                       "choices": ["default",
                                                   "transparent",
                                                   "non-transparent"]},
                "wanopt_peer": {"required": False, "type": "str"},
                "wanopt_profile": {"required": False, "type": "str"},
                "webcache": {"required": False, "type": "str",
                             "choices": ["enable",
                                         "disable"]},
                "webcache_https": {"required": False, "type": "str",
                                   "choices": ["disable",
                                               "enable"]},
                "webfilter_profile": {"required": False, "type": "str"},
                "webproxy_forward_server": {"required": False, "type": "str"},
                "webproxy_profile": {"required": False, "type": "str"}

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

            is_error, has_changed, result = fortios_firewall_consolidated(module.params, fos)
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
        is_error, has_changed, result = fortios_firewall_consolidated(module.params, fos)
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
