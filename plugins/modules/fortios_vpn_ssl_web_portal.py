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
module: fortios_vpn_ssl_web_portal
short_description: Portal in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify vpn_ssl_web feature and portal category.
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
    vpn_ssl_web_portal:
        description:
            - Portal.
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
            allow_user_access:
                description:
                    - Allow user access to SSL-VPN applications.
                type: str
                choices:
                    - web
                    - ftp
                    - smb
                    - telnet
                    - ssh
                    - vnc
                    - rdp
                    - ping
                    - citrix
                    - portforward
            auto_connect:
                description:
                    - Enable/disable automatic connect by client when system is up.
                type: str
                choices:
                    - enable
                    - disable
            bookmark_group:
                description:
                    - Portal bookmark group.
                type: list
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
                            - Bookmark group name.
                        required: true
                        type: str
            custom_lang:
                description:
                    - Change the web portal display language. Overrides config system global set language. You can use config system custom-language and
                       execute system custom-language to add custom language files. Source system.custom-language.name.
                type: str
            customize_forticlient_download_url:
                description:
                    - Enable support of customized download URL for FortiClient.
                type: str
                choices:
                    - enable
                    - disable
            display_bookmark:
                description:
                    - Enable to display the web portal bookmark widget.
                type: str
                choices:
                    - enable
                    - disable
            display_connection_tools:
                description:
                    - Enable to display the web portal connection tools widget.
                type: str
                choices:
                    - enable
                    - disable
            display_history:
                description:
                    - Enable to display the web portal user login history widget.
                type: str
                choices:
                    - enable
                    - disable
            display_status:
                description:
                    - Enable to display the web portal status widget.
                type: str
                choices:
                    - enable
                    - disable
            dns_server1:
                description:
                    - IPv4 DNS server 1.
                type: str
            dns_server2:
                description:
                    - IPv4 DNS server 2.
                type: str
            dns_suffix:
                description:
                    - DNS suffix.
                type: str
            exclusive_routing:
                description:
                    - Enable/disable all traffic go through tunnel only.
                type: str
                choices:
                    - enable
                    - disable
            forticlient_download:
                description:
                    - Enable/disable download option for FortiClient.
                type: str
                choices:
                    - enable
                    - disable
            forticlient_download_method:
                description:
                    - FortiClient download method.
                type: str
                choices:
                    - direct
                    - ssl-vpn
            heading:
                description:
                    - Web portal heading message.
                type: str
            host_check:
                description:
                    - Type of host checking performed on endpoints.
                type: str
                choices:
                    - none
                    - av
                    - fw
                    - av-fw
                    - custom
            host_check_interval:
                description:
                    - Periodic host check interval. Value of 0 means disabled and host checking only happens when the endpoint connects.
                type: int
            host_check_policy:
                description:
                    - One or more policies to require the endpoint to have specific security software.
                type: list
                suboptions:
                    name:
                        description:
                            - Host check software list name. Source vpn.ssl.web.host-check-software.name.
                        required: true
                        type: str
            ip_mode:
                description:
                    - Method by which users of this SSL-VPN tunnel obtain IP addresses.
                type: str
                choices:
                    - range
                    - user-group
            ip_pools:
                description:
                    - IPv4 firewall source address objects reserved for SSL-VPN tunnel mode clients.
                type: list
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name.
                        required: true
                        type: str
            ipv6_dns_server1:
                description:
                    - IPv6 DNS server 1.
                type: str
            ipv6_dns_server2:
                description:
                    - IPv6 DNS server 2.
                type: str
            ipv6_exclusive_routing:
                description:
                    - Enable/disable all IPv6 traffic go through tunnel only.
                type: str
                choices:
                    - enable
                    - disable
            ipv6_pools:
                description:
                    - IPv4 firewall source address objects reserved for SSL-VPN tunnel mode clients.
                type: list
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name firewall.addrgrp6.name.
                        required: true
                        type: str
            ipv6_service_restriction:
                description:
                    - Enable/disable IPv6 tunnel service restriction.
                type: str
                choices:
                    - enable
                    - disable
            ipv6_split_tunneling:
                description:
                    - Enable/disable IPv6 split tunneling.
                type: str
                choices:
                    - enable
                    - disable
            ipv6_split_tunneling_routing_address:
                description:
                    - IPv6 SSL-VPN tunnel mode firewall address objects that override firewall policy destination addresses to control split-tunneling access.
                type: list
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name firewall.addrgrp6.name.
                        required: true
                        type: str
            ipv6_tunnel_mode:
                description:
                    - Enable/disable IPv6 SSL-VPN tunnel mode.
                type: str
                choices:
                    - enable
                    - disable
            ipv6_wins_server1:
                description:
                    - IPv6 WINS server 1.
                type: str
            ipv6_wins_server2:
                description:
                    - IPv6 WINS server 2.
                type: str
            keep_alive:
                description:
                    - Enable/disable automatic reconnect for FortiClient connections.
                type: str
                choices:
                    - enable
                    - disable
            limit_user_logins:
                description:
                    - Enable to limit each user to one SSL-VPN session at a time.
                type: str
                choices:
                    - enable
                    - disable
            mac_addr_action:
                description:
                    - Client MAC address action.
                type: str
                choices:
                    - allow
                    - deny
            mac_addr_check:
                description:
                    - Enable/disable MAC address host checking.
                type: str
                choices:
                    - enable
                    - disable
            mac_addr_check_rule:
                description:
                    - Client MAC address check rule.
                type: list
                suboptions:
                    mac_addr_list:
                        description:
                            - Client MAC address list.
                        type: list
                        suboptions:
                            addr:
                                description:
                                    - Client MAC address.
                                required: true
                                type: str
                    mac_addr_mask:
                        description:
                            - Client MAC address mask.
                        type: int
                    name:
                        description:
                            - Client MAC address check rule name.
                        required: true
                        type: str
            macos_forticlient_download_url:
                description:
                    - Download URL for Mac FortiClient.
                type: str
            name:
                description:
                    - Portal name.
                required: true
                type: str
            os_check:
                description:
                    - Enable to let the FortiGate decide action based on client OS.
                type: str
                choices:
                    - enable
                    - disable
            os_check_list:
                description:
                    - SSL VPN OS checks.
                type: list
                suboptions:
                    action:
                        description:
                            - OS check options.
                        type: str
                        choices:
                            - deny
                            - allow
                            - check-up-to-date
                    latest_patch_level:
                        description:
                            - Latest OS patch level.
                        type: str
                    name:
                        description:
                            - Name.
                        required: true
                        type: str
                    tolerance:
                        description:
                            - OS patch level tolerance.
                        type: int
            redir_url:
                description:
                    - Client login redirect URL.
                type: str
            save_password:
                description:
                    - Enable/disable FortiClient saving the user"s password.
                type: str
                choices:
                    - enable
                    - disable
            service_restriction:
                description:
                    - Enable/disable tunnel service restriction.
                type: str
                choices:
                    - enable
                    - disable
            skip_check_for_unsupported_browser:
                description:
                    - Enable to skip host check if browser does not support it.
                type: str
                choices:
                    - enable
                    - disable
            skip_check_for_unsupported_os:
                description:
                    - Enable to skip host check if client OS does not support it.
                type: str
                choices:
                    - enable
                    - disable
            smb_ntlmv1_auth:
                description:
                    - Enable support of NTLMv1 for Samba authentication.
                type: str
                choices:
                    - enable
                    - disable
            split_dns:
                description:
                    - Split DNS for SSL VPN.
                type: list
                suboptions:
                    dns_server1:
                        description:
                            - DNS server 1.
                        type: str
                    dns_server2:
                        description:
                            - DNS server 2.
                        type: str
                    domains:
                        description:
                            - Split DNS domains used for SSL-VPN clients separated by comma(,).
                        type: str
                    id:
                        description:
                            - ID.
                        required: true
                        type: int
                    ipv6_dns_server1:
                        description:
                            - IPv6 DNS server 1.
                        type: str
                    ipv6_dns_server2:
                        description:
                            - IPv6 DNS server 2.
                        type: str
            split_tunneling:
                description:
                    - Enable/disable IPv4 split tunneling.
                type: str
                choices:
                    - enable
                    - disable
            split_tunneling_routing_address:
                description:
                    - IPv4 SSL-VPN tunnel mode firewall address objects that override firewall policy destination addresses to control split-tunneling access.
                type: list
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name.
                        required: true
                        type: str
            theme:
                description:
                    - Web portal color scheme.
                type: str
                choices:
                    - blue
                    - green
                    - red
                    - melongene
                    - mariner
            tunnel_mode:
                description:
                    - Enable/disable IPv4 SSL-VPN tunnel mode.
                type: str
                choices:
                    - enable
                    - disable
            user_bookmark:
                description:
                    - Enable to allow web portal users to create their own bookmarks.
                type: str
                choices:
                    - enable
                    - disable
            user_group_bookmark:
                description:
                    - Enable to allow web portal users to create bookmarks for all users in the same user group.
                type: str
                choices:
                    - enable
                    - disable
            web_mode:
                description:
                    - Enable/disable SSL VPN web mode.
                type: str
                choices:
                    - enable
                    - disable
            windows_forticlient_download_url:
                description:
                    - Download URL for Windows FortiClient.
                type: str
            wins_server1:
                description:
                    - IPv4 WINS server 1.
                type: str
            wins_server2:
                description:
                    - IPv4 WINS server 1.
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
  - name: Portal.
    fortios_vpn_ssl_web_portal:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      vpn_ssl_web_portal:
        allow_user_access: "web"
        auto_connect: "enable"
        bookmark_group:
         -
            bookmarks:
             -
                additional_params: "<your_own_value>"
                apptype: "citrix"
                description: "<your_own_value>"
                folder: "<your_own_value>"
                form_data:
                 -
                    name: "default_name_12"
                    value: "<your_own_value>"
                host: "<your_own_value>"
                listening_port: "15"
                logon_password: "<your_own_value>"
                logon_user: "<your_own_value>"
                name: "default_name_18"
                port: "19"
                remote_port: "20"
                security: "rdp"
                server_layout: "en-us-qwerty"
                show_status_window: "enable"
                sso: "disable"
                sso_credential: "sslvpn-login"
                sso_credential_sent_once: "enable"
                sso_password: "<your_own_value>"
                sso_username: "<your_own_value>"
                url: "myurl.com"
            name: "default_name_30"
        custom_lang: "<your_own_value> (source system.custom-language.name)"
        customize_forticlient_download_url: "enable"
        display_bookmark: "enable"
        display_connection_tools: "enable"
        display_history: "enable"
        display_status: "enable"
        dns_server1: "<your_own_value>"
        dns_server2: "<your_own_value>"
        dns_suffix: "<your_own_value>"
        exclusive_routing: "enable"
        forticlient_download: "enable"
        forticlient_download_method: "direct"
        heading: "<your_own_value>"
        host_check: "none"
        host_check_interval: "45"
        host_check_policy:
         -
            name: "default_name_47 (source vpn.ssl.web.host-check-software.name)"
        ip_mode: "range"
        ip_pools:
         -
            name: "default_name_50 (source firewall.address.name firewall.addrgrp.name)"
        ipv6_dns_server1: "<your_own_value>"
        ipv6_dns_server2: "<your_own_value>"
        ipv6_exclusive_routing: "enable"
        ipv6_pools:
         -
            name: "default_name_55 (source firewall.address6.name firewall.addrgrp6.name)"
        ipv6_service_restriction: "enable"
        ipv6_split_tunneling: "enable"
        ipv6_split_tunneling_routing_address:
         -
            name: "default_name_59 (source firewall.address6.name firewall.addrgrp6.name)"
        ipv6_tunnel_mode: "enable"
        ipv6_wins_server1: "<your_own_value>"
        ipv6_wins_server2: "<your_own_value>"
        keep_alive: "enable"
        limit_user_logins: "enable"
        mac_addr_action: "allow"
        mac_addr_check: "enable"
        mac_addr_check_rule:
         -
            mac_addr_list:
             -
                addr: "<your_own_value>"
            mac_addr_mask: "70"
            name: "default_name_71"
        macos_forticlient_download_url: "<your_own_value>"
        name: "default_name_73"
        os_check: "enable"
        os_check_list:
         -
            action: "deny"
            latest_patch_level: "<your_own_value>"
            name: "default_name_78"
            tolerance: "79"
        redir_url: "<your_own_value>"
        save_password: "enable"
        service_restriction: "enable"
        skip_check_for_unsupported_browser: "enable"
        skip_check_for_unsupported_os: "enable"
        smb_ntlmv1_auth: "enable"
        split_dns:
         -
            dns_server1: "<your_own_value>"
            dns_server2: "<your_own_value>"
            domains: "<your_own_value>"
            id:  "90"
            ipv6_dns_server1: "<your_own_value>"
            ipv6_dns_server2: "<your_own_value>"
        split_tunneling: "enable"
        split_tunneling_routing_address:
         -
            name: "default_name_95 (source firewall.address.name firewall.addrgrp.name)"
        theme: "blue"
        tunnel_mode: "enable"
        user_bookmark: "enable"
        user_group_bookmark: "enable"
        web_mode: "enable"
        windows_forticlient_download_url: "<your_own_value>"
        wins_server1: "<your_own_value>"
        wins_server2: "<your_own_value>"

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


def filter_vpn_ssl_web_portal_data(json):
    option_list = ['allow_user_access', 'auto_connect', 'bookmark_group',
                   'custom_lang', 'customize_forticlient_download_url', 'display_bookmark',
                   'display_connection_tools', 'display_history', 'display_status',
                   'dns_server1', 'dns_server2', 'dns_suffix',
                   'exclusive_routing', 'forticlient_download', 'forticlient_download_method',
                   'heading', 'host_check', 'host_check_interval',
                   'host_check_policy', 'ip_mode', 'ip_pools',
                   'ipv6_dns_server1', 'ipv6_dns_server2', 'ipv6_exclusive_routing',
                   'ipv6_pools', 'ipv6_service_restriction', 'ipv6_split_tunneling',
                   'ipv6_split_tunneling_routing_address', 'ipv6_tunnel_mode', 'ipv6_wins_server1',
                   'ipv6_wins_server2', 'keep_alive', 'limit_user_logins',
                   'mac_addr_action', 'mac_addr_check', 'mac_addr_check_rule',
                   'macos_forticlient_download_url', 'name', 'os_check',
                   'os_check_list', 'redir_url', 'save_password',
                   'service_restriction', 'skip_check_for_unsupported_browser', 'skip_check_for_unsupported_os',
                   'smb_ntlmv1_auth', 'split_dns', 'split_tunneling',
                   'split_tunneling_routing_address', 'theme', 'tunnel_mode',
                   'user_bookmark', 'user_group_bookmark', 'web_mode',
                   'windows_forticlient_download_url', 'wins_server1', 'wins_server2']
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


def vpn_ssl_web_portal(data, fos):
    vdom = data['vdom']
    if 'state' in data and data['state']:
        state = data['state']
    elif 'state' in data['vpn_ssl_web_portal'] and data['vpn_ssl_web_portal']['state']:
        state = data['vpn_ssl_web_portal']['state']
    else:
        state = True
    vpn_ssl_web_portal_data = data['vpn_ssl_web_portal']
    filtered_data = underscore_to_hyphen(filter_vpn_ssl_web_portal_data(vpn_ssl_web_portal_data))

    if state == "present":
        return fos.set('vpn.ssl.web',
                       'portal',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('vpn.ssl.web',
                          'portal',
                          mkey=filtered_data['name'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_vpn_ssl_web(data, fos):

    if data['vpn_ssl_web_portal']:
        resp = vpn_ssl_web_portal(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('vpn_ssl_web_portal'))

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
        "vpn_ssl_web_portal": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "state": {"required": False, "type": "str",
                          "choices": ["present", "absent"]},
                "allow_user_access": {"required": False, "type": "str",
                                      "choices": ["web",
                                                  "ftp",
                                                  "smb",
                                                  "telnet",
                                                  "ssh",
                                                  "vnc",
                                                  "rdp",
                                                  "ping",
                                                  "citrix",
                                                  "portforward"]},
                "auto_connect": {"required": False, "type": "str",
                                 "choices": ["enable",
                                             "disable"]},
                "bookmark_group": {"required": False, "type": "list",
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
                                   }},
                "custom_lang": {"required": False, "type": "str"},
                "customize_forticlient_download_url": {"required": False, "type": "str",
                                                       "choices": ["enable",
                                                                   "disable"]},
                "display_bookmark": {"required": False, "type": "str",
                                     "choices": ["enable",
                                                 "disable"]},
                "display_connection_tools": {"required": False, "type": "str",
                                             "choices": ["enable",
                                                         "disable"]},
                "display_history": {"required": False, "type": "str",
                                    "choices": ["enable",
                                                "disable"]},
                "display_status": {"required": False, "type": "str",
                                   "choices": ["enable",
                                               "disable"]},
                "dns_server1": {"required": False, "type": "str"},
                "dns_server2": {"required": False, "type": "str"},
                "dns_suffix": {"required": False, "type": "str"},
                "exclusive_routing": {"required": False, "type": "str",
                                      "choices": ["enable",
                                                  "disable"]},
                "forticlient_download": {"required": False, "type": "str",
                                         "choices": ["enable",
                                                     "disable"]},
                "forticlient_download_method": {"required": False, "type": "str",
                                                "choices": ["direct",
                                                            "ssl-vpn"]},
                "heading": {"required": False, "type": "str"},
                "host_check": {"required": False, "type": "str",
                               "choices": ["none",
                                           "av",
                                           "fw",
                                           "av-fw",
                                           "custom"]},
                "host_check_interval": {"required": False, "type": "int"},
                "host_check_policy": {"required": False, "type": "list",
                                      "options": {
                                          "name": {"required": True, "type": "str"}
                                      }},
                "ip_mode": {"required": False, "type": "str",
                            "choices": ["range",
                                        "user-group"]},
                "ip_pools": {"required": False, "type": "list",
                             "options": {
                                 "name": {"required": True, "type": "str"}
                             }},
                "ipv6_dns_server1": {"required": False, "type": "str"},
                "ipv6_dns_server2": {"required": False, "type": "str"},
                "ipv6_exclusive_routing": {"required": False, "type": "str",
                                           "choices": ["enable",
                                                       "disable"]},
                "ipv6_pools": {"required": False, "type": "list",
                               "options": {
                                   "name": {"required": True, "type": "str"}
                               }},
                "ipv6_service_restriction": {"required": False, "type": "str",
                                             "choices": ["enable",
                                                         "disable"]},
                "ipv6_split_tunneling": {"required": False, "type": "str",
                                         "choices": ["enable",
                                                     "disable"]},
                "ipv6_split_tunneling_routing_address": {"required": False, "type": "list",
                                                         "options": {
                                                             "name": {"required": True, "type": "str"}
                                                         }},
                "ipv6_tunnel_mode": {"required": False, "type": "str",
                                     "choices": ["enable",
                                                 "disable"]},
                "ipv6_wins_server1": {"required": False, "type": "str"},
                "ipv6_wins_server2": {"required": False, "type": "str"},
                "keep_alive": {"required": False, "type": "str",
                               "choices": ["enable",
                                           "disable"]},
                "limit_user_logins": {"required": False, "type": "str",
                                      "choices": ["enable",
                                                  "disable"]},
                "mac_addr_action": {"required": False, "type": "str",
                                    "choices": ["allow",
                                                "deny"]},
                "mac_addr_check": {"required": False, "type": "str",
                                   "choices": ["enable",
                                               "disable"]},
                "mac_addr_check_rule": {"required": False, "type": "list",
                                        "options": {
                                            "mac_addr_list": {"required": False, "type": "list",
                                                              "options": {
                                                                  "addr": {"required": True, "type": "str"}
                                                              }},
                                            "mac_addr_mask": {"required": False, "type": "int"},
                                            "name": {"required": True, "type": "str"}
                                        }},
                "macos_forticlient_download_url": {"required": False, "type": "str"},
                "name": {"required": True, "type": "str"},
                "os_check": {"required": False, "type": "str",
                             "choices": ["enable",
                                         "disable"]},
                "os_check_list": {"required": False, "type": "list",
                                  "options": {
                                      "action": {"required": False, "type": "str",
                                                 "choices": ["deny",
                                                             "allow",
                                                             "check-up-to-date"]},
                                      "latest_patch_level": {"required": False, "type": "str"},
                                      "name": {"required": True, "type": "str"},
                                      "tolerance": {"required": False, "type": "int"}
                                  }},
                "redir_url": {"required": False, "type": "str"},
                "save_password": {"required": False, "type": "str",
                                  "choices": ["enable",
                                              "disable"]},
                "service_restriction": {"required": False, "type": "str",
                                        "choices": ["enable",
                                                    "disable"]},
                "skip_check_for_unsupported_browser": {"required": False, "type": "str",
                                                       "choices": ["enable",
                                                                   "disable"]},
                "skip_check_for_unsupported_os": {"required": False, "type": "str",
                                                  "choices": ["enable",
                                                              "disable"]},
                "smb_ntlmv1_auth": {"required": False, "type": "str",
                                    "choices": ["enable",
                                                "disable"]},
                "split_dns": {"required": False, "type": "list",
                              "options": {
                                  "dns_server1": {"required": False, "type": "str"},
                                  "dns_server2": {"required": False, "type": "str"},
                                  "domains": {"required": False, "type": "str"},
                                  "id": {"required": True, "type": "int"},
                                  "ipv6_dns_server1": {"required": False, "type": "str"},
                                  "ipv6_dns_server2": {"required": False, "type": "str"}
                              }},
                "split_tunneling": {"required": False, "type": "str",
                                    "choices": ["enable",
                                                "disable"]},
                "split_tunneling_routing_address": {"required": False, "type": "list",
                                                    "options": {
                                                        "name": {"required": True, "type": "str"}
                                                    }},
                "theme": {"required": False, "type": "str",
                          "choices": ["blue",
                                      "green",
                                      "red",
                                      "melongene",
                                      "mariner"]},
                "tunnel_mode": {"required": False, "type": "str",
                                "choices": ["enable",
                                            "disable"]},
                "user_bookmark": {"required": False, "type": "str",
                                  "choices": ["enable",
                                              "disable"]},
                "user_group_bookmark": {"required": False, "type": "str",
                                        "choices": ["enable",
                                                    "disable"]},
                "web_mode": {"required": False, "type": "str",
                             "choices": ["enable",
                                         "disable"]},
                "windows_forticlient_download_url": {"required": False, "type": "str"},
                "wins_server1": {"required": False, "type": "str"},
                "wins_server2": {"required": False, "type": "str"}

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
