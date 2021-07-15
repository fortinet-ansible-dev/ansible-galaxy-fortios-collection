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
module: fortios_firewall_access_proxy
short_description: Configure Access Proxy in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and access_proxy category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.0
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
    enable_log:
        description:
            - Enable/Disable logging for task.
        type: bool
        required: false
        default: false
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
    firewall_access_proxy:
        description:
            - Configure Access Proxy.
        default: null
        type: dict
        suboptions:
            api_gateway:
                description:
                    - Set API Gateway.
                type: list
                suboptions:
                    http_cookie_age:
                        description:
                            - Time in minutes that client web browsers should keep a cookie. Default is 60 minutes. 0 = no time limit.
                        type: int
                    http_cookie_domain:
                        description:
                            - Domain that HTTP cookie persistence should apply to.
                        type: str
                    http_cookie_domain_from_host:
                        description:
                            - Enable/disable use of HTTP cookie domain from host field in HTTP.
                        type: str
                        choices:
                            - disable
                            - enable
                    http_cookie_generation:
                        description:
                            - Generation of HTTP cookie to be accepted. Changing invalidates all existing cookies.
                        type: int
                    http_cookie_path:
                        description:
                            - Limit HTTP cookie persistence to the specified path.
                        type: str
                    http_cookie_share:
                        description:
                            - Control sharing of cookies across API Gateway. same-ip means a cookie from one virtual server can be used by another. Disable
                               stops cookie sharing.
                        type: str
                        choices:
                            - disable
                            - same-ip
                    https_cookie_secure:
                        description:
                            - Enable/disable verification that inserted HTTPS cookies are secure.
                        type: str
                        choices:
                            - disable
                            - enable
                    id:
                        description:
                            - API Gateway ID.
                        required: true
                        type: int
                    ldb_method:
                        description:
                            - Method used to distribute sessions to real servers.
                        type: str
                        choices:
                            - static
                            - round-robin
                            - weighted
                            - least-session
                            - least-rtt
                            - first-alive
                            - http-host
                    persistence:
                        description:
                            - Configure how to make sure that clients connect to the same server every time they make a request that is part of the same
                               session.
                        type: str
                        choices:
                            - none
                            - http-cookie
                    realservers:
                        description:
                            - Select the real servers that this Access Proxy will distribute traffic to.
                        type: list
                        suboptions:
                            address:
                                description:
                                    - Address or address group of the real server. Source firewall.address.name firewall.addrgrp.name.
                                type: str
                            health_check:
                                description:
                                    - Enable to check the responsiveness of the real server before forwarding traffic.
                                type: str
                                choices:
                                    - disable
                                    - enable
                            health_check_proto:
                                description:
                                    - Protocol of the health check monitor to use when polling to determine server"s connectivity status.
                                type: str
                                choices:
                                    - ping
                                    - http
                                    - tcp-connect
                            http_host:
                                description:
                                    - HTTP server domain name in HTTP header.
                                type: str
                            id:
                                description:
                                    - Real server ID.
                                required: true
                                type: int
                            ip:
                                description:
                                    - IP address of the real server.
                                type: str
                            mappedport:
                                description:
                                    - Port for communicating with the real server.
                                type: str
                            port:
                                description:
                                    - Port for communicating with the real server.
                                type: int
                            status:
                                description:
                                    - Set the status of the real server to active so that it can accept traffic, or on standby or disabled so no traffic is
                                       sent.
                                type: str
                                choices:
                                    - active
                                    - standby
                                    - disable
                            weight:
                                description:
                                    - Weight of the real server. If weighted load balancing is enabled, the server with the highest weight gets more
                                       connections.
                                type: int
                    saml_server:
                        description:
                            - SAML service provider configuration for VIP authentication. Source user.saml.name.
                        type: str
                    service:
                        description:
                            - Service.
                        type: str
                        choices:
                            - http
                            - https
                            - tcp-forwarding
                            - samlsp
                    ssl_algorithm:
                        description:
                            - Permitted encryption algorithms for the server side of SSL full mode sessions according to encryption strength.
                        type: str
                        choices:
                            - high
                            - medium
                            - low
                            - custom
                    ssl_cipher_suites:
                        description:
                            - SSL/TLS cipher suites to offer to a server, ordered by priority.
                        type: list
                        suboptions:
                            cipher:
                                description:
                                    - Cipher suite name.
                                type: str
                                choices:
                                    - TLS-AES-128-GCM-SHA256
                                    - TLS-AES-256-GCM-SHA384
                                    - TLS-CHACHA20-POLY1305-SHA256
                                    - TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256
                                    - TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256
                                    - TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256
                                    - TLS-DHE-RSA-WITH-AES-128-CBC-SHA
                                    - TLS-DHE-RSA-WITH-AES-256-CBC-SHA
                                    - TLS-DHE-RSA-WITH-AES-128-CBC-SHA256
                                    - TLS-DHE-RSA-WITH-AES-128-GCM-SHA256
                                    - TLS-DHE-RSA-WITH-AES-256-CBC-SHA256
                                    - TLS-DHE-RSA-WITH-AES-256-GCM-SHA384
                                    - TLS-DHE-DSS-WITH-AES-128-CBC-SHA
                                    - TLS-DHE-DSS-WITH-AES-256-CBC-SHA
                                    - TLS-DHE-DSS-WITH-AES-128-CBC-SHA256
                                    - TLS-DHE-DSS-WITH-AES-128-GCM-SHA256
                                    - TLS-DHE-DSS-WITH-AES-256-CBC-SHA256
                                    - TLS-DHE-DSS-WITH-AES-256-GCM-SHA384
                                    - TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA
                                    - TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256
                                    - TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256
                                    - TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA
                                    - TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384
                                    - TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384
                                    - TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA
                                    - TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256
                                    - TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
                                    - TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384
                                    - TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384
                                    - TLS-RSA-WITH-AES-128-CBC-SHA
                                    - TLS-RSA-WITH-AES-256-CBC-SHA
                                    - TLS-RSA-WITH-AES-128-CBC-SHA256
                                    - TLS-RSA-WITH-AES-128-GCM-SHA256
                                    - TLS-RSA-WITH-AES-256-CBC-SHA256
                                    - TLS-RSA-WITH-AES-256-GCM-SHA384
                                    - TLS-RSA-WITH-CAMELLIA-128-CBC-SHA
                                    - TLS-RSA-WITH-CAMELLIA-256-CBC-SHA
                                    - TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256
                                    - TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256
                                    - TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA
                                    - TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA
                                    - TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA
                                    - TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA
                                    - TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA
                                    - TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256
                                    - TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256
                                    - TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256
                                    - TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256
                                    - TLS-DHE-RSA-WITH-SEED-CBC-SHA
                                    - TLS-DHE-DSS-WITH-SEED-CBC-SHA
                                    - TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256
                                    - TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384
                                    - TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256
                                    - TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384
                                    - TLS-RSA-WITH-SEED-CBC-SHA
                                    - TLS-RSA-WITH-ARIA-128-CBC-SHA256
                                    - TLS-RSA-WITH-ARIA-256-CBC-SHA384
                                    - TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256
                                    - TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384
                                    - TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256
                                    - TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384
                                    - TLS-ECDHE-RSA-WITH-RC4-128-SHA
                                    - TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA
                                    - TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA
                                    - TLS-RSA-WITH-3DES-EDE-CBC-SHA
                                    - TLS-RSA-WITH-RC4-128-MD5
                                    - TLS-RSA-WITH-RC4-128-SHA
                                    - TLS-DHE-RSA-WITH-DES-CBC-SHA
                                    - TLS-DHE-DSS-WITH-DES-CBC-SHA
                                    - TLS-RSA-WITH-DES-CBC-SHA
                            priority:
                                description:
                                    - SSL/TLS cipher suites priority.
                                required: true
                                type: int
                            versions:
                                description:
                                    - SSL/TLS versions that the cipher suite can be used with.
                                type: str
                                choices:
                                    - tls-1.0
                                    - tls-1.1
                                    - tls-1.2
                                    - tls-1.3
                    ssl_dh_bits:
                        description:
                            - Number of bits to use in the Diffie-Hellman exchange for RSA encryption of SSL sessions.
                        type: str
                        choices:
                            - 768
                            - 1024
                            - 1536
                            - 2048
                            - 3072
                            - 4096
                    ssl_max_version:
                        description:
                            - Highest SSL/TLS version acceptable from a server.
                        type: str
                        choices:
                            - tls-1.0
                            - tls-1.1
                            - tls-1.2
                            - tls-1.3
                    ssl_min_version:
                        description:
                            - Lowest SSL/TLS version acceptable from a server.
                        type: str
                        choices:
                            - tls-1.0
                            - tls-1.1
                            - tls-1.2
                            - tls-1.3
                    url_map:
                        description:
                            - URL pattern to match.
                        type: str
                    url_map_type:
                        description:
                            - Type of url-map.
                        type: str
                        choices:
                            - sub-string
                            - wildcard
                            - regex
                    virtual_host:
                        description:
                            - Virtual host. Source firewall.access-proxy-virtual-host.name.
                        type: str
            client_cert:
                description:
                    - Enable/disable to request client certificate.
                type: str
                choices:
                    - disable
                    - enable
            empty_cert_action:
                description:
                    - Action of an empty client certificate.
                type: str
                choices:
                    - accept
                    - block
            ldb_method:
                description:
                    - Method used to distribute sessions to SSL real servers.
                type: str
                choices:
                    - static
                    - round-robin
                    - weighted
                    - least-session
                    - least-rtt
                    - first-alive
            name:
                description:
                    - Access Proxy name.
                required: true
                type: str
            realservers:
                description:
                    - Select the SSL real servers that this Access Proxy will distribute traffic to.
                type: list
                suboptions:
                    id:
                        description:
                            - Real server ID.
                        required: true
                        type: int
                    ip:
                        description:
                            - IP address of the real server.
                        type: str
                    port:
                        description:
                            - Port for communicating with the real server.
                        type: int
                    status:
                        description:
                            - Set the status of the real server to active so that it can accept traffic, or on standby or disabled so no traffic is sent.
                        type: str
                        choices:
                            - active
                            - standby
                            - disable
                    weight:
                        description:
                            - Weight of the real server. If weighted load balancing is enabled, the server with the highest weight gets more connections.
                        type: int
            server_pubkey_auth:
                description:
                    - Enable/disable SSH real server public key authentication.
                type: str
                choices:
                    - disable
                    - enable
            server_pubkey_auth_settings:
                description:
                    - Server SSH public key authentication settings.
                type: dict
                suboptions:
                    auth_ca:
                        description:
                            - Name of the SSH server public key authentication CA. Source firewall.ssh.local-ca.name.
                        type: str
                    cert_extension:
                        description:
                            - Configure certificate extension for user certificate.
                        type: list
                        suboptions:
                            critical:
                                description:
                                    - Critical option.
                                type: str
                                choices:
                                    - no
                                    - yes
                            data:
                                description:
                                    - Name of certificate extension.
                                type: str
                            name:
                                description:
                                    - Name of certificate extension.
                                required: true
                                type: str
                            type:
                                description:
                                    - Type of certificate extension.
                                type: str
                                choices:
                                    - fixed
                                    - user
                    permit_agent_forwarding:
                        description:
                            - Enable/disable appending permit-agent-forwarding certificate extension.
                        type: str
                        choices:
                            - enable
                            - disable
                    permit_port_forwarding:
                        description:
                            - Enable/disable appending permit-port-forwarding certificate extension.
                        type: str
                        choices:
                            - enable
                            - disable
                    permit_pty:
                        description:
                            - Enable/disable appending permit-pty certificate extension.
                        type: str
                        choices:
                            - enable
                            - disable
                    permit_user_rc:
                        description:
                            - Enable/disable appending permit-user-rc certificate extension.
                        type: str
                        choices:
                            - enable
                            - disable
                    permit_x11_forwarding:
                        description:
                            - Enable/disable appending permit-x11-forwarding certificate extension.
                        type: str
                        choices:
                            - enable
                            - disable
                    source_address:
                        description:
                            - Enable/disable appending source-address certificate critical option. This option ensure certificate only accepted from FortiGate
                               source address.
                        type: str
                        choices:
                            - enable
                            - disable
            vip:
                description:
                    - Virtual IP name. Source firewall.vip.name.
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
  - name: Configure Access Proxy.
    fortios_firewall_access_proxy:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_access_proxy:
        api_gateway:
         -
            http_cookie_age: "4"
            http_cookie_domain: "<your_own_value>"
            http_cookie_domain_from_host: "disable"
            http_cookie_generation: "7"
            http_cookie_path: "<your_own_value>"
            http_cookie_share: "disable"
            https_cookie_secure: "disable"
            id:  "11"
            ldb_method: "static"
            persistence: "none"
            realservers:
             -
                address: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
                health_check: "disable"
                health_check_proto: "ping"
                http_host: "myhostname"
                id:  "19"
                ip: "<your_own_value>"
                mappedport: "<your_own_value>"
                port: "22"
                status: "active"
                weight: "24"
            saml_server: "<your_own_value> (source user.saml.name)"
            service: "http"
            ssl_algorithm: "high"
            ssl_cipher_suites:
             -
                cipher: "TLS-AES-128-GCM-SHA256"
                priority: "30"
                versions: "tls-1.0"
            ssl_dh_bits: "768"
            ssl_max_version: "tls-1.0"
            ssl_min_version: "tls-1.0"
            url_map: "<your_own_value>"
            url_map_type: "sub-string"
            virtual_host: "myhostname (source firewall.access-proxy-virtual-host.name)"
        client_cert: "disable"
        empty_cert_action: "accept"
        ldb_method: "static"
        name: "default_name_41"
        realservers:
         -
            id:  "43"
            ip: "<your_own_value>"
            port: "45"
            status: "active"
            weight: "47"
        server_pubkey_auth: "disable"
        server_pubkey_auth_settings:
            auth_ca: "<your_own_value> (source firewall.ssh.local-ca.name)"
            cert_extension:
             -
                critical: "no"
                data: "<your_own_value>"
                name: "default_name_54"
                type: "fixed"
            permit_agent_forwarding: "enable"
            permit_port_forwarding: "enable"
            permit_pty: "enable"
            permit_user_rc: "enable"
            permit_x11_forwarding: "enable"
            source_address: "enable"
        vip: "<your_own_value> (source firewall.vip.name)"

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
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import schema_to_module_spec
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import check_schema_versioning
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import FAIL_SOCKET_MSG
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import is_same_comparison
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import serialize


def filter_firewall_access_proxy_data(json):
    option_list = ['api_gateway', 'client_cert', 'empty_cert_action',
                   'ldb_method', 'name', 'realservers',
                   'server_pubkey_auth', 'server_pubkey_auth_settings', 'vip']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def flatten_single_path(data, path, index):
    if not data or index == len(path) or path[index] not in data or not data[path[index]]:
        return

    if index == len(path) - 1:
        data[path[index]] = ' '.join(str(elem) for elem in data[path[index]])
    elif isinstance(data[path[index]], list):
        for value in data[path[index]]:
            flatten_single_path(value, path, index + 1)
    else:
        flatten_single_path(data[path[index]], path, index + 1)


def flatten_multilists_attributes(data):
    multilist_attrs = [[u'api_gateway', u'ssl_cipher_suites', u'versions']]

    for attr in multilist_attrs:
        flatten_single_path(data, attr, 0)

    return data


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


def firewall_access_proxy(data, fos):
    vdom = data['vdom']

    state = data['state']

    firewall_access_proxy_data = data['firewall_access_proxy']
    firewall_access_proxy_data = flatten_multilists_attributes(firewall_access_proxy_data)
    filtered_data = underscore_to_hyphen(filter_firewall_access_proxy_data(firewall_access_proxy_data))

    if state == "present" or state is True:
        return fos.set('firewall',
                       'access-proxy',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('firewall',
                          'access-proxy',
                          mkey=filtered_data['name'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_firewall(data, fos):

    if data['firewall_access_proxy']:
        resp = firewall_access_proxy(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('firewall_access_proxy'))

    return not is_successful_status(resp), \
        resp['status'] == "success" and \
        (resp['revision_changed'] if 'revision_changed' in resp else True), \
        resp


versioned_schema = {
    "type": "list",
    "children": {
        "api_gateway": {
            "type": "list",
            "children": {
                "ssl_algorithm": {
                    "type": "string",
                    "options": [
                        {
                            "value": "high",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "medium",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "low",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "custom",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ssl_min_version": {
                    "type": "string",
                    "options": [
                        {
                            "value": "tls-1.0",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "tls-1.1",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "tls-1.2",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "tls-1.3",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ssl_cipher_suites": {
                    "type": "list",
                    "children": {
                        "priority": {
                            "type": "integer",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "cipher": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "TLS-AES-128-GCM-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-AES-256-GCM-SHA384",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-CHACHA20-POLY1305-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-RSA-WITH-AES-128-CBC-SHA",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-RSA-WITH-AES-256-CBC-SHA",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-RSA-WITH-AES-128-CBC-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-RSA-WITH-AES-128-GCM-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-RSA-WITH-AES-256-CBC-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-RSA-WITH-AES-256-GCM-SHA384",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-DSS-WITH-AES-128-CBC-SHA",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-DSS-WITH-AES-256-CBC-SHA",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-DSS-WITH-AES-128-CBC-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-DSS-WITH-AES-128-GCM-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-DSS-WITH-AES-256-CBC-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-DSS-WITH-AES-256-GCM-SHA384",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-RSA-WITH-AES-128-CBC-SHA",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-RSA-WITH-AES-256-CBC-SHA",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-RSA-WITH-AES-128-CBC-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-RSA-WITH-AES-128-GCM-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-RSA-WITH-AES-256-CBC-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-RSA-WITH-AES-256-GCM-SHA384",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-RSA-WITH-CAMELLIA-128-CBC-SHA",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-RSA-WITH-CAMELLIA-256-CBC-SHA",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-RSA-WITH-SEED-CBC-SHA",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-DSS-WITH-SEED-CBC-SHA",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-RSA-WITH-SEED-CBC-SHA",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-RSA-WITH-ARIA-128-CBC-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-RSA-WITH-ARIA-256-CBC-SHA384",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-ECDHE-RSA-WITH-RC4-128-SHA",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-RSA-WITH-3DES-EDE-CBC-SHA",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-RSA-WITH-RC4-128-MD5",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-RSA-WITH-RC4-128-SHA",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-RSA-WITH-DES-CBC-SHA",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-DHE-DSS-WITH-DES-CBC-SHA",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "TLS-RSA-WITH-DES-CBC-SHA",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                }
                            ],
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "versions": {
                            "multiple_values": True,
                            "type": "list",
                            "options": [
                                {
                                    "value": "tls-1.0",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "tls-1.1",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "tls-1.2",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "tls-1.3",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                }
                            ],
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    },
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "service": {
                    "type": "string",
                    "options": [
                        {
                            "value": "http",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "https",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "tcp-forwarding",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "samlsp",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "realservers": {
                    "type": "list",
                    "children": {
                        "status": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "active",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "standby",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                }
                            ],
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "health_check": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                }
                            ],
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "weight": {
                            "type": "integer",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "ip": {
                            "type": "string",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "id": {
                            "type": "integer",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "http_host": {
                            "type": "string",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "health_check_proto": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "ping",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "http",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "tcp-connect",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                }
                            ],
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "address": {
                            "type": "string",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "port": {
                            "type": "integer",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "mappedport": {
                            "type": "string",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    },
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "http_cookie_domain_from_host": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "https_cookie_secure": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "http_cookie_generation": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "http_cookie_domain": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "url_map_type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "sub-string",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "wildcard",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "regex",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "http_cookie_share": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "same-ip",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ssl_dh_bits": {
                    "type": "string",
                    "options": [
                        {
                            "value": "768",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "1024",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "1536",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "2048",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "3072",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "4096",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ldb_method": {
                    "type": "string",
                    "options": [
                        {
                            "value": "static",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "round-robin",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "weighted",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "least-session",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "least-rtt",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "first-alive",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "http-host",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "persistence": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "http-cookie",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "virtual_host": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ssl_max_version": {
                    "type": "string",
                    "options": [
                        {
                            "value": "tls-1.0",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "tls-1.1",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "tls-1.2",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "tls-1.3",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "url_map": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "saml_server": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "id": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "http_cookie_age": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "http_cookie_path": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            },
            "revisions": {
                "v7.0.0": True
            }
        },
        "name": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "realservers": {
            "type": "list",
            "children": {
                "status": {
                    "type": "string",
                    "options": [
                        {
                            "value": "active",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "standby",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "ip": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "id": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "weight": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "port": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            },
            "revisions": {
                "v7.0.0": True
            }
        },
        "empty_cert_action": {
            "type": "string",
            "options": [
                {
                    "value": "accept",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "block",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "server_pubkey_auth": {
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "vip": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "ldb_method": {
            "type": "string",
            "options": [
                {
                    "value": "static",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "round-robin",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "weighted",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "least-session",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "least-rtt",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "first-alive",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "server_pubkey_auth_settings": {
            "type": "dict",
            "children": {
                "permit_x11_forwarding": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "auth_ca": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "permit_port_forwarding": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "permit_pty": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "permit_user_rc": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "permit_agent_forwarding": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "source_address": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "cert_extension": {
                    "type": "list",
                    "children": {
                        "data": {
                            "type": "string",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "critical": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "no",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "yes",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                }
                            ],
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "type": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "fixed",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                },
                                {
                                    "value": "user",
                                    "revisions": {
                                        "v7.0.0": True
                                    }
                                }
                            ],
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        "name": {
                            "type": "string",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    },
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            },
            "revisions": {
                "v7.0.0": True
            }
        },
        "client_cert": {
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        }
    },
    "revisions": {
        "v7.0.0": True
    }
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = 'name'
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "enable_log": {"required": False, "type": bool},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "state": {"required": True, "type": "str",
                  "choices": ["present", "absent"]},
        "firewall_access_proxy": {
            "required": False, "type": "dict", "default": None,
            "options": {
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["firewall_access_proxy"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_access_proxy"]['options'][attribute_name]['required'] = True

    check_legacy_fortiosapi()
    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if 'access_token' in module.params:
            connection.set_option('access_token', module.params['access_token'])

        if 'enable_log' in module.params:
            connection.set_option('enable_log', module.params['enable_log'])
        else:
            connection.set_option('enable_log', False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(fos, versioned_schema, "firewall_access_proxy")

        is_error, has_changed, result = fortios_firewall(module.params, fos)

    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result['matched'] is False:
        module.warn("Ansible has detected version mismatch between FortOS system and your playbook, see more details by specifying option -vvv")

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
