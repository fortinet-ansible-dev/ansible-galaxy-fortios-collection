#!/usr/bin/python
from __future__ import absolute_import, division, print_function

# Copyright: (c) 2022 Fortinet
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

__metaclass__ = type

ANSIBLE_METADATA = {
    "status": ["preview"],
    "supported_by": "community",
    "metadata_version": "1.1",
}

DOCUMENTATION = """
---
module: fortios_system_dns
short_description: Configure DNS in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and dns category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.0
version_added: "2.0.0"
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
    - ansible>=2.9
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
    member_path:
        type: str
        description:
            - Member attribute path to operate on.
            - Delimited by a slash character if there are more than one attribute.
            - Parameter marked with member_path is legitimate for doing member operation.
    member_state:
        type: str
        description:
            - Add or delete a member under specified attribute path.
            - When member_state is specified, the state option is ignored.
        choices:
            - present
            - absent

    system_dns:
        description:
            - Configure DNS.
        default: null
        type: dict
        suboptions:
            alt_primary:
                description:
                    - Alternate primary DNS server. This is not used as a failover DNS server.
                type: str
            alt_secondary:
                description:
                    - Alternate secondary DNS server. This is not used as a failover DNS server.
                type: str
            cache_notfound_responses:
                description:
                    - Enable/disable response from the DNS server when a record is not in cache.
                type: str
                choices:
                    - disable
                    - enable
            dns_cache_limit:
                description:
                    - Maximum number of records in the DNS cache.
                type: int
            dns_cache_ttl:
                description:
                    - Duration in seconds that the DNS cache retains information.
                type: int
            dns_over_tls:
                description:
                    - Enable/disable/enforce DNS over TLS.
                type: str
                choices:
                    - disable
                    - enable
                    - enforce
            domain:
                description:
                    - Search suffix list for hostname lookup.
                type: list
                elements: dict
                suboptions:
                    domain:
                        description:
                            - DNS search domain list separated by space (maximum 8 domains).
                        type: str
            interface:
                description:
                    - Specify outgoing interface to reach server. Source system.interface.name.
                type: str
            interface_select_method:
                description:
                    - Specify how to select outgoing interface to reach server.
                type: str
                choices:
                    - auto
                    - sdwan
                    - specify
            ip6_primary:
                description:
                    - Primary DNS server IPv6 address.
                type: str
            ip6_secondary:
                description:
                    - Secondary DNS server IPv6 address.
                type: str
            log:
                description:
                    - Local DNS log setting.
                type: str
                choices:
                    - disable
                    - error
                    - all
            primary:
                description:
                    - Primary DNS server IP address.
                type: str
            protocol:
                description:
                    - DNS transport protocols.
                type: list
                elements: str
                choices:
                    - cleartext
                    - dot
                    - doh
            retry:
                description:
                    - Number of times to retry (0 - 5).
                type: int
            secondary:
                description:
                    - Secondary DNS server IP address.
                type: str
            server_hostname:
                description:
                    - DNS server host name list.
                type: list
                elements: dict
                suboptions:
                    hostname:
                        description:
                            - DNS server host name list separated by space (maximum 4 domains).
                        type: str
            server_select_method:
                description:
                    - Specify how configured servers are prioritized.
                type: str
                choices:
                    - least-rtt
                    - failover
            source_ip:
                description:
                    - IP address used by the DNS server as its source IP.
                type: str
            ssl_certificate:
                description:
                    - Name of local certificate for SSL connections. Source certificate.local.name.
                type: str
            timeout:
                description:
                    - DNS query timeout interval in seconds (1 - 10).
                type: int
"""

EXAMPLES = """
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
  - name: Configure DNS.
    fortios_system_dns:
      vdom:  "{{ vdom }}"
      system_dns:
        alt_primary: "<your_own_value>"
        alt_secondary: "<your_own_value>"
        cache_notfound_responses: "disable"
        dns_cache_limit: "6"
        dns_cache_ttl: "7"
        dns_over_tls: "disable"
        domain:
         -
            domain: "<your_own_value>"
        interface: "<your_own_value> (source system.interface.name)"
        interface_select_method: "auto"
        ip6_primary: "<your_own_value>"
        ip6_secondary: "<your_own_value>"
        log: "disable"
        primary: "<your_own_value>"
        protocol: "cleartext"
        retry: "18"
        secondary: "<your_own_value>"
        server_hostname:
         -
            hostname: "myhostname"
        server_select_method: "least-rtt"
        source_ip: "84.230.14.43"
        ssl_certificate: "<your_own_value> (source certificate.local.name)"
        timeout: "25"

"""

RETURN = """
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

"""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    FortiOSHandler,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_legacy_fortiosapi,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    schema_to_module_spec,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_schema_versioning,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import (
    FAIL_SOCKET_MSG,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.data_post_processor import (
    remove_invalid_fields,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.secret_field import (
    is_secret_field,
)


def filter_system_dns_data(json):
    option_list = [
        "alt_primary",
        "alt_secondary",
        "cache_notfound_responses",
        "dns_cache_limit",
        "dns_cache_ttl",
        "dns_over_tls",
        "domain",
        "interface",
        "interface_select_method",
        "ip6_primary",
        "ip6_secondary",
        "log",
        "primary",
        "protocol",
        "retry",
        "secondary",
        "server_hostname",
        "server_select_method",
        "source_ip",
        "ssl_certificate",
        "timeout",
    ]

    json = remove_invalid_fields(json)
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def flatten_single_path(data, path, index):
    if (
        not data
        or index == len(path)
        or path[index] not in data
        or not data[path[index]]
    ):
        return

    if index == len(path) - 1:
        data[path[index]] = " ".join(str(elem) for elem in data[path[index]])
    elif isinstance(data[path[index]], list):
        for value in data[path[index]]:
            flatten_single_path(value, path, index + 1)
    else:
        flatten_single_path(data[path[index]], path, index + 1)


def flatten_multilists_attributes(data):
    multilist_attrs = [
        ["protocol"],
    ]

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
            new_data[k.replace("_", "-")] = underscore_to_hyphen(v)
        data = new_data

    return data


def system_dns(data, fos):
    vdom = data["vdom"]
    system_dns_data = data["system_dns"]
    system_dns_data = flatten_multilists_attributes(system_dns_data)
    filtered_data = underscore_to_hyphen(filter_system_dns_data(system_dns_data))

    return fos.set("system", "dns", data=filtered_data, vdom=vdom)


def is_successful_status(resp):
    return (
        "status" in resp
        and resp["status"] == "success"
        or "http_status" in resp
        and resp["http_status"] == 200
        or "http_method" in resp
        and resp["http_method"] == "DELETE"
        and resp["http_status"] == 404
    )


def fortios_system(data, fos):

    fos.do_member_operation("system", "dns")
    if data["system_dns"]:
        resp = system_dns(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_dns"))

    return (
        not is_successful_status(resp),
        is_successful_status(resp)
        and (resp["revision_changed"] if "revision_changed" in resp else True),
        resp,
        {},
    )


versioned_schema = {
    "type": "dict",
    "children": {
        "server_hostname": {
            "elements": "dict",
            "type": "list",
            "children": {
                "hostname": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                }
            },
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": False,
            },
        },
        "dns_cache_limit": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "domain": {
            "elements": "dict",
            "type": "list",
            "children": {
                "domain": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                }
            },
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "retry": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "protocol": {
            "multiple_values": True,
            "elements": "str",
            "type": "list",
            "options": [
                {
                    "value": "cleartext",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.2.0": True,
                    },
                },
                {
                    "value": "dot",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.2.0": True,
                    },
                },
                {
                    "value": "doh",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.2.0": True,
                    },
                },
            ],
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": False,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "log": {
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.2.0": True,
                    },
                },
                {
                    "value": "error",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.2.0": True,
                    },
                },
                {
                    "value": "all",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.2.0": True,
                    },
                },
            ],
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": False,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": False,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "cache_notfound_responses": {
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
            ],
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "server_select_method": {
            "type": "string",
            "options": [
                {
                    "value": "least-rtt",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.2.0": True,
                    },
                },
                {
                    "value": "failover",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.2.0": True,
                    },
                },
            ],
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": False,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": False,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "alt_primary": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": False,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": False,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "source_ip": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "primary": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "alt_secondary": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": False,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": False,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "interface": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": False,
            },
        },
        "interface_select_method": {
            "type": "string",
            "options": [
                {
                    "value": "auto",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                },
                {
                    "value": "sdwan",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                },
                {
                    "value": "specify",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                },
            ],
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": False,
            },
        },
        "ssl_certificate": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": False,
            },
        },
        "timeout": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "dns_over_tls": {
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                },
                {
                    "value": "enforce",
                    "revisions": {
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                },
            ],
            "revisions": {
                "v6.0.0": False,
                "v6.0.5": False,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": False,
            },
        },
        "ip6_primary": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "ip6_secondary": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "dns_cache_ttl": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "secondary": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
    },
    "revisions": {
        "v7.0.3": True,
        "v7.0.2": True,
        "v7.0.1": True,
        "v7.0.0": True,
        "v7.0.5": True,
        "v7.0.4": True,
        "v6.4.4": True,
        "v6.0.5": True,
        "v6.0.0": True,
        "v6.4.0": True,
        "v6.4.1": True,
        "v6.2.0": True,
        "v7.2.0": True,
        "v6.2.3": True,
        "v6.2.5": True,
        "v6.2.7": True,
        "v6.0.11": True,
    },
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = None
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "enable_log": {"required": False, "type": "bool", "default": False},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"],
        },
        "system_dns": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_dns"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_dns"]["options"][attribute_name]["required"] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=False)
    check_legacy_fortiosapi(module)

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if "access_token" in module.params:
            connection.set_option("access_token", module.params["access_token"])

        if "enable_log" in module.params:
            connection.set_option("enable_log", module.params["enable_log"])
        else:
            connection.set_option("enable_log", False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(
            fos, versioned_schema, "system_dns"
        )

        is_error, has_changed, result, diff = fortios_system(module.params, fos)

    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result["matched"] is False:
        module.warn(
            "Ansible has detected version mismatch between FortOS system and your playbook, see more details by specifying option -vvv"
        )

    if not is_error:
        if versions_check_result and versions_check_result["matched"] is False:
            module.exit_json(
                changed=has_changed,
                version_check_warning=versions_check_result,
                meta=result,
                diff=diff,
            )
        else:
            module.exit_json(changed=has_changed, meta=result, diff=diff)
    else:
        if versions_check_result and versions_check_result["matched"] is False:
            module.fail_json(
                msg="Error in repo",
                version_check_warning=versions_check_result,
                meta=result,
            )
        else:
            module.fail_json(msg="Error in repo", meta=result)


if __name__ == "__main__":
    main()
