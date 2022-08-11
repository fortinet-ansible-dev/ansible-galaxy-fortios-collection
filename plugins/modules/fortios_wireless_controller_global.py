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
module: fortios_wireless_controller_global
short_description: Configure wireless controller global settings in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify wireless_controller feature and global category.
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

    wireless_controller_global:
        description:
            - Configure wireless controller global settings.
        default: null
        type: dict
        suboptions:
            ap_log_server:
                description:
                    - Enable/disable configuring FortiGate to redirect wireless event log messages or FortiAPs to send UTM log messages to a syslog server .
                type: str
                choices:
                    - enable
                    - disable
            ap_log_server_ip:
                description:
                    - IP address that FortiGate or FortiAPs send log messages to.
                type: str
            ap_log_server_port:
                description:
                    - Port that FortiGate or FortiAPs send log messages to.
                type: int
            control_message_offload:
                description:
                    - Configure CAPWAP control message data channel offload.
                type: list
                elements: str
                choices:
                    - ebp-frame
                    - aeroscout-tag
                    - ap-list
                    - sta-list
                    - sta-cap-list
                    - stats
                    - aeroscout-mu
                    - sta-health
                    - spectral-analysis
            data_ethernet_II:
                description:
                    - Configure the wireless controller to use Ethernet II or 802.3 frames with 802.3 data tunnel mode .
                type: str
                choices:
                    - enable
                    - disable
            discovery_mc_addr:
                description:
                    - Multicast IP address for AP discovery .
                type: str
            fiapp_eth_type:
                description:
                    - Ethernet type for Fortinet Inter-Access Point Protocol (IAPP), or IEEE 802.11f, packets (0 - 65535).
                type: int
            image_download:
                description:
                    - Enable/disable WTP image download at join time.
                type: str
                choices:
                    - enable
                    - disable
            ipsec_base_ip:
                description:
                    - Base IP address for IPsec VPN tunnels between the access points and the wireless controller .
                type: str
            link_aggregation:
                description:
                    - Enable/disable calculating the CAPWAP transmit hash to load balance sessions to link aggregation nodes .
                type: str
                choices:
                    - enable
                    - disable
            location:
                description:
                    - Description of the location of the wireless controller.
                type: str
            max_clients:
                description:
                    - Maximum number of clients that can connect simultaneously .
                type: int
            max_retransmit:
                description:
                    - Maximum number of tunnel packet retransmissions (0 - 64).
                type: int
            mesh_eth_type:
                description:
                    - Mesh Ethernet identifier included in backhaul packets (0 - 65535).
                type: int
            nac_interval:
                description:
                    - Interval in seconds between two WiFi network access control (NAC) checks (10 - 600).
                type: int
            name:
                description:
                    - Name of the wireless controller.
                type: str
            rogue_scan_mac_adjacency:
                description:
                    - Maximum numerical difference between an AP"s Ethernet and wireless MAC values to match for rogue detection (0 - 31).
                type: int
            tunnel_mode:
                description:
                    - Compatible/strict tunnel mode.
                type: str
                choices:
                    - compatible
                    - strict
            wtp_share:
                description:
                    - Enable/disable sharing of WTPs between VDOMs.
                type: str
                choices:
                    - enable
                    - disable
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
  - name: Configure wireless controller global settings.
    fortios_wireless_controller_global:
      vdom:  "{{ vdom }}"
      wireless_controller_global:
        ap_log_server: "enable"
        ap_log_server_ip: "<your_own_value>"
        ap_log_server_port: "5"
        control_message_offload: "ebp-frame"
        data_ethernet_II: "enable"
        discovery_mc_addr: "<your_own_value>"
        fiapp_eth_type: "9"
        image_download: "enable"
        ipsec_base_ip: "<your_own_value>"
        link_aggregation: "enable"
        location: "<your_own_value>"
        max_clients: "14"
        max_retransmit: "15"
        mesh_eth_type: "16"
        nac_interval: "17"
        name: "default_name_18"
        rogue_scan_mac_adjacency: "19"
        tunnel_mode: "compatible"
        wtp_share: "enable"

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


def filter_wireless_controller_global_data(json):
    option_list = [
        "ap_log_server",
        "ap_log_server_ip",
        "ap_log_server_port",
        "control_message_offload",
        "data_ethernet_II",
        "discovery_mc_addr",
        "fiapp_eth_type",
        "image_download",
        "ipsec_base_ip",
        "link_aggregation",
        "location",
        "max_clients",
        "max_retransmit",
        "mesh_eth_type",
        "nac_interval",
        "name",
        "rogue_scan_mac_adjacency",
        "tunnel_mode",
        "wtp_share",
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
        ["control_message_offload"],
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


def wireless_controller_global(data, fos):
    vdom = data["vdom"]
    wireless_controller_global_data = data["wireless_controller_global"]
    wireless_controller_global_data = flatten_multilists_attributes(
        wireless_controller_global_data
    )
    filtered_data = underscore_to_hyphen(
        filter_wireless_controller_global_data(wireless_controller_global_data)
    )

    return fos.set("wireless-controller", "global", data=filtered_data, vdom=vdom)


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


def fortios_wireless_controller(data, fos):

    fos.do_member_operation("wireless-controller", "global")
    if data["wireless_controller_global"]:
        resp = wireless_controller_global(data, fos)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("wireless_controller_global")
        )

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
        "ipsec_base_ip": {
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
        "max_retransmit": {
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
        "name": {
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
        "data_ethernet_II": {
            "type": "string",
            "options": [
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
        "discovery_mc_addr": {
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
        "wtp_share": {
            "type": "string",
            "options": [
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
        "rogue_scan_mac_adjacency": {
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
        "nac_interval": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": False,
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
        "ap_log_server_port": {
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
        "tunnel_mode": {
            "type": "string",
            "options": [
                {
                    "value": "compatible",
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
                    "value": "strict",
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
        "location": {
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
        "control_message_offload": {
            "multiple_values": True,
            "elements": "str",
            "type": "list",
            "options": [
                {
                    "value": "ebp-frame",
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
                    "value": "aeroscout-tag",
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
                    "value": "ap-list",
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
                    "value": "sta-list",
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
                    "value": "sta-cap-list",
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
                    "value": "stats",
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
                    "value": "aeroscout-mu",
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
                    "value": "sta-health",
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
                {
                    "value": "spectral-analysis",
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
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
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
        "mesh_eth_type": {
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
        "image_download": {
            "type": "string",
            "options": [
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
        "ap_log_server_ip": {
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
        "ap_log_server": {
            "type": "string",
            "options": [
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
        "max_clients": {
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
        "fiapp_eth_type": {
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
        "link_aggregation": {
            "type": "string",
            "options": [
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
        "wireless_controller_global": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["wireless_controller_global"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["wireless_controller_global"]["options"][attribute_name][
                "required"
            ] = True

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
            fos, versioned_schema, "wireless_controller_global"
        )

        is_error, has_changed, result, diff = fortios_wireless_controller(
            module.params, fos
        )

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
