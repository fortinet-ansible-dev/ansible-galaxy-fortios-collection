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
module: fortios_router_ospf
short_description: Configure OSPF in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify router feature and ospf category.
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

    router_ospf:
        description:
            - Configure OSPF.
        default: null
        type: dict
        suboptions:
            abr_type:
                description:
                    - Area border router type.
                type: str
                choices:
                    - cisco
                    - ibm
                    - shortcut
                    - standard
            area:
                description:
                    - OSPF area configuration.
                type: list
                elements: dict
                suboptions:
                    authentication:
                        description:
                            - Authentication type.
                        type: str
                        choices:
                            - none
                            - text
                            - message-digest
                            - md5
                    comments:
                        description:
                            - Comment.
                        type: str
                    default_cost:
                        description:
                            - Summary default cost of stub or NSSA area.
                        type: int
                    filter_list:
                        description:
                            - OSPF area filter-list configuration.
                        type: list
                        elements: dict
                        suboptions:
                            direction:
                                description:
                                    - Direction.
                                type: str
                                choices:
                                    - in
                                    - out
                            id:
                                description:
                                    - Filter list entry ID.
                                type: int
                            list:
                                description:
                                    - Access-list or prefix-list name. Source router.access-list.name router.prefix-list.name.
                                type: str
                    id:
                        description:
                            - Area entry IP address.
                        type: str
                    nssa_default_information_originate:
                        description:
                            - Redistribute, advertise, or do not originate Type-7 default route into NSSA area.
                        type: str
                        choices:
                            - enable
                            - always
                            - disable
                    nssa_default_information_originate_metric:
                        description:
                            - OSPF default metric.
                        type: int
                    nssa_default_information_originate_metric_type:
                        description:
                            - OSPF metric type for default routes.
                        type: str
                        choices:
                            - 1
                            - 2
                    nssa_redistribution:
                        description:
                            - Enable/disable redistribute into NSSA area.
                        type: str
                        choices:
                            - enable
                            - disable
                    nssa_translator_role:
                        description:
                            - NSSA translator role type.
                        type: str
                        choices:
                            - candidate
                            - never
                            - always
                    range:
                        description:
                            - OSPF area range configuration.
                        type: list
                        elements: dict
                        suboptions:
                            advertise:
                                description:
                                    - Enable/disable advertise status.
                                type: str
                                choices:
                                    - disable
                                    - enable
                            id:
                                description:
                                    - Range entry ID.
                                type: int
                            prefix:
                                description:
                                    - Prefix.
                                type: str
                            substitute:
                                description:
                                    - Substitute prefix.
                                type: str
                            substitute_status:
                                description:
                                    - Enable/disable substitute status.
                                type: str
                                choices:
                                    - enable
                                    - disable
                    shortcut:
                        description:
                            - Enable/disable shortcut option.
                        type: str
                        choices:
                            - disable
                            - enable
                            - default
                    stub_type:
                        description:
                            - Stub summary setting.
                        type: str
                        choices:
                            - no-summary
                            - summary
                    type:
                        description:
                            - Area type setting.
                        type: str
                        choices:
                            - regular
                            - nssa
                            - stub
                    virtual_link:
                        description:
                            - OSPF virtual link configuration.
                        type: list
                        elements: dict
                        suboptions:
                            authentication:
                                description:
                                    - Authentication type.
                                type: str
                                choices:
                                    - none
                                    - text
                                    - message-digest
                                    - md5
                            authentication_key:
                                description:
                                    - Authentication key.
                                type: str
                            dead_interval:
                                description:
                                    - Dead interval.
                                type: int
                            hello_interval:
                                description:
                                    - Hello interval.
                                type: int
                            keychain:
                                description:
                                    - Message-digest key-chain name. Source router.key-chain.name.
                                type: str
                            md5_key:
                                description:
                                    - MD5 key.
                                type: str
                            md5_keychain:
                                description:
                                    - Authentication MD5 key-chain name. Source router.key-chain.name.
                                type: str
                            md5_keys:
                                description:
                                    - MD5 key.
                                type: list
                                elements: dict
                                suboptions:
                                    id:
                                        description:
                                            - Key ID (1 - 255).
                                        type: int
                                    key_string:
                                        description:
                                            - Password for the key.
                                        type: str
                            name:
                                description:
                                    - Virtual link entry name.
                                type: str
                            peer:
                                description:
                                    - Peer IP.
                                type: str
                            retransmit_interval:
                                description:
                                    - Retransmit interval.
                                type: int
                            transmit_delay:
                                description:
                                    - Transmit delay.
                                type: int
            auto_cost_ref_bandwidth:
                description:
                    - Reference bandwidth in terms of megabits per second.
                type: int
            bfd:
                description:
                    - Bidirectional Forwarding Detection (BFD).
                type: str
                choices:
                    - enable
                    - disable
            database_overflow:
                description:
                    - Enable/disable database overflow.
                type: str
                choices:
                    - enable
                    - disable
            database_overflow_max_lsas:
                description:
                    - Database overflow maximum LSAs.
                type: int
            database_overflow_time_to_recover:
                description:
                    - Database overflow time to recover (sec).
                type: int
            default_information_metric:
                description:
                    - Default information metric.
                type: int
            default_information_metric_type:
                description:
                    - Default information metric type.
                type: str
                choices:
                    - 1
                    - 2
            default_information_originate:
                description:
                    - Enable/disable generation of default route.
                type: str
                choices:
                    - enable
                    - always
                    - disable
            default_information_route_map:
                description:
                    - Default information route map. Source router.route-map.name.
                type: str
            default_metric:
                description:
                    - Default metric of redistribute routes.
                type: int
            distance:
                description:
                    - Distance of the route.
                type: int
            distance_external:
                description:
                    - Administrative external distance.
                type: int
            distance_inter_area:
                description:
                    - Administrative inter-area distance.
                type: int
            distance_intra_area:
                description:
                    - Administrative intra-area distance.
                type: int
            distribute_list:
                description:
                    - Distribute list configuration.
                type: list
                elements: dict
                suboptions:
                    access_list:
                        description:
                            - Access list name. Source router.access-list.name.
                        type: str
                    id:
                        description:
                            - Distribute list entry ID.
                        type: int
                    protocol:
                        description:
                            - Protocol type.
                        type: str
                        choices:
                            - connected
                            - static
                            - rip
            distribute_list_in:
                description:
                    - Filter incoming routes. Source router.access-list.name router.prefix-list.name.
                type: str
            distribute_route_map_in:
                description:
                    - Filter incoming external routes by route-map. Source router.route-map.name.
                type: str
            log_neighbour_changes:
                description:
                    - Log of OSPF neighbor changes.
                type: str
                choices:
                    - enable
                    - disable
            neighbor:
                description:
                    - OSPF neighbor configuration are used when OSPF runs on non-broadcast media.
                type: list
                elements: dict
                suboptions:
                    cost:
                        description:
                            - Cost of the interface, value range from 0 to 65535, 0 means auto-cost.
                        type: int
                    id:
                        description:
                            - Neighbor entry ID.
                        type: int
                    ip:
                        description:
                            - Interface IP address of the neighbor.
                        type: str
                    poll_interval:
                        description:
                            - Poll interval time in seconds.
                        type: int
                    priority:
                        description:
                            - Priority.
                        type: int
            network:
                description:
                    - OSPF network configuration.
                type: list
                elements: dict
                suboptions:
                    area:
                        description:
                            - Attach the network to area.
                        type: str
                    comments:
                        description:
                            - Comment.
                        type: str
                    id:
                        description:
                            - Network entry ID.
                        type: int
                    prefix:
                        description:
                            - Prefix.
                        type: str
            ospf_interface:
                description:
                    - OSPF interface configuration.
                type: list
                elements: dict
                suboptions:
                    authentication:
                        description:
                            - Authentication type.
                        type: str
                        choices:
                            - none
                            - text
                            - message-digest
                            - md5
                    authentication_key:
                        description:
                            - Authentication key.
                        type: str
                    bfd:
                        description:
                            - Bidirectional Forwarding Detection (BFD).
                        type: str
                        choices:
                            - global
                            - enable
                            - disable
                    comments:
                        description:
                            - Comment.
                        type: str
                    cost:
                        description:
                            - Cost of the interface, value range from 0 to 65535, 0 means auto-cost.
                        type: int
                    database_filter_out:
                        description:
                            - Enable/disable control of flooding out LSAs.
                        type: str
                        choices:
                            - enable
                            - disable
                    dead_interval:
                        description:
                            - Dead interval.
                        type: int
                    hello_interval:
                        description:
                            - Hello interval.
                        type: int
                    hello_multiplier:
                        description:
                            - Number of hello packets within dead interval.
                        type: int
                    interface:
                        description:
                            - Configuration interface name. Source system.interface.name.
                        type: str
                    ip:
                        description:
                            - IP address.
                        type: str
                    keychain:
                        description:
                            - Message-digest key-chain name. Source router.key-chain.name.
                        type: str
                    md5_key:
                        description:
                            - MD5 key.
                        type: str
                    md5_keychain:
                        description:
                            - Authentication MD5 key-chain name. Source router.key-chain.name.
                        type: str
                    md5_keys:
                        description:
                            - MD5 key.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - Key ID (1 - 255).
                                type: int
                            key_string:
                                description:
                                    - Password for the key.
                                type: str
                    mtu:
                        description:
                            - MTU for database description packets.
                        type: int
                    mtu_ignore:
                        description:
                            - Enable/disable ignore MTU.
                        type: str
                        choices:
                            - enable
                            - disable
                    name:
                        description:
                            - Interface entry name.
                        type: str
                    network_type:
                        description:
                            - Network type.
                        type: str
                        choices:
                            - broadcast
                            - non-broadcast
                            - point-to-point
                            - point-to-multipoint
                            - point-to-multipoint-non-broadcast
                    prefix_length:
                        description:
                            - Prefix length.
                        type: int
                    priority:
                        description:
                            - Priority.
                        type: int
                    resync_timeout:
                        description:
                            - Graceful restart neighbor resynchronization timeout.
                        type: int
                    retransmit_interval:
                        description:
                            - Retransmit interval.
                        type: int
                    status:
                        description:
                            - Enable/disable status.
                        type: str
                        choices:
                            - disable
                            - enable
                    transmit_delay:
                        description:
                            - Transmit delay.
                        type: int
            passive_interface:
                description:
                    - Passive interface configuration.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Passive interface name. Source system.interface.name.
                        type: str
            redistribute:
                description:
                    - Redistribute configuration.
                type: list
                elements: dict
                suboptions:
                    metric:
                        description:
                            - Redistribute metric setting.
                        type: int
                    metric_type:
                        description:
                            - Metric type.
                        type: str
                        choices:
                            - 1
                            - 2
                    name:
                        description:
                            - Redistribute name.
                        type: str
                    routemap:
                        description:
                            - Route map name. Source router.route-map.name.
                        type: str
                    status:
                        description:
                            - Status.
                        type: str
                        choices:
                            - enable
                            - disable
                    tag:
                        description:
                            - Tag value.
                        type: int
            restart_mode:
                description:
                    - OSPF restart mode (graceful or LLS).
                type: str
                choices:
                    - none
                    - lls
                    - graceful-restart
            restart_on_topology_change:
                description:
                    - Enable/disable continuing graceful restart upon topology change.
                type: str
                choices:
                    - enable
                    - disable
            restart_period:
                description:
                    - Graceful restart period.
                type: int
            rfc1583_compatible:
                description:
                    - Enable/disable RFC1583 compatibility.
                type: str
                choices:
                    - enable
                    - disable
            router_id:
                description:
                    - Router ID.
                type: str
            spf_timers:
                description:
                    - SPF calculation frequency.
                type: str
            summary_address:
                description:
                    - IP address summary configuration.
                type: list
                elements: dict
                suboptions:
                    advertise:
                        description:
                            - Enable/disable advertise status.
                        type: str
                        choices:
                            - disable
                            - enable
                    id:
                        description:
                            - Summary address entry ID.
                        type: int
                    prefix:
                        description:
                            - Prefix.
                        type: str
                    tag:
                        description:
                            - Tag value.
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
  - name: Configure OSPF.
    fortios_router_ospf:
      vdom:  "{{ vdom }}"
      router_ospf:
        abr_type: "cisco"
        area:
         -
            authentication: "none"
            comments: "<your_own_value>"
            default_cost: "7"
            filter_list:
             -
                direction: "in"
                id:  "10"
                list: "<your_own_value> (source router.access-list.name router.prefix-list.name)"
            id:  "12"
            nssa_default_information_originate: "enable"
            nssa_default_information_originate_metric: "14"
            nssa_default_information_originate_metric_type: "1"
            nssa_redistribution: "enable"
            nssa_translator_role: "candidate"
            range:
             -
                advertise: "disable"
                id:  "20"
                prefix: "<your_own_value>"
                substitute: "<your_own_value>"
                substitute_status: "enable"
            shortcut: "disable"
            stub_type: "no-summary"
            type: "regular"
            virtual_link:
             -
                authentication: "none"
                authentication_key: "<your_own_value>"
                dead_interval: "30"
                hello_interval: "31"
                keychain: "<your_own_value> (source router.key-chain.name)"
                md5_key: "<your_own_value>"
                md5_keychain: "<your_own_value> (source router.key-chain.name)"
                md5_keys:
                 -
                    id:  "36"
                    key_string: "<your_own_value>"
                name: "default_name_38"
                peer: "<your_own_value>"
                retransmit_interval: "40"
                transmit_delay: "41"
        auto_cost_ref_bandwidth: "42"
        bfd: "enable"
        database_overflow: "enable"
        database_overflow_max_lsas: "45"
        database_overflow_time_to_recover: "46"
        default_information_metric: "47"
        default_information_metric_type: "1"
        default_information_originate: "enable"
        default_information_route_map: "<your_own_value> (source router.route-map.name)"
        default_metric: "51"
        distance: "52"
        distance_external: "53"
        distance_inter_area: "54"
        distance_intra_area: "55"
        distribute_list:
         -
            access_list: "<your_own_value> (source router.access-list.name)"
            id:  "58"
            protocol: "connected"
        distribute_list_in: "<your_own_value> (source router.access-list.name router.prefix-list.name)"
        distribute_route_map_in: "<your_own_value> (source router.route-map.name)"
        log_neighbour_changes: "enable"
        neighbor:
         -
            cost: "64"
            id:  "65"
            ip: "<your_own_value>"
            poll_interval: "67"
            priority: "68"
        network:
         -
            area: "<your_own_value>"
            comments: "<your_own_value>"
            id:  "72"
            prefix: "<your_own_value>"
        ospf_interface:
         -
            authentication: "none"
            authentication_key: "<your_own_value>"
            bfd: "global"
            comments: "<your_own_value>"
            cost: "79"
            database_filter_out: "enable"
            dead_interval: "81"
            hello_interval: "82"
            hello_multiplier: "83"
            interface: "<your_own_value> (source system.interface.name)"
            ip: "<your_own_value>"
            keychain: "<your_own_value> (source router.key-chain.name)"
            md5_key: "<your_own_value>"
            md5_keychain: "<your_own_value> (source router.key-chain.name)"
            md5_keys:
             -
                id:  "90"
                key_string: "<your_own_value>"
            mtu: "92"
            mtu_ignore: "enable"
            name: "default_name_94"
            network_type: "broadcast"
            prefix_length: "96"
            priority: "97"
            resync_timeout: "98"
            retransmit_interval: "99"
            status: "disable"
            transmit_delay: "101"
        passive_interface:
         -
            name: "default_name_103 (source system.interface.name)"
        redistribute:
         -
            metric: "105"
            metric_type: "1"
            name: "default_name_107"
            routemap: "<your_own_value> (source router.route-map.name)"
            status: "enable"
            tag: "110"
        restart_mode: "none"
        restart_on_topology_change: "enable"
        restart_period: "113"
        rfc1583_compatible: "enable"
        router_id: "<your_own_value>"
        spf_timers: "<your_own_value>"
        summary_address:
         -
            advertise: "disable"
            id:  "119"
            prefix: "<your_own_value>"
            tag: "121"

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


def filter_router_ospf_data(json):
    option_list = [
        "abr_type",
        "area",
        "auto_cost_ref_bandwidth",
        "bfd",
        "database_overflow",
        "database_overflow_max_lsas",
        "database_overflow_time_to_recover",
        "default_information_metric",
        "default_information_metric_type",
        "default_information_originate",
        "default_information_route_map",
        "default_metric",
        "distance",
        "distance_external",
        "distance_inter_area",
        "distance_intra_area",
        "distribute_list",
        "distribute_list_in",
        "distribute_route_map_in",
        "log_neighbour_changes",
        "neighbor",
        "network",
        "ospf_interface",
        "passive_interface",
        "redistribute",
        "restart_mode",
        "restart_on_topology_change",
        "restart_period",
        "rfc1583_compatible",
        "router_id",
        "spf_timers",
        "summary_address",
    ]

    json = remove_invalid_fields(json)
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
            new_data[k.replace("_", "-")] = underscore_to_hyphen(v)
        data = new_data

    return data


def router_ospf(data, fos):
    vdom = data["vdom"]
    router_ospf_data = data["router_ospf"]
    filtered_data = underscore_to_hyphen(filter_router_ospf_data(router_ospf_data))

    return fos.set("router", "ospf", data=filtered_data, vdom=vdom)


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


def fortios_router(data, fos):

    fos.do_member_operation("router", "ospf")
    if data["router_ospf"]:
        resp = router_ospf(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("router_ospf"))

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
        "distribute_route_map_in": {
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
        "default_information_metric": {
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
        "distance_intra_area": {
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
        "default_information_metric_type": {
            "type": "string",
            "options": [
                {
                    "value": "1",
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
                    "value": "2",
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
        "network": {
            "elements": "dict",
            "type": "list",
            "children": {
                "prefix": {
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
                "id": {
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
                "comments": {
                    "type": "string",
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
                "area": {
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
        },
        "area": {
            "elements": "dict",
            "type": "list",
            "children": {
                "stub_type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "no-summary",
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
                            "value": "summary",
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
                "nssa_default_information_originate_metric": {
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
                "nssa_default_information_originate_metric_type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "1",
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
                            "value": "2",
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
                "nssa_default_information_originate": {
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
                            "value": "always",
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
                "nssa_redistribution": {
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
                "shortcut": {
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
                        {
                            "value": "default",
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
                "default_cost": {
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
                "authentication": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
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
                            "value": "text",
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
                            "value": "message-digest",
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
                        {
                            "value": "md5",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
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
                "nssa_translator_role": {
                    "type": "string",
                    "options": [
                        {
                            "value": "candidate",
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
                            "value": "never",
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
                            "value": "always",
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
                "virtual_link": {
                    "elements": "dict",
                    "type": "list",
                    "children": {
                        "retransmit_interval": {
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
                        "md5_keys": {
                            "elements": "dict",
                            "type": "list",
                            "children": {
                                "key_string": {
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
                                },
                                "id": {
                                    "type": "integer",
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
                        "keychain": {
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
                        "md5_keychain": {
                            "type": "string",
                            "revisions": {
                                "v6.0.0": False,
                                "v7.0.0": True,
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
                        "md5_key": {
                            "type": "string",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "authentication": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "none",
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
                                    "value": "text",
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
                                    "value": "message-digest",
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
                                {
                                    "value": "md5",
                                    "revisions": {
                                        "v6.0.0": True,
                                        "v7.0.0": True,
                                        "v6.0.5": True,
                                        "v6.4.4": True,
                                        "v6.4.0": True,
                                        "v6.4.1": True,
                                        "v6.2.0": True,
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
                        "dead_interval": {
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
                        "hello_interval": {
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
                        "peer": {
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
                        "authentication_key": {
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
                        "transmit_delay": {
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
                "filter_list": {
                    "elements": "dict",
                    "type": "list",
                    "children": {
                        "direction": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "in",
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
                                    "value": "out",
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
                        "list": {
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
                        "id": {
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
                "range": {
                    "elements": "dict",
                    "type": "list",
                    "children": {
                        "substitute_status": {
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
                        "advertise": {
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
                        "prefix": {
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
                        "substitute": {
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
                        "id": {
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
                "type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "regular",
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
                            "value": "nssa",
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
                            "value": "stub",
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
                "id": {
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
                "comments": {
                    "type": "string",
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
        "distribute_list": {
            "elements": "dict",
            "type": "list",
            "children": {
                "protocol": {
                    "type": "string",
                    "options": [
                        {
                            "value": "connected",
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
                            "value": "static",
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
                            "value": "rip",
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
                "id": {
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
                "access_list": {
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
        },
        "abr_type": {
            "type": "string",
            "options": [
                {
                    "value": "cisco",
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
                    "value": "ibm",
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
                    "value": "shortcut",
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
                    "value": "standard",
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
        "distance_external": {
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
        "default_information_originate": {
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
                    "value": "always",
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
        "passive_interface": {
            "elements": "dict",
            "type": "list",
            "children": {
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
        "restart_mode": {
            "type": "string",
            "options": [
                {
                    "value": "none",
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
                    "value": "lls",
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
                    "value": "graceful-restart",
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
        "default_information_route_map": {
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
        "router_id": {
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
        "distance_inter_area": {
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
        "auto_cost_ref_bandwidth": {
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
        "log_neighbour_changes": {
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
        "restart_on_topology_change": {
            "type": "string",
            "options": [
                {"value": "enable", "revisions": {"v7.2.0": True}},
                {"value": "disable", "revisions": {"v7.2.0": True}},
            ],
            "revisions": {
                "v7.0.3": False,
                "v7.0.2": False,
                "v7.0.1": False,
                "v7.0.0": False,
                "v7.0.5": False,
                "v7.0.4": False,
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
        "default_metric": {
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
        "summary_address": {
            "elements": "dict",
            "type": "list",
            "children": {
                "prefix": {
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
                "tag": {
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
                "id": {
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
                "advertise": {
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
        "spf_timers": {
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
        "distance": {
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
        "redistribute": {
            "elements": "dict",
            "type": "list",
            "children": {
                "status": {
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
                "metric": {
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
                "tag": {
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
                "metric_type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "1",
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
                            "value": "2",
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
                "routemap": {
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
        },
        "restart_period": {
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
        "bfd": {
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
        "distribute_list_in": {
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
        "database_overflow": {
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
        "database_overflow_max_lsas": {
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
        "database_overflow_time_to_recover": {
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
        "neighbor": {
            "elements": "dict",
            "type": "list",
            "children": {
                "priority": {
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
                "ip": {
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
                "cost": {
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
                "poll_interval": {
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
                "id": {
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
        "rfc1583_compatible": {
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
        "ospf_interface": {
            "elements": "dict",
            "type": "list",
            "children": {
                "ip": {
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
                "md5_key": {
                    "type": "string",
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "cost": {
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
                "hello_interval": {
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
                "mtu": {
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
                "retransmit_interval": {
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
                "keychain": {
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
                "bfd": {
                    "type": "string",
                    "options": [
                        {
                            "value": "global",
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
                "comments": {
                    "type": "string",
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
                "priority": {
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
                "authentication": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
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
                            "value": "text",
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
                            "value": "message-digest",
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
                        {
                            "value": "md5",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
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
                "prefix_length": {
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
                "authentication_key": {
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
                "resync_timeout": {
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
                "status": {
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
                "database_filter_out": {
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
                "hello_multiplier": {
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
                "transmit_delay": {
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
                "md5_keys": {
                    "elements": "dict",
                    "type": "list",
                    "children": {
                        "key_string": {
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
                        },
                        "id": {
                            "type": "integer",
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
                "md5_keychain": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": False,
                        "v7.0.0": True,
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
                "mtu_ignore": {
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
                "dead_interval": {
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
                "network_type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "broadcast",
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
                            "value": "non-broadcast",
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
                            "value": "point-to-point",
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
                            "value": "point-to-multipoint",
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
                            "value": "point-to-multipoint-non-broadcast",
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
        "router_ospf": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["router_ospf"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["router_ospf"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "router_ospf"
        )

        is_error, has_changed, result, diff = fortios_router(module.params, fos)

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
