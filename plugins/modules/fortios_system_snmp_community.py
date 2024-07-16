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
module: fortios_system_snmp_community
short_description: SNMP community configuration in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system_snmp feature and community category.
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
    - We highly recommend using your own value as the id instead of 0, while '0' is a special placeholder that allows the backend to assign the latest
       available number for the object, it does have limitations. Please find more details in Q&A.
    - Legacy fortiosapi has been deprecated, httpapi is the preferred way to run playbooks

    - The module supports check_mode.

requirements:
    - ansible>=2.15
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
            - 'present'
            - 'absent'

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - 'present'
            - 'absent'
    system_snmp_community:
        description:
            - SNMP community configuration.
        default: null
        type: dict
        suboptions:
            events:
                description:
                    - SNMP trap events.
                type: list
                elements: str
                choices:
                    - 'cpu-high'
                    - 'mem-low'
                    - 'log-full'
                    - 'intf-ip'
                    - 'vpn-tun-up'
                    - 'vpn-tun-down'
                    - 'ha-switch'
                    - 'ha-hb-failure'
                    - 'ips-signature'
                    - 'ips-anomaly'
                    - 'av-virus'
                    - 'av-oversize'
                    - 'av-pattern'
                    - 'av-fragmented'
                    - 'fm-if-change'
                    - 'fm-conf-change'
                    - 'bgp-established'
                    - 'bgp-backward-transition'
                    - 'ha-member-up'
                    - 'ha-member-down'
                    - 'ent-conf-change'
                    - 'av-conserve'
                    - 'av-bypass'
                    - 'av-oversize-passed'
                    - 'av-oversize-blocked'
                    - 'ips-pkg-update'
                    - 'ips-fail-open'
                    - 'faz-disconnect'
                    - 'faz'
                    - 'wc-ap-up'
                    - 'wc-ap-down'
                    - 'fswctl-session-up'
                    - 'fswctl-session-down'
                    - 'load-balance-real-server-down'
                    - 'device-new'
                    - 'per-cpu-high'
                    - 'dhcp'
                    - 'pool-usage'
                    - 'ospf-nbr-state-change'
                    - 'ospf-virtnbr-state-change'
                    - 'temperature-high'
                    - 'voltage-alert'
                    - 'power-supply'
                    - 'fan-failure'
                    - 'power-supply-failure'
            hosts:
                description:
                    - Configure IPv4 SNMP managers (hosts).
                type: list
                elements: dict
                suboptions:
                    ha_direct:
                        description:
                            - Enable/disable direct management of HA cluster members.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    host_type:
                        description:
                            - Control whether the SNMP manager sends SNMP queries, receives SNMP traps, or both. No traps will be sent when IP type is subnet.
                        type: str
                        choices:
                            - 'any'
                            - 'query'
                            - 'trap'
                    id:
                        description:
                            - Host entry ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    ip:
                        description:
                            - IPv4 address of the SNMP manager (host).
                        type: str
                    source_ip:
                        description:
                            - Source IPv4 address for SNMP traps.
                        type: str
            hosts6:
                description:
                    - Configure IPv6 SNMP managers.
                type: list
                elements: dict
                suboptions:
                    ha_direct:
                        description:
                            - Enable/disable direct management of HA cluster members.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    host_type:
                        description:
                            - Control whether the SNMP manager sends SNMP queries, receives SNMP traps, or both.
                        type: str
                        choices:
                            - 'any'
                            - 'query'
                            - 'trap'
                    id:
                        description:
                            - Host6 entry ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    ipv6:
                        description:
                            - SNMP manager IPv6 address prefix.
                        type: str
                    source_ipv6:
                        description:
                            - Source IPv6 address for SNMP traps.
                        type: str
            id:
                description:
                    - Community ID. see <a href='#notes'>Notes</a>.
                required: true
                type: int
            mib_view:
                description:
                    - SNMP access control MIB view. Source system.snmp.mib-view.name.
                type: str
            name:
                description:
                    - Community name.
                type: str
            query_v1_port:
                description:
                    - SNMP v1 query port .
                type: int
            query_v1_status:
                description:
                    - Enable/disable SNMP v1 queries.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            query_v2c_port:
                description:
                    - SNMP v2c query port .
                type: int
            query_v2c_status:
                description:
                    - Enable/disable SNMP v2c queries.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            status:
                description:
                    - Enable/disable this SNMP community.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            trap_v1_lport:
                description:
                    - SNMP v1 trap local port .
                type: int
            trap_v1_rport:
                description:
                    - SNMP v1 trap remote port .
                type: int
            trap_v1_status:
                description:
                    - Enable/disable SNMP v1 traps.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            trap_v2c_lport:
                description:
                    - SNMP v2c trap local port .
                type: int
            trap_v2c_rport:
                description:
                    - SNMP v2c trap remote port .
                type: int
            trap_v2c_status:
                description:
                    - Enable/disable SNMP v2c traps.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            vdoms:
                description:
                    - SNMP access control VDOMs.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - VDOM name. Source system.vdom.name.
                        required: true
                        type: str
"""

EXAMPLES = """
- name: SNMP community configuration.
  fortinet.fortios.fortios_system_snmp_community:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      system_snmp_community:
          events: "cpu-high"
          hosts:
              -
                  ha_direct: "enable"
                  host_type: "any"
                  id: "7"
                  ip: "<your_own_value>"
                  source_ip: "84.230.14.43"
          hosts6:
              -
                  ha_direct: "enable"
                  host_type: "any"
                  id: "13"
                  ipv6: "<your_own_value>"
                  source_ipv6: "<your_own_value>"
          id: "16"
          mib_view: "<your_own_value> (source system.snmp.mib-view.name)"
          name: "default_name_18"
          query_v1_port: "161"
          query_v1_status: "enable"
          query_v2c_port: "161"
          query_v2c_status: "enable"
          status: "enable"
          trap_v1_lport: "162"
          trap_v1_rport: "162"
          trap_v1_status: "enable"
          trap_v2c_lport: "162"
          trap_v2c_rport: "162"
          trap_v2c_status: "enable"
          vdoms:
              -
                  name: "default_name_31 (source system.vdom.name)"
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
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    is_same_comparison,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    serialize,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    find_current_values,
)


def filter_system_snmp_community_data(json):
    option_list = [
        "events",
        "hosts",
        "hosts6",
        "id",
        "mib_view",
        "name",
        "query_v1_port",
        "query_v1_status",
        "query_v2c_port",
        "query_v2c_status",
        "status",
        "trap_v1_lport",
        "trap_v1_rport",
        "trap_v1_status",
        "trap_v2c_lport",
        "trap_v2c_rport",
        "trap_v2c_status",
        "vdoms",
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
        ["events"],
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


def system_snmp_community(data, fos, check_mode=False):
    state = None
    vdom = data["vdom"]

    state = data["state"]

    system_snmp_community_data = data["system_snmp_community"]
    system_snmp_community_data = flatten_multilists_attributes(
        system_snmp_community_data
    )
    filtered_data = filter_system_snmp_community_data(system_snmp_community_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("system.snmp", "community", filtered_data, vdom=vdom)
        current_data = fos.get("system.snmp", "community", vdom=vdom, mkey=mkey)
        is_existed = (
            current_data
            and current_data.get("http_status") == 200
            and isinstance(current_data.get("results"), list)
            and len(current_data["results"]) > 0
        )

        # 2. if it exists and the state is 'present' then compare current settings with desired
        if state == "present" or state is True:
            if mkey is None:
                return False, True, filtered_data, diff

            # if mkey exists then compare each other
            # record exits and they're matched or not
            if is_existed:
                is_same = is_same_comparison(
                    serialize(current_data["results"][0]), serialize(filtered_data)
                )

                current_values = find_current_values(
                    current_data["results"][0], filtered_data
                )

                return (
                    False,
                    not is_same,
                    filtered_data,
                    {"before": current_values, "after": filtered_data},
                )

            # record does not exist
            return False, True, filtered_data, diff

        if state == "absent":
            if mkey is None:
                return (
                    False,
                    False,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )

            if is_existed:
                return (
                    False,
                    True,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )
            return False, False, filtered_data, {}

        return True, False, {"reason: ": "Must provide state parameter"}, {}

    if state == "present" or state is True:
        return fos.set("system.snmp", "community", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "system.snmp", "community", mkey=converted_data["id"], vdom=vdom
        )
    else:
        fos._module.fail_json(msg="state must be present or absent!")


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


def fortios_system_snmp(data, fos, check_mode):
    fos.do_member_operation("system.snmp", "community")
    if data["system_snmp_community"]:
        resp = system_snmp_community(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_snmp_community"))
    if isinstance(resp, tuple) and len(resp) == 4:
        return resp
    return (
        not is_successful_status(resp),
        is_successful_status(resp)
        and (resp["revision_changed"] if "revision_changed" in resp else True),
        resp,
        {},
    )


versioned_schema = {
    "type": "list",
    "elements": "dict",
    "children": {
        "id": {"v_range": [["v6.0.0", ""]], "type": "integer", "required": True},
        "name": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "hosts": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "source_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "ha_direct": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "host_type": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "any"},
                        {"value": "query"},
                        {"value": "trap"},
                    ],
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "hosts6": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "source_ipv6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "ipv6": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "ha_direct": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "host_type": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "any"},
                        {"value": "query"},
                        {"value": "trap"},
                    ],
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "query_v1_status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "query_v1_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "query_v2c_status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "query_v2c_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "trap_v1_status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "trap_v1_lport": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "trap_v1_rport": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "trap_v2c_status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "trap_v2c_lport": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "trap_v2c_rport": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "events": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "cpu-high"},
                {"value": "mem-low"},
                {"value": "log-full"},
                {"value": "intf-ip"},
                {"value": "vpn-tun-up"},
                {"value": "vpn-tun-down"},
                {"value": "ha-switch"},
                {"value": "ha-hb-failure"},
                {"value": "ips-signature"},
                {"value": "ips-anomaly"},
                {"value": "av-virus"},
                {"value": "av-oversize"},
                {"value": "av-pattern"},
                {"value": "av-fragmented"},
                {"value": "fm-if-change"},
                {"value": "fm-conf-change"},
                {"value": "bgp-established"},
                {"value": "bgp-backward-transition"},
                {"value": "ha-member-up"},
                {"value": "ha-member-down"},
                {"value": "ent-conf-change"},
                {"value": "av-conserve"},
                {"value": "av-bypass"},
                {"value": "av-oversize-passed"},
                {"value": "av-oversize-blocked"},
                {"value": "ips-pkg-update"},
                {"value": "ips-fail-open"},
                {"value": "faz-disconnect"},
                {"value": "faz", "v_range": [["v7.4.1", ""]]},
                {"value": "wc-ap-up"},
                {"value": "wc-ap-down"},
                {"value": "fswctl-session-up"},
                {"value": "fswctl-session-down"},
                {"value": "load-balance-real-server-down"},
                {"value": "device-new"},
                {"value": "per-cpu-high"},
                {"value": "dhcp", "v_range": [["v6.4.0", ""]]},
                {
                    "value": "pool-usage",
                    "v_range": [["v7.0.6", "v7.0.12"], ["v7.2.1", ""]],
                },
                {"value": "ospf-nbr-state-change", "v_range": [["v7.0.0", ""]]},
                {"value": "ospf-virtnbr-state-change", "v_range": [["v7.0.0", ""]]},
                {"value": "temperature-high"},
                {"value": "voltage-alert"},
                {"value": "power-supply", "v_range": [["v7.4.2", ""]]},
                {"value": "fan-failure"},
                {"value": "power-supply-failure", "v_range": [["v6.0.0", "v7.4.1"]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "mib_view": {"v_range": [["v7.2.0", ""]], "type": "string"},
        "vdoms": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.2.0", ""]],
        },
    },
    "v_range": [["v6.0.0", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "id"
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
        "state": {"required": True, "type": "str", "choices": ["present", "absent"]},
        "system_snmp_community": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_snmp_community"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_snmp_community"]["options"][attribute_name][
                "required"
            ] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)
    check_legacy_fortiosapi(module)

    is_error = False
    has_changed = False
    result = None
    diff = None

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if "access_token" in module.params:
            connection.set_custom_option("access_token", module.params["access_token"])

        if "enable_log" in module.params:
            connection.set_custom_option("enable_log", module.params["enable_log"])
        else:
            connection.set_custom_option("enable_log", False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(
            fos, versioned_schema, "system_snmp_community"
        )

        is_error, has_changed, result, diff = fortios_system_snmp(
            module.params, fos, module.check_mode
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
