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
module: fortios_system_pcp_server
short_description: Configure PCP server information in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and pcp_server category.
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

    system_pcp_server:
        description:
            - Configure PCP server information.
        default: null
        type: dict
        suboptions:
            pools:
                description:
                    - Configure PCP pools.
                type: list
                elements: dict
                suboptions:
                    allow_opcode:
                        description:
                            - Allowed PCP opcode.
                        type: list
                        elements: str
                        choices:
                            - 'map'
                            - 'peer'
                            - 'announce'
                    announcement_count:
                        description:
                            - Number of multicast announcements.
                        type: int
                    arp_reply:
                        description:
                            - Enable to respond to ARP requests for external IP .
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    client_mapping_limit:
                        description:
                            - Mapping limit per client (0 - 65535).
                        type: int
                    client_subnet:
                        description:
                            - Subnets from which PCP requests are accepted.
                        type: list
                        elements: dict
                        suboptions:
                            subnet:
                                description:
                                    - Client subnets.
                                required: true
                                type: str
                    description:
                        description:
                            - Description.
                        type: str
                    ext_intf:
                        description:
                            - External interface name. Source system.interface.name.
                        type: str
                    extip:
                        description:
                            - IP address or address range on the external interface that you want to map to an address on the internal network.
                        type: str
                    extport:
                        description:
                            - Incoming port number range that you want to map to a port number on the internal network.
                        type: str
                    id:
                        description:
                            - ID.
                        type: int
                    intl_intf:
                        description:
                            - Internal interface name.
                        type: list
                        elements: dict
                        suboptions:
                            interface_name:
                                description:
                                    - Interface name. Source system.interface.name.
                                required: true
                                type: str
                    mapping_filter_limit:
                        description:
                            - Filter limit per mapping (0 - 5).
                        type: int
                    maximal_lifetime:
                        description:
                            - Maximal lifetime of a PCP mapping in seconds (3600 - 604800).
                        type: int
                    minimal_lifetime:
                        description:
                            - Minimal lifetime of a PCP mapping in seconds (60 - 300).
                        type: int
                    multicast_announcement:
                        description:
                            - Enable/disable multicast announcements.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    name:
                        description:
                            - PCP pool name.
                        required: true
                        type: str
                    recycle_delay:
                        description:
                            - Minimum delay (in seconds) the PCP Server will wait before recycling mappings that have expired (0 - 3600).
                        type: int
                    third_party:
                        description:
                            - Allow/disallow third party option.
                        type: str
                        choices:
                            - 'allow'
                            - 'disallow'
                    third_party_subnet:
                        description:
                            - Subnets from which third party requests are accepted.
                        type: list
                        elements: dict
                        suboptions:
                            subnet:
                                description:
                                    - Third party subnets.
                                required: true
                                type: str
            status:
                description:
                    - Enable/disable PCP server.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure PCP server information.
  fortinet.fortios.fortios_system_pcp_server:
      vdom: "{{ vdom }}"
      system_pcp_server:
          pools:
              -
                  allow_opcode: "map"
                  announcement_count: "3"
                  arp_reply: "disable"
                  client_mapping_limit: "0"
                  client_subnet:
                      -
                          subnet: "<your_own_value>"
                  description: "<your_own_value>"
                  ext_intf: "<your_own_value> (source system.interface.name)"
                  extip: "<your_own_value>"
                  extport: "<your_own_value>"
                  id: "14"
                  intl_intf:
                      -
                          interface_name: "<your_own_value> (source system.interface.name)"
                  mapping_filter_limit: "1"
                  maximal_lifetime: "86400"
                  minimal_lifetime: "120"
                  multicast_announcement: "enable"
                  name: "default_name_21"
                  recycle_delay: "0"
                  third_party: "allow"
                  third_party_subnet:
                      -
                          subnet: "<your_own_value>"
          status: "enable"
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


def filter_system_pcp_server_data(json):
    option_list = ["pools", "status"]

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
        ["pools", "allow_opcode"],
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


def system_pcp_server(data, fos):
    state = None
    vdom = data["vdom"]
    system_pcp_server_data = data["system_pcp_server"]
    system_pcp_server_data = flatten_multilists_attributes(system_pcp_server_data)
    filtered_data = filter_system_pcp_server_data(system_pcp_server_data)
    converted_data = underscore_to_hyphen(filtered_data)

    return fos.set("system", "pcp-server", data=converted_data, vdom=vdom)


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
    fos.do_member_operation("system", "pcp-server")
    if data["system_pcp_server"]:
        resp = system_pcp_server(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_pcp_server"))

    return (
        not is_successful_status(resp),
        is_successful_status(resp)
        and (resp["revision_changed"] if "revision_changed" in resp else True),
        resp,
        {},
    )


versioned_schema = {
    "v_range": [["v7.4.0", ""]],
    "type": "dict",
    "children": {
        "status": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "pools": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "description": {"v_range": [["v7.4.0", ""]], "type": "string"},
                "id": {"v_range": [["v7.4.0", ""]], "type": "integer"},
                "client_subnet": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "subnet": {
                            "v_range": [["v7.4.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.4.0", ""]],
                },
                "ext_intf": {"v_range": [["v7.4.0", ""]], "type": "string"},
                "arp_reply": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "extip": {"v_range": [["v7.4.0", ""]], "type": "string"},
                "extport": {"v_range": [["v7.4.0", ""]], "type": "string"},
                "minimal_lifetime": {"v_range": [["v7.4.0", ""]], "type": "integer"},
                "maximal_lifetime": {"v_range": [["v7.4.0", ""]], "type": "integer"},
                "client_mapping_limit": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "integer",
                },
                "mapping_filter_limit": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "integer",
                },
                "allow_opcode": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "map"},
                        {"value": "peer"},
                        {"value": "announce"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "third_party": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "allow"}, {"value": "disallow"}],
                },
                "third_party_subnet": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "subnet": {
                            "v_range": [["v7.4.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.4.0", ""]],
                },
                "multicast_announcement": {
                    "v_range": [["v7.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "announcement_count": {"v_range": [["v7.4.0", ""]], "type": "integer"},
                "intl_intf": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "interface_name": {
                            "v_range": [["v7.4.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.4.0", ""]],
                },
                "recycle_delay": {"v_range": [["v7.4.0", ""]], "type": "integer"},
            },
            "v_range": [["v7.4.0", ""]],
        },
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
        "system_pcp_server": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_pcp_server"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_pcp_server"]["options"][attribute_name]["required"] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=False)
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
            fos, versioned_schema, "system_pcp_server"
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
