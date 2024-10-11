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
module: fortios_router_setting
short_description: Configure router settings in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify router feature and setting category.
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

    router_setting:
        description:
            - Configure router settings.
        default: null
        type: dict
        suboptions:
            bgp_debug_flags:
                description:
                    - bgp_debug_flags
                type: str
            hostname:
                description:
                    - Hostname for this virtual domain router.
                type: str
            igmp_debug_flags:
                description:
                    - igmp_debug_flags
                type: str
            imi_debug_flags:
                description:
                    - imi_debug_flags
                type: str
            isis_debug_flags:
                description:
                    - isis_debug_flags
                type: str
            kernel_route_distance:
                description:
                    - Administrative distance for routes learned from kernel (0 - 255).
                type: int
            ospf_debug_events_flags:
                description:
                    - ospf_debug_events_flags
                type: str
            ospf_debug_ifsm_flags:
                description:
                    - ospf_debug_ifsm_flags
                type: str
            ospf_debug_lsa_flags:
                description:
                    - ospf_debug_lsa_flags
                type: str
            ospf_debug_nfsm_flags:
                description:
                    - ospf_debug_nfsm_flags
                type: str
            ospf_debug_nsm_flags:
                description:
                    - ospf_debug_nsm_flags
                type: str
            ospf_debug_packet_flags:
                description:
                    - ospf_debug_packet_flags
                type: str
            ospf_debug_route_flags:
                description:
                    - ospf_debug_route_flags
                type: str
            ospf6_debug_events_flags:
                description:
                    - ospf6_debug_events_flags
                type: str
            ospf6_debug_ifsm_flags:
                description:
                    - ospf6_debug_ifsm_flags
                type: str
            ospf6_debug_lsa_flags:
                description:
                    - ospf6_debug_lsa_flags
                type: str
            ospf6_debug_nfsm_flags:
                description:
                    - ospf6_debug_nfsm_flags
                type: str
            ospf6_debug_nsm_flags:
                description:
                    - ospf6_debug_nsm_flags
                type: str
            ospf6_debug_packet_flags:
                description:
                    - ospf6_debug_packet_flags
                type: str
            ospf6_debug_route_flags:
                description:
                    - ospf6_debug_route_flags
                type: str
            pimdm_debug_flags:
                description:
                    - pimdm_debug_flags
                type: str
            pimsm_debug_joinprune_flags:
                description:
                    - pimsm_debug_joinprune_flags
                type: str
            pimsm_debug_simple_flags:
                description:
                    - pimsm_debug_simple_flags
                type: str
            pimsm_debug_timer_flags:
                description:
                    - pimsm_debug_timer_flags
                type: str
            rip_debug_flags:
                description:
                    - rip_debug_flags
                type: str
            ripng_debug_flags:
                description:
                    - ripng_debug_flags
                type: str
            show_filter:
                description:
                    - Prefix-list as filter for showing routes. Source router.prefix-list.name.
                type: str
"""

EXAMPLES = """
- name: Configure router settings.
  fortinet.fortios.fortios_router_setting:
      vdom: "{{ vdom }}"
      router_setting:
          bgp_debug_flags: "<your_own_value>"
          hostname: "myhostname"
          igmp_debug_flags: "<your_own_value>"
          imi_debug_flags: "<your_own_value>"
          isis_debug_flags: "<your_own_value>"
          kernel_route_distance: "255"
          ospf_debug_events_flags: "<your_own_value>"
          ospf_debug_ifsm_flags: "<your_own_value>"
          ospf_debug_lsa_flags: "<your_own_value>"
          ospf_debug_nfsm_flags: "<your_own_value>"
          ospf_debug_nsm_flags: "<your_own_value>"
          ospf_debug_packet_flags: "<your_own_value>"
          ospf_debug_route_flags: "<your_own_value>"
          ospf6_debug_events_flags: "<your_own_value>"
          ospf6_debug_ifsm_flags: "<your_own_value>"
          ospf6_debug_lsa_flags: "<your_own_value>"
          ospf6_debug_nfsm_flags: "<your_own_value>"
          ospf6_debug_nsm_flags: "<your_own_value>"
          ospf6_debug_packet_flags: "<your_own_value>"
          ospf6_debug_route_flags: "<your_own_value>"
          pimdm_debug_flags: "<your_own_value>"
          pimsm_debug_joinprune_flags: "<your_own_value>"
          pimsm_debug_simple_flags: "<your_own_value>"
          pimsm_debug_timer_flags: "<your_own_value>"
          rip_debug_flags: "<your_own_value>"
          ripng_debug_flags: "<your_own_value>"
          show_filter: "<your_own_value> (source router.prefix-list.name)"
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


def filter_router_setting_data(json):
    option_list = [
        "bgp_debug_flags",
        "hostname",
        "igmp_debug_flags",
        "imi_debug_flags",
        "isis_debug_flags",
        "kernel_route_distance",
        "ospf_debug_events_flags",
        "ospf_debug_ifsm_flags",
        "ospf_debug_lsa_flags",
        "ospf_debug_nfsm_flags",
        "ospf_debug_nsm_flags",
        "ospf_debug_packet_flags",
        "ospf_debug_route_flags",
        "ospf6_debug_events_flags",
        "ospf6_debug_ifsm_flags",
        "ospf6_debug_lsa_flags",
        "ospf6_debug_nfsm_flags",
        "ospf6_debug_nsm_flags",
        "ospf6_debug_packet_flags",
        "ospf6_debug_route_flags",
        "pimdm_debug_flags",
        "pimsm_debug_joinprune_flags",
        "pimsm_debug_simple_flags",
        "pimsm_debug_timer_flags",
        "rip_debug_flags",
        "ripng_debug_flags",
        "show_filter",
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


def router_setting(data, fos):
    state = None
    vdom = data["vdom"]
    router_setting_data = data["router_setting"]

    filtered_data = filter_router_setting_data(router_setting_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # pass post processed data to member operations
    data_copy = data.copy()
    data_copy["router_setting"] = converted_data
    fos.do_member_operation(
        "router",
        "setting",
        data_copy,
    )

    return fos.set("router", "setting", data=converted_data, vdom=vdom)


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
    if data["router_setting"]:
        resp = router_setting(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("router_setting"))

    return (
        not is_successful_status(resp),
        is_successful_status(resp)
        and (resp["revision_changed"] if "revision_changed" in resp else True),
        resp,
        {},
    )


versioned_schema = {
    "v_range": [["v6.0.0", ""]],
    "type": "dict",
    "children": {
        "show_filter": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "hostname": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "kernel_route_distance": {"v_range": [["v7.6.0", ""]], "type": "integer"},
        "ospf_debug_lsa_flags": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "string"},
        "ospf_debug_nfsm_flags": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "string"},
        "ospf_debug_packet_flags": {
            "v_range": [["v6.2.3", "v6.2.3"]],
            "type": "string",
        },
        "ospf_debug_events_flags": {
            "v_range": [["v6.2.3", "v6.2.3"]],
            "type": "string",
        },
        "ospf_debug_route_flags": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "string"},
        "ospf_debug_ifsm_flags": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "string"},
        "ospf_debug_nsm_flags": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "string"},
        "rip_debug_flags": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "string"},
        "bgp_debug_flags": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "string"},
        "igmp_debug_flags": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "string"},
        "pimdm_debug_flags": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "string"},
        "pimsm_debug_simple_flags": {
            "v_range": [["v6.2.3", "v6.2.3"]],
            "type": "string",
        },
        "pimsm_debug_timer_flags": {
            "v_range": [["v6.2.3", "v6.2.3"]],
            "type": "string",
        },
        "pimsm_debug_joinprune_flags": {
            "v_range": [["v6.2.3", "v6.2.3"]],
            "type": "string",
        },
        "imi_debug_flags": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "string"},
        "isis_debug_flags": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "string"},
        "ospf6_debug_lsa_flags": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "string"},
        "ospf6_debug_nfsm_flags": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "string"},
        "ospf6_debug_packet_flags": {
            "v_range": [["v6.2.3", "v6.2.3"]],
            "type": "string",
        },
        "ospf6_debug_events_flags": {
            "v_range": [["v6.2.3", "v6.2.3"]],
            "type": "string",
        },
        "ospf6_debug_route_flags": {
            "v_range": [["v6.2.3", "v6.2.3"]],
            "type": "string",
        },
        "ospf6_debug_ifsm_flags": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "string"},
        "ospf6_debug_nsm_flags": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "string"},
        "ripng_debug_flags": {"v_range": [["v6.2.3", "v6.2.3"]], "type": "string"},
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
        "router_setting": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["router_setting"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["router_setting"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "router_setting"
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
