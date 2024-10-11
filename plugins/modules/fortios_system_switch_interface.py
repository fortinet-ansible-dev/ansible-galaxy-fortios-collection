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
module: fortios_system_switch_interface
short_description: Configure software switch interfaces by grouping physical and WiFi interfaces in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and switch_interface category.
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
    system_switch_interface:
        description:
            - Configure software switch interfaces by grouping physical and WiFi interfaces.
        default: null
        type: dict
        suboptions:
            intra_switch_policy:
                description:
                    - Allow any traffic between switch interfaces or require firewall policies to allow traffic between switch interfaces.
                type: str
                choices:
                    - 'implicit'
                    - 'explicit'
            mac_ttl:
                description:
                    - Duration for which MAC addresses are held in the ARP table (300 - 8640000 sec).
                type: int
            member:
                description:
                    - Names of the interfaces that belong to the virtual switch.
                type: list
                elements: dict
                suboptions:
                    interface_name:
                        description:
                            - Interface name. Source system.interface.name.
                        required: true
                        type: str
            name:
                description:
                    - Interface name (name cannot be in use by any other interfaces, VLANs, or inter-VDOM links).
                required: true
                type: str
            span:
                description:
                    - Enable/disable port spanning. Port spanning echoes traffic received by the software switch to the span destination port.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            span_dest_port:
                description:
                    - SPAN destination port name. All traffic on the SPAN source ports is echoed to the SPAN destination port. Source system.interface.name.
                type: str
            span_direction:
                description:
                    - 'The direction in which the SPAN port operates, either: rx, tx, or both.'
                type: str
                choices:
                    - 'rx'
                    - 'tx'
                    - 'both'
            span_source_port:
                description:
                    - Physical interface name. Port spanning echoes all traffic on the SPAN source ports to the SPAN destination port.
                type: list
                elements: dict
                suboptions:
                    interface_name:
                        description:
                            - Physical interface name. Source system.interface.name.
                        required: true
                        type: str
            type:
                description:
                    - 'Type of switch based on functionality: switch for normal functionality, or hub to duplicate packets to all port members.'
                type: str
                choices:
                    - 'switch'
                    - 'hub'
            vdom:
                description:
                    - VDOM that the software switch belongs to. Source system.vdom.name.
                type: str
"""

EXAMPLES = """
- name: Configure software switch interfaces by grouping physical and WiFi interfaces.
  fortinet.fortios.fortios_system_switch_interface:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      system_switch_interface:
          intra_switch_policy: "implicit"
          mac_ttl: "300"
          member:
              -
                  interface_name: "<your_own_value> (source system.interface.name)"
          name: "default_name_7"
          span: "disable"
          span_dest_port: "<your_own_value> (source system.interface.name)"
          span_direction: "rx"
          span_source_port:
              -
                  interface_name: "<your_own_value> (source system.interface.name)"
          type: "switch"
          vdom: "<your_own_value> (source system.vdom.name)"
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


def filter_system_switch_interface_data(json):
    option_list = [
        "intra_switch_policy",
        "mac_ttl",
        "member",
        "name",
        "span",
        "span_dest_port",
        "span_direction",
        "span_source_port",
        "type",
        "vdom",
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


def system_switch_interface(data, fos, check_mode=False):
    state = None
    vdom = data["vdom"]

    state = data["state"]

    system_switch_interface_data = data["system_switch_interface"]

    filtered_data = filter_system_switch_interface_data(system_switch_interface_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("system", "switch-interface", filtered_data, vdom=vdom)
        current_data = fos.get("system", "switch-interface", vdom=vdom, mkey=mkey)
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
            copied_filtered_data = filtered_data.copy()
            copied_filtered_data.pop(fos.get_mkeyname(None, None), None)

            if is_existed:
                is_same = is_same_comparison(
                    serialize(current_data["results"][0]),
                    serialize(copied_filtered_data),
                )

                current_values = find_current_values(
                    copied_filtered_data, current_data["results"][0]
                )

                return (
                    False,
                    not is_same,
                    filtered_data,
                    {"before": current_values, "after": copied_filtered_data},
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
    # pass post processed data to member operations
    data_copy = data.copy()
    data_copy["system_switch_interface"] = converted_data
    fos.do_member_operation(
        "system",
        "switch-interface",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("system", "switch-interface", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "system", "switch-interface", mkey=converted_data["name"], vdom=vdom
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


def fortios_system(data, fos, check_mode):
    if data["system_switch_interface"]:
        resp = system_switch_interface(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_switch_interface"))
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
        "name": {"v_range": [["v6.0.0", ""]], "type": "string", "required": True},
        "vdom": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "span_dest_port": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "span_source_port": {
            "type": "list",
            "elements": "dict",
            "children": {
                "interface_name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "member": {
            "type": "list",
            "elements": "dict",
            "children": {
                "interface_name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "switch"}, {"value": "hub"}],
        },
        "intra_switch_policy": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "implicit"}, {"value": "explicit"}],
        },
        "mac_ttl": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "integer",
        },
        "span": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "span_direction": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "rx"}, {"value": "tx"}, {"value": "both"}],
        },
    },
    "v_range": [["v6.0.0", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "name"
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
        "system_switch_interface": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_switch_interface"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_switch_interface"]["options"][attribute_name][
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
            fos, versioned_schema, "system_switch_interface"
        )

        is_error, has_changed, result, diff = fortios_system(
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
