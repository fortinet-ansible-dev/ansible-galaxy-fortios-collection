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
module: fortios_router_bfd
short_description: Configure BFD in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify router feature and bfd category.
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

    router_bfd:
        description:
            - Configure BFD.
        default: null
        type: dict
        suboptions:
            multihop_template:
                description:
                    - BFD multi-hop template table.
                type: list
                elements: dict
                suboptions:
                    auth_mode:
                        description:
                            - Authentication mode.
                        type: str
                        choices:
                            - 'none'
                            - 'md5'
                    bfd_desired_min_tx:
                        description:
                            - BFD desired minimal transmit interval (milliseconds).
                        type: int
                    bfd_detect_mult:
                        description:
                            - BFD detection multiplier.
                        type: int
                    bfd_required_min_rx:
                        description:
                            - BFD required minimal receive interval (milliseconds).
                        type: int
                    dst:
                        description:
                            - Destination prefix.
                        type: str
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    md5_key:
                        description:
                            - MD5 key of key ID 1.
                        type: str
                    src:
                        description:
                            - Source prefix.
                        type: str
            neighbor:
                description:
                    - Neighbor.
                type: list
                elements: dict
                suboptions:
                    interface:
                        description:
                            - Interface name. Source system.interface.name.
                        type: str
                    ip:
                        description:
                            - IPv4 address of the BFD neighbor.
                        required: true
                        type: str
"""

EXAMPLES = """
- name: Configure BFD.
  fortinet.fortios.fortios_router_bfd:
      vdom: "{{ vdom }}"
      router_bfd:
          multihop_template:
              -
                  auth_mode: "none"
                  bfd_desired_min_tx: "250"
                  bfd_detect_mult: "3"
                  bfd_required_min_rx: "250"
                  dst: "<your_own_value>"
                  id: "9"
                  md5_key: "<your_own_value>"
                  src: "<your_own_value>"
          neighbor:
              -
                  interface: "<your_own_value> (source system.interface.name)"
                  ip: "<your_own_value>"
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


def filter_router_bfd_data(json):
    option_list = ["multihop_template", "neighbor"]

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


def router_bfd(data, fos):
    state = None
    vdom = data["vdom"]
    router_bfd_data = data["router_bfd"]

    filtered_data = filter_router_bfd_data(router_bfd_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # pass post processed data to member operations
    data_copy = data.copy()
    data_copy["router_bfd"] = converted_data
    fos.do_member_operation(
        "router",
        "bfd",
        data_copy,
    )

    return fos.set("router", "bfd", data=converted_data, vdom=vdom)


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
    if data["router_bfd"]:
        resp = router_bfd(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("router_bfd"))

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
        "neighbor": {
            "type": "list",
            "elements": "dict",
            "children": {
                "ip": {"v_range": [["v6.0.0", ""]], "type": "string", "required": True},
                "interface": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "multihop_template": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v7.0.6", ""]],
                    "type": "integer",
                    "required": True,
                },
                "src": {"v_range": [["v7.0.6", ""]], "type": "string"},
                "dst": {"v_range": [["v7.0.6", ""]], "type": "string"},
                "bfd_desired_min_tx": {"v_range": [["v7.0.6", ""]], "type": "integer"},
                "bfd_required_min_rx": {"v_range": [["v7.0.6", ""]], "type": "integer"},
                "bfd_detect_mult": {"v_range": [["v7.0.6", ""]], "type": "integer"},
                "auth_mode": {
                    "v_range": [["v7.0.6", ""]],
                    "type": "string",
                    "options": [{"value": "none"}, {"value": "md5"}],
                },
                "md5_key": {"v_range": [["v7.0.6", ""]], "type": "string"},
            },
            "v_range": [["v7.0.6", ""]],
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
        "router_bfd": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["router_bfd"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["router_bfd"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "router_bfd"
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
