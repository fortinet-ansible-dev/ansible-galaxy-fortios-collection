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
module: fortios_switch_controller_system
short_description: Configure system-wide switch controller settings in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify switch_controller feature and system category.
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

    switch_controller_system:
        description:
            - Configure system-wide switch controller settings.
        default: null
        type: dict
        suboptions:
            caputp_echo_interval:
                description:
                    - Echo interval for the caputp echo requests from swtp.
                type: int
            caputp_max_retransmit:
                description:
                    - Maximum retransmission count for the caputp tunnel packets.
                type: int
            data_sync_interval:
                description:
                    - Time interval between collection of switch data (30 - 1800 sec).
                type: int
            dynamic_periodic_interval:
                description:
                    - Periodic time interval to run Dynamic port policy engine (5 - 180 sec).
                type: int
            iot_holdoff:
                description:
                    - MAC entry"s creation time. Time must be greater than this value for an entry to be created (0 - 10080 mins).
                type: int
            iot_mac_idle:
                description:
                    - MAC entry"s idle time. MAC entry is removed after this value (0 - 10080 mins).
                type: int
            iot_scan_interval:
                description:
                    - IoT scan interval (2 - 10080 mins).
                type: int
            iot_weight_threshold:
                description:
                    - MAC entry"s confidence value. Value is re-queried when below this value .
                type: int
            nac_periodic_interval:
                description:
                    - Periodic time interval to run NAC engine (5 - 180 sec).
                type: int
            parallel_process:
                description:
                    - Maximum number of parallel processes.
                type: int
            parallel_process_override:
                description:
                    - Enable/disable parallel process override.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            tunnel_mode:
                description:
                    - Compatible/strict tunnel mode.
                type: str
                choices:
                    - 'compatible'
                    - 'moderate'
                    - 'strict'
"""

EXAMPLES = """
- name: Configure system-wide switch controller settings.
  fortinet.fortios.fortios_switch_controller_system:
      vdom: "{{ vdom }}"
      switch_controller_system:
          caputp_echo_interval: "30"
          caputp_max_retransmit: "5"
          data_sync_interval: "60"
          dynamic_periodic_interval: "60"
          iot_holdoff: "5"
          iot_mac_idle: "1440"
          iot_scan_interval: "60"
          iot_weight_threshold: "1"
          nac_periodic_interval: "60"
          parallel_process: "1"
          parallel_process_override: "disable"
          tunnel_mode: "compatible"
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


def filter_switch_controller_system_data(json):
    option_list = [
        "caputp_echo_interval",
        "caputp_max_retransmit",
        "data_sync_interval",
        "dynamic_periodic_interval",
        "iot_holdoff",
        "iot_mac_idle",
        "iot_scan_interval",
        "iot_weight_threshold",
        "nac_periodic_interval",
        "parallel_process",
        "parallel_process_override",
        "tunnel_mode",
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


def switch_controller_system(data, fos):
    state = None
    vdom = data["vdom"]
    switch_controller_system_data = data["switch_controller_system"]
    filtered_data = filter_switch_controller_system_data(switch_controller_system_data)
    converted_data = underscore_to_hyphen(filtered_data)

    return fos.set("switch-controller", "system", data=converted_data, vdom=vdom)


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


def fortios_switch_controller(data, fos):
    fos.do_member_operation("switch-controller", "system")
    if data["switch_controller_system"]:
        resp = switch_controller_system(data, fos)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("switch_controller_system")
        )

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
        "parallel_process_override": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "parallel_process": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "data_sync_interval": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "iot_weight_threshold": {"v_range": [["v6.4.0", ""]], "type": "integer"},
        "iot_scan_interval": {"v_range": [["v6.4.0", ""]], "type": "integer"},
        "iot_holdoff": {"v_range": [["v6.4.0", ""]], "type": "integer"},
        "iot_mac_idle": {"v_range": [["v6.4.0", ""]], "type": "integer"},
        "nac_periodic_interval": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "dynamic_periodic_interval": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "tunnel_mode": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "compatible"},
                {"value": "moderate", "v_range": [["v7.4.2", ""]]},
                {"value": "strict"},
            ],
        },
        "caputp_echo_interval": {"v_range": [["v7.4.0", ""]], "type": "integer"},
        "caputp_max_retransmit": {"v_range": [["v7.4.0", ""]], "type": "integer"},
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
        "switch_controller_system": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["switch_controller_system"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["switch_controller_system"]["options"][attribute_name][
                "required"
            ] = True

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
            fos, versioned_schema, "switch_controller_system"
        )

        is_error, has_changed, result, diff = fortios_switch_controller(
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
