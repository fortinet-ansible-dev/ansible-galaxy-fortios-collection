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
module: fortios_wireless_controller_ble_profile
short_description: Configure Bluetooth Low Energy profile in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify wireless_controller feature and ble_profile category.
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
    wireless_controller_ble_profile:
        description:
            - Configure Bluetooth Low Energy profile.
        default: null
        type: dict
        suboptions:
            advertising:
                description:
                    - Advertising type.
                type: list
                elements: str
                choices:
                    - 'ibeacon'
                    - 'eddystone-uid'
                    - 'eddystone-url'
            beacon_interval:
                description:
                    - Beacon interval .
                type: int
            ble_scanning:
                description:
                    - Enable/disable Bluetooth Low Energy (BLE) scanning.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            comment:
                description:
                    - Comment.
                type: str
            eddystone_instance:
                description:
                    - Eddystone instance ID.
                type: str
            eddystone_namespace:
                description:
                    - Eddystone namespace ID.
                type: str
            eddystone_url:
                description:
                    - Eddystone URL.
                type: str
            eddystone_url_encode_hex:
                description:
                    - Eddystone encoded URL hexadecimal string
                type: str
            ibeacon_uuid:
                description:
                    - Universally Unique Identifier (UUID; automatically assigned but can be manually reset).
                type: str
            major_id:
                description:
                    - Major ID.
                type: int
            minor_id:
                description:
                    - Minor ID.
                type: int
            name:
                description:
                    - Bluetooth Low Energy profile name.
                required: true
                type: str
            scan_interval:
                description:
                    - Scan Interval .
                type: int
            scan_period:
                description:
                    - Scan Period .
                type: int
            scan_threshold:
                description:
                    - Minimum signal level/threshold in dBm required for the AP to report detected BLE device (-95 to -20).
                type: str
            scan_time:
                description:
                    - Scan Time .
                type: int
            scan_type:
                description:
                    - Scan Type .
                type: str
                choices:
                    - 'active'
                    - 'passive'
            scan_window:
                description:
                    - Scan Windows .
                type: int
            txpower:
                description:
                    - Transmit power level .
                type: str
                choices:
                    - '0'
                    - '1'
                    - '2'
                    - '3'
                    - '4'
                    - '5'
                    - '6'
                    - '7'
                    - '8'
                    - '9'
                    - '10'
                    - '11'
                    - '12'
"""

EXAMPLES = """
- name: Configure Bluetooth Low Energy profile.
  fortinet.fortios.fortios_wireless_controller_ble_profile:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      wireless_controller_ble_profile:
          advertising: "ibeacon"
          beacon_interval: "100"
          ble_scanning: "enable"
          comment: "Comment."
          eddystone_instance: "<your_own_value>"
          eddystone_namespace: "<your_own_value>"
          eddystone_url: "<your_own_value>"
          eddystone_url_encode_hex: "<your_own_value>"
          ibeacon_uuid: "<your_own_value>"
          major_id: "1000"
          minor_id: "2000"
          name: "default_name_14"
          scan_interval: "50"
          scan_period: "4000"
          scan_threshold: "<your_own_value>"
          scan_time: "1000"
          scan_type: "active"
          scan_window: "50"
          txpower: "0"
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


def filter_wireless_controller_ble_profile_data(json):
    option_list = [
        "advertising",
        "beacon_interval",
        "ble_scanning",
        "comment",
        "eddystone_instance",
        "eddystone_namespace",
        "eddystone_url",
        "eddystone_url_encode_hex",
        "ibeacon_uuid",
        "major_id",
        "minor_id",
        "name",
        "scan_interval",
        "scan_period",
        "scan_threshold",
        "scan_time",
        "scan_type",
        "scan_window",
        "txpower",
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
        ["advertising"],
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


def wireless_controller_ble_profile(data, fos, check_mode=False):
    state = None
    vdom = data["vdom"]

    state = data["state"]

    wireless_controller_ble_profile_data = data["wireless_controller_ble_profile"]
    wireless_controller_ble_profile_data = flatten_multilists_attributes(
        wireless_controller_ble_profile_data
    )
    filtered_data = filter_wireless_controller_ble_profile_data(
        wireless_controller_ble_profile_data
    )
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey(
            "wireless-controller", "ble-profile", filtered_data, vdom=vdom
        )
        current_data = fos.get(
            "wireless-controller", "ble-profile", vdom=vdom, mkey=mkey
        )
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
        return fos.set(
            "wireless-controller", "ble-profile", data=converted_data, vdom=vdom
        )

    elif state == "absent":
        return fos.delete(
            "wireless-controller", "ble-profile", mkey=converted_data["name"], vdom=vdom
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


def fortios_wireless_controller(data, fos, check_mode):
    fos.do_member_operation("wireless-controller", "ble-profile")
    if data["wireless_controller_ble_profile"]:
        resp = wireless_controller_ble_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("wireless_controller_ble_profile")
        )
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
        "comment": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "advertising": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "ibeacon"},
                {"value": "eddystone-uid"},
                {"value": "eddystone-url"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "ibeacon_uuid": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "major_id": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "minor_id": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "eddystone_namespace": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "eddystone_instance": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "eddystone_url": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "txpower": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "0"},
                {"value": "1"},
                {"value": "2"},
                {"value": "3"},
                {"value": "4"},
                {"value": "5"},
                {"value": "6"},
                {"value": "7"},
                {"value": "8"},
                {"value": "9"},
                {"value": "10"},
                {"value": "11"},
                {"value": "12"},
            ],
        },
        "beacon_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ble_scanning": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "scan_type": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [{"value": "active"}, {"value": "passive"}],
        },
        "scan_threshold": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "scan_period": {"v_range": [["v7.4.1", ""]], "type": "integer"},
        "scan_time": {"v_range": [["v7.4.1", ""]], "type": "integer"},
        "scan_interval": {"v_range": [["v7.4.1", ""]], "type": "integer"},
        "scan_window": {"v_range": [["v7.4.1", ""]], "type": "integer"},
        "eddystone_url_encode_hex": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "string",
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
        "wireless_controller_ble_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["wireless_controller_ble_profile"]["options"][
            attribute_name
        ] = module_spec["options"][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["wireless_controller_ble_profile"]["options"][attribute_name][
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
            fos, versioned_schema, "wireless_controller_ble_profile"
        )

        is_error, has_changed, result, diff = fortios_wireless_controller(
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
