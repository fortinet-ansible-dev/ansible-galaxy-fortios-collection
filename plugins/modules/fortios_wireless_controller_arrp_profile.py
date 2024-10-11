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
module: fortios_wireless_controller_arrp_profile
short_description: Configure WiFi Automatic Radio Resource Provisioning (ARRP) profiles in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify wireless_controller feature and arrp_profile category.
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
    wireless_controller_arrp_profile:
        description:
            - Configure WiFi Automatic Radio Resource Provisioning (ARRP) profiles.
        default: null
        type: dict
        suboptions:
            comment:
                description:
                    - Comment.
                type: str
            darrp_optimize:
                description:
                    - Time for running Distributed Automatic Radio Resource Provisioning (DARRP) optimizations (0 - 86400 sec).
                type: int
            darrp_optimize_schedules:
                description:
                    - Firewall schedules for DARRP running time. DARRP will run periodically based on darrp-optimize within the schedules. Separate multiple
                       schedule names with a space.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Schedule name. Source firewall.schedule.group.name firewall.schedule.recurring.name firewall.schedule.onetime.name.
                        required: true
                        type: str
            include_dfs_channel:
                description:
                    - Enable/disable use of DFS channel in DARRP channel selection phase 1 .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
                    - 'yes'
                    - 'no'
            include_weather_channel:
                description:
                    - Enable/disable use of weather channel in DARRP channel selection phase 1 .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
                    - 'yes'
                    - 'no'
            monitor_period:
                description:
                    - Period in seconds to measure average transmit retries and receive errors .
                type: int
            name:
                description:
                    - WiFi ARRP profile name.
                required: true
                type: str
            override_darrp_optimize:
                description:
                    - Enable to override setting darrp-optimize and darrp-optimize-schedules .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            selection_period:
                description:
                    - Period in seconds to measure average channel load, noise floor, spectral RSSI .
                type: int
            threshold_ap:
                description:
                    - Threshold to reject channel in DARRP channel selection phase 1 due to surrounding APs (0 - 500).
                type: int
            threshold_channel_load:
                description:
                    - Threshold in percentage to reject channel in DARRP channel selection phase 1 due to channel load (0 - 100).
                type: int
            threshold_noise_floor:
                description:
                    - Threshold in dBm to reject channel in DARRP channel selection phase 1 due to noise floor (-95 to -20).
                type: str
            threshold_rx_errors:
                description:
                    - Threshold in percentage for receive errors to trigger channel reselection in DARRP monitor stage (0 - 100).
                type: int
            threshold_spectral_rssi:
                description:
                    - Threshold in dBm to reject channel in DARRP channel selection phase 1 due to spectral RSSI (-95 to -20).
                type: str
            threshold_tx_retries:
                description:
                    - Threshold in percentage for transmit retries to trigger channel reselection in DARRP monitor stage (0 - 1000).
                type: int
            weight_channel_load:
                description:
                    - Weight in DARRP channel score calculation for channel load (0 - 2000).
                type: int
            weight_dfs_channel:
                description:
                    - Weight in DARRP channel score calculation for DFS channel (0 - 2000).
                type: int
            weight_managed_ap:
                description:
                    - Weight in DARRP channel score calculation for managed APs (0 - 2000).
                type: int
            weight_noise_floor:
                description:
                    - Weight in DARRP channel score calculation for noise floor (0 - 2000).
                type: int
            weight_rogue_ap:
                description:
                    - Weight in DARRP channel score calculation for rogue APs (0 - 2000).
                type: int
            weight_spectral_rssi:
                description:
                    - Weight in DARRP channel score calculation for spectral RSSI (0 - 2000).
                type: int
            weight_weather_channel:
                description:
                    - Weight in DARRP channel score calculation for weather channel (0 - 2000).
                type: int
"""

EXAMPLES = """
- name: Configure WiFi Automatic Radio Resource Provisioning (ARRP) profiles.
  fortinet.fortios.fortios_wireless_controller_arrp_profile:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      wireless_controller_arrp_profile:
          comment: "Comment."
          darrp_optimize: "86400"
          darrp_optimize_schedules:
              -
                  name: "default_name_6 (source firewall.schedule.group.name firewall.schedule.recurring.name firewall.schedule.onetime.name)"
          include_dfs_channel: "enable"
          include_weather_channel: "enable"
          monitor_period: "300"
          name: "default_name_10"
          override_darrp_optimize: "enable"
          selection_period: "3600"
          threshold_ap: "250"
          threshold_channel_load: "60"
          threshold_noise_floor: "<your_own_value>"
          threshold_rx_errors: "50"
          threshold_spectral_rssi: "<your_own_value>"
          threshold_tx_retries: "300"
          weight_channel_load: "20"
          weight_dfs_channel: "500"
          weight_managed_ap: "50"
          weight_noise_floor: "40"
          weight_rogue_ap: "10"
          weight_spectral_rssi: "40"
          weight_weather_channel: "1000"
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


def filter_wireless_controller_arrp_profile_data(json):
    option_list = [
        "comment",
        "darrp_optimize",
        "darrp_optimize_schedules",
        "include_dfs_channel",
        "include_weather_channel",
        "monitor_period",
        "name",
        "override_darrp_optimize",
        "selection_period",
        "threshold_ap",
        "threshold_channel_load",
        "threshold_noise_floor",
        "threshold_rx_errors",
        "threshold_spectral_rssi",
        "threshold_tx_retries",
        "weight_channel_load",
        "weight_dfs_channel",
        "weight_managed_ap",
        "weight_noise_floor",
        "weight_rogue_ap",
        "weight_spectral_rssi",
        "weight_weather_channel",
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


def wireless_controller_arrp_profile(data, fos, check_mode=False):
    state = None
    vdom = data["vdom"]

    state = data["state"]

    wireless_controller_arrp_profile_data = data["wireless_controller_arrp_profile"]

    filtered_data = filter_wireless_controller_arrp_profile_data(
        wireless_controller_arrp_profile_data
    )
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey(
            "wireless-controller", "arrp-profile", filtered_data, vdom=vdom
        )
        current_data = fos.get(
            "wireless-controller", "arrp-profile", vdom=vdom, mkey=mkey
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
    data_copy["wireless_controller_arrp_profile"] = converted_data
    fos.do_member_operation(
        "wireless-controller",
        "arrp-profile",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set(
            "wireless-controller", "arrp-profile", data=converted_data, vdom=vdom
        )

    elif state == "absent":
        return fos.delete(
            "wireless-controller",
            "arrp-profile",
            mkey=converted_data["name"],
            vdom=vdom,
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
    if data["wireless_controller_arrp_profile"]:
        resp = wireless_controller_arrp_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("wireless_controller_arrp_profile")
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
        "name": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
            "required": True,
        },
        "comment": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
        },
        "selection_period": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "integer",
        },
        "monitor_period": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "integer",
        },
        "weight_managed_ap": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "integer",
        },
        "weight_rogue_ap": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "integer",
        },
        "weight_noise_floor": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "integer",
        },
        "weight_channel_load": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "integer",
        },
        "weight_spectral_rssi": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "integer",
        },
        "weight_weather_channel": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "integer",
        },
        "weight_dfs_channel": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "integer",
        },
        "threshold_ap": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "integer",
        },
        "threshold_noise_floor": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
        },
        "threshold_channel_load": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "integer",
        },
        "threshold_spectral_rssi": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
        },
        "threshold_tx_retries": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "integer",
        },
        "threshold_rx_errors": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "integer",
        },
        "include_weather_channel": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
            "options": [
                {"value": "enable", "v_range": [["v6.4.4", ""]]},
                {"value": "disable", "v_range": [["v6.4.4", ""]]},
                {"value": "yes", "v_range": [["v6.4.0", "v6.4.0"]]},
                {"value": "no", "v_range": [["v6.4.0", "v6.4.0"]]},
            ],
        },
        "include_dfs_channel": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
            "options": [
                {"value": "enable", "v_range": [["v6.4.4", ""]]},
                {"value": "disable", "v_range": [["v6.4.4", ""]]},
                {"value": "yes", "v_range": [["v6.4.0", "v6.4.0"]]},
                {"value": "no", "v_range": [["v6.4.0", "v6.4.0"]]},
            ],
        },
        "override_darrp_optimize": {
            "v_range": [["v7.0.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "darrp_optimize": {"v_range": [["v7.0.4", ""]], "type": "integer"},
        "darrp_optimize_schedules": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.0.4", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.0.4", ""]],
        },
    },
    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
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
        "wireless_controller_arrp_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["wireless_controller_arrp_profile"]["options"][
            attribute_name
        ] = module_spec["options"][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["wireless_controller_arrp_profile"]["options"][attribute_name][
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
            fos, versioned_schema, "wireless_controller_arrp_profile"
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
