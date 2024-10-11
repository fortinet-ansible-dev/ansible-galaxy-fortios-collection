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
module: fortios_system_federated_upgrade
short_description: Coordinate federated upgrades within the Security Fabric in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and federated_upgrade category.
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

    system_federated_upgrade:
        description:
            - Coordinate federated upgrades within the Security Fabric.
        default: null
        type: dict
        suboptions:
            failure_device:
                description:
                    - Serial number of the node to include.
                type: str
            failure_reason:
                description:
                    - Reason for upgrade failure.
                type: str
                choices:
                    - 'none'
                    - 'internal'
                    - 'timeout'
                    - 'device-type-unsupported'
                    - 'download-failed'
                    - 'device-missing'
                    - 'version-unavailable'
                    - 'staging-failed'
                    - 'reboot-failed'
                    - 'device-not-reconnected'
                    - 'node-not-ready'
                    - 'no-final-confirmation'
                    - 'no-confirmation-query'
                    - 'config-error-log-nonempty'
                    - 'csf-tree-not-supported'
                    - 'node-failed'
            ha_reboot_controller:
                description:
                    - Serial number of the FortiGate unit that will control the reboot process for the federated upgrade of the HA cluster.
                type: str
            ignore_signing_errors:
                description:
                    - Allow/reject use of FortiGate firmware images that are unsigned.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            known_ha_members:
                description:
                    - Known members of the HA cluster. If a member is missing at upgrade time, the upgrade will be cancelled.
                type: list
                elements: dict
                suboptions:
                    serial:
                        description:
                            - Serial number of HA member
                        required: true
                        type: str
            next_path_index:
                description:
                    - The index of the next image to upgrade to.
                type: int
            node_list:
                description:
                    - Nodes which will be included in the upgrade.
                type: list
                elements: dict
                suboptions:
                    coordinating_fortigate:
                        description:
                            - Serial number of the FortiGate unit that controls this device.
                        type: str
                    device_type:
                        description:
                            - Fortinet device type.
                        type: str
                        choices:
                            - 'fortigate'
                            - 'fortiswitch'
                            - 'fortiap'
                            - 'fortiextender'
                    maximum_minutes:
                        description:
                            - Maximum number of minutes to allow for immediate upgrade preparation.
                        type: int
                    serial:
                        description:
                            - Serial number of the node to include.
                        required: true
                        type: str
                    setup_time:
                        description:
                            - 'Upgrade preparation start time in UTC (hh:mm yyyy/mm/dd UTC).'
                        type: str
                    time:
                        description:
                            - 'Scheduled upgrade execution time in UTC (hh:mm yyyy/mm/dd UTC).'
                        type: str
                    timing:
                        description:
                            - Run immediately or at a scheduled time.
                        type: str
                        choices:
                            - 'immediate'
                            - 'scheduled'
                    upgrade_path:
                        description:
                            - Fortinet OS image versions to upgrade through in major-minor-patch format, such as 7-0-4.
                        type: str
            source:
                description:
                    - Source that set up the federated upgrade config.
                type: str
                choices:
                    - 'user'
                    - 'auto-firmware-upgrade'
            status:
                description:
                    - Current status of the upgrade.
                type: str
                choices:
                    - 'disabled'
                    - 'initialized'
                    - 'downloading'
                    - 'device-disconnected'
                    - 'ready'
                    - 'coordinating'
                    - 'staging'
                    - 'final-check'
                    - 'upgrade-devices'
                    - 'cancelled'
                    - 'confirmed'
                    - 'done'
                    - 'dry-run-done'
                    - 'failed'
                    - 'download-failed'
            upgrade_id:
                description:
                    - Unique identifier for this upgrade.
                type: int
"""

EXAMPLES = """
- name: Coordinate federated upgrades within the Security Fabric.
  fortinet.fortios.fortios_system_federated_upgrade:
      vdom: "{{ vdom }}"
      system_federated_upgrade:
          failure_device: "<your_own_value>"
          failure_reason: "none"
          ha_reboot_controller: "<your_own_value>"
          ignore_signing_errors: "enable"
          known_ha_members:
              -
                  serial: "<your_own_value>"
          next_path_index: "0"
          node_list:
              -
                  coordinating_fortigate: "<your_own_value>"
                  device_type: "fortigate"
                  maximum_minutes: "15"
                  serial: "<your_own_value>"
                  setup_time: "<your_own_value>"
                  time: "<your_own_value>"
                  timing: "immediate"
                  upgrade_path: "<your_own_value>"
          source: "user"
          status: "disabled"
          upgrade_id: "0"
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


def filter_system_federated_upgrade_data(json):
    option_list = [
        "failure_device",
        "failure_reason",
        "ha_reboot_controller",
        "ignore_signing_errors",
        "known_ha_members",
        "next_path_index",
        "node_list",
        "source",
        "status",
        "upgrade_id",
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


def system_federated_upgrade(data, fos):
    state = None
    vdom = data["vdom"]
    system_federated_upgrade_data = data["system_federated_upgrade"]

    filtered_data = filter_system_federated_upgrade_data(system_federated_upgrade_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # pass post processed data to member operations
    data_copy = data.copy()
    data_copy["system_federated_upgrade"] = converted_data
    fos.do_member_operation(
        "system",
        "federated-upgrade",
        data_copy,
    )

    return fos.set("system", "federated-upgrade", data=converted_data, vdom=vdom)


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
    if data["system_federated_upgrade"]:
        resp = system_federated_upgrade(data, fos)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("system_federated_upgrade")
        )

    return (
        not is_successful_status(resp),
        is_successful_status(resp)
        and (resp["revision_changed"] if "revision_changed" in resp else True),
        resp,
        {},
    )


versioned_schema = {
    "v_range": [["v7.0.0", ""]],
    "type": "dict",
    "children": {
        "status": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "disabled"},
                {"value": "initialized"},
                {"value": "downloading"},
                {"value": "device-disconnected"},
                {"value": "ready"},
                {"value": "coordinating", "v_range": [["v7.2.4", ""]]},
                {"value": "staging"},
                {"value": "final-check", "v_range": [["v7.0.1", ""]]},
                {"value": "upgrade-devices", "v_range": [["v7.0.2", ""]]},
                {"value": "cancelled"},
                {"value": "confirmed"},
                {"value": "done"},
                {"value": "dry-run-done", "v_range": [["v7.6.0", ""]]},
                {"value": "failed"},
                {"value": "download-failed", "v_range": [["v7.0.0", "v7.0.1"]]},
            ],
        },
        "source": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [{"value": "user"}, {"value": "auto-firmware-upgrade"}],
        },
        "failure_reason": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
            "options": [
                {"value": "none"},
                {"value": "internal"},
                {"value": "timeout"},
                {"value": "device-type-unsupported"},
                {"value": "download-failed"},
                {"value": "device-missing"},
                {"value": "version-unavailable"},
                {"value": "staging-failed"},
                {"value": "reboot-failed"},
                {"value": "device-not-reconnected"},
                {"value": "node-not-ready"},
                {"value": "no-final-confirmation"},
                {"value": "no-confirmation-query"},
                {"value": "config-error-log-nonempty", "v_range": [["v7.2.4", ""]]},
                {"value": "csf-tree-not-supported", "v_range": [["v7.4.1", ""]]},
                {"value": "node-failed", "v_range": [["v7.2.4", ""]]},
            ],
        },
        "failure_device": {"v_range": [["v7.0.2", ""]], "type": "string"},
        "upgrade_id": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "next_path_index": {"v_range": [["v7.0.4", ""]], "type": "integer"},
        "ignore_signing_errors": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ha_reboot_controller": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "known_ha_members": {
            "type": "list",
            "elements": "dict",
            "children": {
                "serial": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.4.2", ""]],
        },
        "node_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "serial": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "timing": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "immediate"}, {"value": "scheduled"}],
                },
                "maximum_minutes": {"v_range": [["v7.4.0", ""]], "type": "integer"},
                "time": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "setup_time": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "upgrade_path": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "device_type": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "fortigate"},
                        {"value": "fortiswitch"},
                        {"value": "fortiap"},
                        {"value": "fortiextender", "v_range": [["v7.2.1", ""]]},
                    ],
                },
                "coordinating_fortigate": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                },
            },
            "v_range": [["v7.0.0", ""]],
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
        "system_federated_upgrade": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_federated_upgrade"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_federated_upgrade"]["options"][attribute_name][
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
            fos, versioned_schema, "system_federated_upgrade"
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
