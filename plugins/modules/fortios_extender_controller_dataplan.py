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
module: fortios_extender_controller_dataplan
short_description: FortiExtender dataplan configuration in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify extender_controller feature and dataplan category.
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
    extender_controller_dataplan:
        description:
            - FortiExtender dataplan configuration.
        default: null
        type: dict
        suboptions:
            apn:
                description:
                    - APN configuration.
                type: str
            auth_type:
                description:
                    - Authentication type.
                type: str
                choices:
                    - 'none'
                    - 'pap'
                    - 'chap'
            billing_date:
                description:
                    - Billing day of the month (1 - 31).
                type: int
            capacity:
                description:
                    - Capacity in MB (0 - 102400000).
                type: int
            carrier:
                description:
                    - Carrier configuration.
                type: str
            iccid:
                description:
                    - ICCID configuration.
                type: str
            modem_id:
                description:
                    - Dataplan"s modem specifics, if any.
                type: str
                choices:
                    - 'modem1'
                    - 'modem2'
                    - 'all'
            monthly_fee:
                description:
                    - Monthly fee of dataplan (0 - 100000, in local currency).
                type: int
            name:
                description:
                    - FortiExtender data plan name.
                required: true
                type: str
            overage:
                description:
                    - Enable/disable dataplan overage detection.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            password:
                description:
                    - Password.
                type: str
            pdn:
                description:
                    - PDN type.
                type: str
                choices:
                    - 'ipv4-only'
                    - 'ipv6-only'
                    - 'ipv4-ipv6'
            preferred_subnet:
                description:
                    - Preferred subnet mask (0 - 32).
                type: int
            private_network:
                description:
                    - Enable/disable dataplan private network support.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            signal_period:
                description:
                    - Signal period (600 to 18000 seconds).
                type: int
            signal_threshold:
                description:
                    - Signal threshold. Specify the range between 50 - 100, where 50/100 means -50/-100 dBm.
                type: int
            slot:
                description:
                    - SIM slot configuration.
                type: str
                choices:
                    - 'sim1'
                    - 'sim2'
            type:
                description:
                    - Type preferences configuration.
                type: str
                choices:
                    - 'carrier'
                    - 'slot'
                    - 'iccid'
                    - 'generic'
            username:
                description:
                    - Username.
                type: str
"""

EXAMPLES = """
- name: FortiExtender dataplan configuration.
  fortinet.fortios.fortios_extender_controller_dataplan:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      extender_controller_dataplan:
          apn: "<your_own_value>"
          auth_type: "none"
          billing_date: "1"
          capacity: "0"
          carrier: "<your_own_value>"
          iccid: "<your_own_value>"
          modem_id: "modem1"
          monthly_fee: "0"
          name: "default_name_11"
          overage: "disable"
          password: "<your_own_value>"
          pdn: "ipv4-only"
          preferred_subnet: "32"
          private_network: "disable"
          signal_period: "3600"
          signal_threshold: "100"
          slot: "sim1"
          type: "carrier"
          username: "<your_own_value>"
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
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    unify_data_format,
)


def filter_extender_controller_dataplan_data(json):
    option_list = [
        "apn",
        "auth_type",
        "billing_date",
        "capacity",
        "carrier",
        "iccid",
        "modem_id",
        "monthly_fee",
        "name",
        "overage",
        "password",
        "pdn",
        "preferred_subnet",
        "private_network",
        "signal_period",
        "signal_threshold",
        "slot",
        "type",
        "username",
    ]

    json = remove_invalid_fields(json)
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def underscore_to_hyphen(data):
    new_data = None
    if isinstance(data, list):
        new_data = []
        for i, elem in enumerate(data):
            new_data.append(underscore_to_hyphen(elem))
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace("_", "-")] = underscore_to_hyphen(v)
    else:
        return data
    return new_data


def extender_controller_dataplan(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    extender_controller_dataplan_data = data["extender_controller_dataplan"]

    filtered_data = filter_extender_controller_dataplan_data(
        extender_controller_dataplan_data
    )
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("extender-controller", "dataplan", filtered_data, vdom=vdom)
        current_data = fos.get("extender-controller", "dataplan", vdom=vdom, mkey=mkey)
        is_existed = (
            current_data
            and current_data.get("http_status") == 200
            and (
                mkeyname
                and isinstance(current_data.get("results"), list)
                and len(current_data["results"]) > 0
                or not mkeyname
                and current_data["results"]  # global object response
            )
        )

        # 2. if it exists and the state is 'present' then compare current settings with desired
        if state == "present" or state is True or state is None:
            # for non global modules, mkeyname must exist and it's a new module when mkey is None
            if mkeyname is not None and mkey is None:
                return False, True, filtered_data, diff

            # if mkey exists then compare each other
            # record exits and they're matched or not
            copied_filtered_data = filtered_data.copy()
            copied_filtered_data.pop(mkeyname, None)
            unified_filtered_data = unify_data_format(copied_filtered_data)

            current_data_results = current_data.get("results", {})
            current_config = (
                current_data_results[0]
                if mkeyname
                and isinstance(current_data_results, list)
                and len(current_data_results) > 0
                else current_data_results
            )
            if is_existed:
                unified_current_values = find_current_values(
                    unified_filtered_data,
                    unify_data_format(current_config),
                )

                is_same = is_same_comparison(
                    serialize(unified_current_values), serialize(unified_filtered_data)
                )

                return (
                    False,
                    not is_same,
                    filtered_data,
                    {"before": unified_current_values, "after": unified_filtered_data},
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
    # no need to do underscore_to_hyphen since do_member_operation handles it by itself
    data_copy = data.copy()
    data_copy["extender_controller_dataplan"] = filtered_data
    fos.do_member_operation(
        "extender-controller",
        "dataplan",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set(
            "extender-controller", "dataplan", data=converted_data, vdom=vdom
        )

    elif state == "absent":
        return fos.delete(
            "extender-controller", "dataplan", mkey=converted_data["name"], vdom=vdom
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


def fortios_extender_controller(data, fos, check_mode):

    if data["extender_controller_dataplan"]:
        resp = extender_controller_dataplan(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("extender_controller_dataplan")
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
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.2.0"]],
            "type": "string",
            "required": True,
        },
        "modem_id": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.2.0"]],
            "type": "string",
            "options": [{"value": "modem1"}, {"value": "modem2"}, {"value": "all"}],
        },
        "type": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.2.0"]],
            "type": "string",
            "options": [
                {"value": "carrier"},
                {"value": "slot"},
                {"value": "iccid"},
                {"value": "generic"},
            ],
        },
        "slot": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.2.0"]],
            "type": "string",
            "options": [{"value": "sim1"}, {"value": "sim2"}],
        },
        "iccid": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.2.0"]],
            "type": "string",
        },
        "carrier": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.2.0"]],
            "type": "string",
        },
        "apn": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.2.0"]],
            "type": "string",
        },
        "auth_type": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.2.0"]],
            "type": "string",
            "options": [{"value": "none"}, {"value": "pap"}, {"value": "chap"}],
        },
        "username": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.2.0"]],
            "type": "string",
        },
        "password": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.2.0"]],
            "type": "string",
        },
        "pdn": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.2.0"]],
            "type": "string",
            "options": [
                {"value": "ipv4-only"},
                {"value": "ipv6-only"},
                {"value": "ipv4-ipv6"},
            ],
        },
        "signal_threshold": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.2.0"]],
            "type": "integer",
        },
        "signal_period": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.2.0"]],
            "type": "integer",
        },
        "capacity": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.2.0"]],
            "type": "integer",
        },
        "monthly_fee": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.2.0"]],
            "type": "integer",
        },
        "billing_date": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.2.0"]],
            "type": "integer",
        },
        "overage": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.2.0"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "preferred_subnet": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.2.0"]],
            "type": "integer",
        },
        "private_network": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.2.0"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
    },
    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", "v7.2.0"]],
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
        "extender_controller_dataplan": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["extender_controller_dataplan"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["extender_controller_dataplan"]["options"][attribute_name][
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
            fos, versioned_schema, "extender_controller_dataplan"
        )

        is_error, has_changed, result, diff = fortios_extender_controller(
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
