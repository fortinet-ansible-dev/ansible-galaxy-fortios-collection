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
module: fortios_system_password_policy_guest_admin
short_description: Configure the password policy for guest administrators in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and password_policy_guest_admin category.
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

    system_password_policy_guest_admin:
        description:
            - Configure the password policy for guest administrators.
        default: null
        type: dict
        suboptions:
            apply_to:
                description:
                    - Guest administrator to which this password policy applies.
                type: list
                elements: str
                choices:
                    - 'guest-admin-password'
            change_4_characters:
                description:
                    - Enable/disable changing at least 4 characters for a new password (This attribute overrides reuse-password if both are enabled).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            expire_day:
                description:
                    - Number of days after which passwords expire (1 - 999 days).
                type: int
            expire_status:
                description:
                    - Enable/disable password expiration.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            min_change_characters:
                description:
                    - Minimum number of unique characters in new password which do not exist in old password (0 - 128).
                type: int
            min_lower_case_letter:
                description:
                    - Minimum number of lowercase characters in password (0 - 128).
                type: int
            min_non_alphanumeric:
                description:
                    - Minimum number of non-alphanumeric characters in password (0 - 128).
                type: int
            min_number:
                description:
                    - Minimum number of numeric characters in password (0 - 128).
                type: int
            min_upper_case_letter:
                description:
                    - Minimum number of uppercase characters in password (0 - 128).
                type: int
            minimum_length:
                description:
                    - Minimum password length (8 - 128).
                type: int
            reuse_password:
                description:
                    - Enable/disable reuse of password. If both reuse-password and min-change-characters are enabled, min-change-characters overrides.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            reuse_password_limit:
                description:
                    - Number of times passwords can be reused (0 - 20).
                type: int
            status:
                description:
                    - Enable/disable setting a password policy for locally defined administrator passwords and IPsec VPN pre-shared keys.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure the password policy for guest administrators.
  fortinet.fortios.fortios_system_password_policy_guest_admin:
      vdom: "{{ vdom }}"
      system_password_policy_guest_admin:
          apply_to: "guest-admin-password"
          change_4_characters: "enable"
          expire_day: "90"
          expire_status: "enable"
          min_change_characters: "0"
          min_lower_case_letter: "0"
          min_non_alphanumeric: "0"
          min_number: "0"
          min_upper_case_letter: "0"
          minimum_length: "8"
          reuse_password: "enable"
          reuse_password_limit: "0"
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


def filter_system_password_policy_guest_admin_data(json):
    option_list = [
        "apply_to",
        "change_4_characters",
        "expire_day",
        "expire_status",
        "min_change_characters",
        "min_lower_case_letter",
        "min_non_alphanumeric",
        "min_number",
        "min_upper_case_letter",
        "minimum_length",
        "reuse_password",
        "reuse_password_limit",
        "status",
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
        and not isinstance(data[path[index]], list)
    ):
        return

    if index == len(path) - 1:
        data[path[index]] = " ".join(str(elem) for elem in data[path[index]])
        if len(data[path[index]]) == 0:
            data[path[index]] = None
    elif isinstance(data[path[index]], list):
        for value in data[path[index]]:
            flatten_single_path(value, path, index + 1)
    else:
        flatten_single_path(data[path[index]], path, index + 1)


def flatten_multilists_attributes(data):
    multilist_attrs = [
        ["apply_to"],
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


def system_password_policy_guest_admin(data, fos):
    state = None
    vdom = data["vdom"]
    system_password_policy_guest_admin_data = data["system_password_policy_guest_admin"]

    filtered_data = filter_system_password_policy_guest_admin_data(
        system_password_policy_guest_admin_data
    )
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # pass post processed data to member operations
    data_copy = data.copy()
    data_copy["system_password_policy_guest_admin"] = converted_data
    fos.do_member_operation(
        "system",
        "password-policy-guest-admin",
        data_copy,
    )

    return fos.set(
        "system", "password-policy-guest-admin", data=converted_data, vdom=vdom
    )


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
    if data["system_password_policy_guest_admin"]:
        resp = system_password_policy_guest_admin(data, fos)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("system_password_policy_guest_admin")
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
        "status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "apply_to": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [{"value": "guest-admin-password"}],
            "multiple_values": True,
            "elements": "str",
        },
        "minimum_length": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "min_lower_case_letter": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "min_upper_case_letter": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "min_non_alphanumeric": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "min_number": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "min_change_characters": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "expire_status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "expire_day": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "reuse_password": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "reuse_password_limit": {"v_range": [["v7.6.0", ""]], "type": "integer"},
        "change_4_characters": {
            "v_range": [["v6.0.0", "v6.4.4"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
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
        "system_password_policy_guest_admin": {
            "required": False,
            "type": "dict",
            "default": None,
            "no_log": True,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_password_policy_guest_admin"]["options"][
            attribute_name
        ] = module_spec["options"][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_password_policy_guest_admin"]["options"][attribute_name][
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
            fos, versioned_schema, "system_password_policy_guest_admin"
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
