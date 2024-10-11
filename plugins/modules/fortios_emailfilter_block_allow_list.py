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
module: fortios_emailfilter_block_allow_list
short_description: Configure anti-spam block/allow list in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify emailfilter feature and block_allow_list category.
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
    - We highly recommend using your own value as the id instead of 0, while '0' is a special placeholder that allows the backend to assign the latest
       available number for the object, it does have limitations. Please find more details in Q&A.
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

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - 'present'
            - 'absent'
    emailfilter_block_allow_list:
        description:
            - Configure anti-spam block/allow list.
        default: null
        type: dict
        suboptions:
            comment:
                description:
                    - Optional comments.
                type: str
            entries:
                description:
                    - Anti-spam block/allow entries.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Reject, mark as spam or good email.
                        type: str
                        choices:
                            - 'reject'
                            - 'spam'
                            - 'clear'
                    addr_type:
                        description:
                            - IP address type.
                        type: str
                        choices:
                            - 'ipv4'
                            - 'ipv6'
                    email_pattern:
                        description:
                            - Email address pattern.
                        type: str
                    id:
                        description:
                            - Entry ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    ip4_subnet:
                        description:
                            - IPv4 network address/subnet mask bits.
                        type: str
                    ip6_subnet:
                        description:
                            - IPv6 network address/subnet mask bits.
                        type: str
                    pattern:
                        description:
                            - Pattern to match.
                        type: str
                    pattern_type:
                        description:
                            - Wildcard pattern or regular expression.
                        type: str
                        choices:
                            - 'wildcard'
                            - 'regexp'
                    status:
                        description:
                            - Enable/disable status.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    type:
                        description:
                            - Entry type.
                        type: str
                        choices:
                            - 'ip'
                            - 'email-to'
                            - 'email-from'
                            - 'subject'
                            - 'email'
            id:
                description:
                    - ID. see <a href='#notes'>Notes</a>.
                required: true
                type: int
            name:
                description:
                    - Name of table.
                type: str
"""

EXAMPLES = """
- name: Configure anti-spam block/allow list.
  fortinet.fortios.fortios_emailfilter_block_allow_list:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      emailfilter_block_allow_list:
          comment: "Optional comments."
          entries:
              -
                  action: "reject"
                  addr_type: "ipv4"
                  email_pattern: "<your_own_value>"
                  id: "8"
                  ip4_subnet: "<your_own_value>"
                  ip6_subnet: "<your_own_value>"
                  pattern: "<your_own_value>"
                  pattern_type: "wildcard"
                  status: "enable"
                  type: "ip"
          id: "15"
          name: "default_name_16"
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


def filter_emailfilter_block_allow_list_data(json):
    option_list = ["comment", "entries", "id", "name"]

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


def emailfilter_block_allow_list(data, fos):
    state = None
    vdom = data["vdom"]

    state = data["state"]

    emailfilter_block_allow_list_data = data["emailfilter_block_allow_list"]

    filtered_data = filter_emailfilter_block_allow_list_data(
        emailfilter_block_allow_list_data
    )
    converted_data = underscore_to_hyphen(filtered_data)

    # pass post processed data to member operations
    data_copy = data.copy()
    data_copy["emailfilter_block_allow_list"] = converted_data
    fos.do_member_operation(
        "emailfilter",
        "block-allow-list",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set(
            "emailfilter", "block-allow-list", data=converted_data, vdom=vdom
        )

    elif state == "absent":
        return fos.delete(
            "emailfilter", "block-allow-list", mkey=converted_data["id"], vdom=vdom
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


def fortios_emailfilter(data, fos):
    if data["emailfilter_block_allow_list"]:
        resp = emailfilter_block_allow_list(data, fos)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("emailfilter_block_allow_list")
        )

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
        "id": {"v_range": [["v7.0.0", ""]], "type": "integer", "required": True},
        "name": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "comment": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "entries": {
            "type": "list",
            "elements": "dict",
            "children": {
                "status": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "id": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "type": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "ip"},
                        {"value": "email-to", "v_range": [["v7.2.0", ""]]},
                        {"value": "email-from", "v_range": [["v7.2.0", ""]]},
                        {"value": "subject", "v_range": [["v7.2.0", ""]]},
                        {"value": "email", "v_range": [["v7.0.0", "v7.0.12"]]},
                    ],
                },
                "action": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "reject"},
                        {"value": "spam"},
                        {"value": "clear"},
                    ],
                },
                "addr_type": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "ipv4"}, {"value": "ipv6"}],
                },
                "ip4_subnet": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "ip6_subnet": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "pattern_type": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "wildcard"}, {"value": "regexp"}],
                },
                "pattern": {"v_range": [["v7.2.0", ""]], "type": "string"},
                "email_pattern": {"v_range": [["v7.0.0", "v7.0.12"]], "type": "string"},
            },
            "v_range": [["v7.0.0", ""]],
        },
    },
    "v_range": [["v7.0.0", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "id"
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
        "emailfilter_block_allow_list": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["emailfilter_block_allow_list"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["emailfilter_block_allow_list"]["options"][attribute_name][
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
            fos, versioned_schema, "emailfilter_block_allow_list"
        )

        is_error, has_changed, result, diff = fortios_emailfilter(module.params, fos)

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
