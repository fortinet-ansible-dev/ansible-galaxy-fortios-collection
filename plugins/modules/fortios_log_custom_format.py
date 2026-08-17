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
module: fortios_log_custom_format
short_description: Configure custom log format in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify log feature and custom_format category.
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
    - ansible>=2.16
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
    log_custom_format:
        description:
            - Configure custom log format.
        default: null
        type: dict
        suboptions:
            empty_value_indicator:
                description:
                    - A character to indicate log field is empty.
                type: str
            field_exclusion_list:
                description:
                    - Log fields to exclude in the log.
                type: list
                elements: dict
                suboptions:
                    field:
                        description:
                            - Log field to exclude from formatting.
                        required: true
                        type: list
                        elements: str
            log_templates:
                description:
                    - Custom log templates.
                type: list
                elements: dict
                suboptions:
                    category:
                        description:
                            - Log category.
                        type: str
                        choices:
                            - 'traffic'
                            - 'event'
                            - 'virus'
                            - 'webfilter'
                            - 'attack'
                            - 'spam'
                            - 'anomaly'
                            - 'voip'
                            - 'dlp'
                            - 'app-ctrl'
                            - 'waf'
                            - 'dns'
                            - 'ssh'
                            - 'ssl'
                            - 'file-filter'
                            - 'icap'
                            - 'virtual-patch'
                            - 'debug'
                    name:
                        description:
                            - Template name string.
                        required: true
                        type: str
                    subtypes:
                        description:
                            - Log subtypes to apply template to.
                        type: list
                        elements: dict
                        suboptions:
                            subtype:
                                description:
                                    - Log subtype.
                                required: true
                                type: str
                    template:
                        description:
                            - Log template string.
                        type: str
            name:
                description:
                    - Format name string.
                required: true
                type: str
"""
EXAMPLES = """
- name: Configure custom log format.
  fortinet.fortios.fortios_log_custom_format:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      log_custom_format:
          empty_value_indicator: "<your_own_value>"
          field_exclusion_list:
              -
                  field: "<your_own_value>"
          log_templates:
              -
                  category: "traffic"
                  name: "default_name_8"
                  subtypes:
                      -
                          subtype: "<your_own_value>"
                  template: "<your_own_value>"
          name: "default_name_12"
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


def filter_log_custom_format_data(json):
    option_list = [
        "empty_value_indicator",
        "field_exclusion_list",
        "log_templates",
        "name",
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
        or (not data[path[index]] and not isinstance(data[path[index]], list))
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
        ["field_exclusion_list", "field"],
    ]

    for attr in multilist_attrs:
        flatten_single_path(data, attr, 0)

    return data


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


def log_custom_format(data, fos):
    state = None
    vdom = data["vdom"]
    parameters = None
    state = data.get("state", None)
    log_custom_format_data = data["log_custom_format"]

    filtered_data = filter_log_custom_format_data(log_custom_format_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # pass post processed data to member operations
    # no need to do underscore_to_hyphen since do_member_operation handles it by itself
    data_copy = data.copy()
    data_copy["log_custom_format"] = filtered_data
    fos.do_member_operation(
        "log",
        "custom-format",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set(
            "log",
            "custom-format",
            data=converted_data,
            vdom=vdom,
            parameters=parameters,
        )

    elif state == "absent":
        return fos.delete(
            "log",
            "custom-format",
            mkey=converted_data["name"],
            vdom=vdom,
            parameters=parameters,
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


def fortios_log(data, fos):

    if data["log_custom_format"]:
        resp = log_custom_format(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("log_custom_format"))

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
        "name": {"v_range": [["v8.0.0", ""]], "type": "string", "required": True},
        "field_exclusion_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "field": {
                    "v_range": [["v8.0.0", ""]],
                    "type": "list",
                    "multiple_values": True,
                    "elements": "str",
                    "required": True,
                }
            },
            "v_range": [["v8.0.0", ""]],
        },
        "empty_value_indicator": {"v_range": [["v8.0.0", ""]], "type": "string"},
        "log_templates": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v8.0.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "category": {
                    "v_range": [["v8.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "traffic"},
                        {"value": "event"},
                        {"value": "virus"},
                        {"value": "webfilter"},
                        {"value": "attack"},
                        {"value": "spam"},
                        {"value": "anomaly"},
                        {"value": "voip"},
                        {"value": "dlp"},
                        {"value": "app-ctrl"},
                        {"value": "waf"},
                        {"value": "dns"},
                        {"value": "ssh"},
                        {"value": "ssl"},
                        {"value": "file-filter"},
                        {"value": "icap"},
                        {"value": "virtual-patch"},
                        {"value": "debug"},
                    ],
                },
                "subtypes": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "subtype": {
                            "v_range": [["v8.0.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v8.0.0", ""]],
                },
                "template": {"v_range": [["v8.0.0", ""]], "type": "string"},
            },
            "v_range": [["v8.0.0", ""]],
        },
    },
    "v_range": [["v8.0.0", ""]],
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
        "log_custom_format": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["log_custom_format"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["log_custom_format"]["options"][attribute_name]["required"] = True

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
        fos = FortiOSHandler(connection, module, mkeyname, admin_passwd_header=False)
        versions_check_result = check_schema_versioning(
            fos, versioned_schema, "log_custom_format"
        )

        is_error, has_changed, result, diff = fortios_log(module.params, fos)

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
