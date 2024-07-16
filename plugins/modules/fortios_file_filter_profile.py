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
module: fortios_file_filter_profile
short_description: Configure file-filter profiles in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify file_filter feature and profile category.
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
    file_filter_profile:
        description:
            - Configure file-filter profiles.
        default: null
        type: dict
        suboptions:
            comment:
                description:
                    - Comment.
                type: str
            extended_log:
                description:
                    - Enable/disable file-filter extended logging.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            feature_set:
                description:
                    - Flow/proxy feature set.
                type: str
                choices:
                    - 'flow'
                    - 'proxy'
            log:
                description:
                    - Enable/disable file-filter logging.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            name:
                description:
                    - Profile name.
                required: true
                type: str
            replacemsg_group:
                description:
                    - Replacement message group. Source system.replacemsg-group.name.
                type: str
            rules:
                description:
                    - File filter rules.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Action taken for matched file.
                        type: str
                        choices:
                            - 'log-only'
                            - 'block'
                    comment:
                        description:
                            - Comment.
                        type: str
                    direction:
                        description:
                            - Traffic direction (HTTP, FTP, SSH, CIFS, and MAPI only).
                        type: str
                        choices:
                            - 'incoming'
                            - 'outgoing'
                            - 'any'
                    file_type:
                        description:
                            - Select file type.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - File type name. Source antivirus.filetype.name.
                                required: true
                                type: str
                    name:
                        description:
                            - File-filter rule name.
                        required: true
                        type: str
                    password_protected:
                        description:
                            - Match password-protected files.
                        type: str
                        choices:
                            - 'yes'
                            - 'any'
                    protocol:
                        description:
                            - Protocols to apply rule to.
                        type: list
                        elements: str
                        choices:
                            - 'http'
                            - 'ftp'
                            - 'smtp'
                            - 'imap'
                            - 'pop3'
                            - 'mapi'
                            - 'cifs'
                            - 'ssh'
            scan_archive_contents:
                description:
                    - Enable/disable archive contents scan.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
"""

EXAMPLES = """
- name: Configure file-filter profiles.
  fortinet.fortios.fortios_file_filter_profile:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      file_filter_profile:
          comment: "Comment."
          extended_log: "disable"
          feature_set: "flow"
          log: "disable"
          name: "default_name_7"
          replacemsg_group: "<your_own_value> (source system.replacemsg-group.name)"
          rules:
              -
                  action: "log-only"
                  comment: "Comment."
                  direction: "incoming"
                  file_type:
                      -
                          name: "default_name_14 (source antivirus.filetype.name)"
                  name: "default_name_15"
                  password_protected: "yes"
                  protocol: "http"
          scan_archive_contents: "disable"
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


def filter_file_filter_profile_data(json):
    option_list = [
        "comment",
        "extended_log",
        "feature_set",
        "log",
        "name",
        "replacemsg_group",
        "rules",
        "scan_archive_contents",
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
        ["rules", "protocol"],
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


def file_filter_profile(data, fos, check_mode=False):
    state = None
    vdom = data["vdom"]

    state = data["state"]

    file_filter_profile_data = data["file_filter_profile"]
    file_filter_profile_data = flatten_multilists_attributes(file_filter_profile_data)
    filtered_data = filter_file_filter_profile_data(file_filter_profile_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("file-filter", "profile", filtered_data, vdom=vdom)
        current_data = fos.get("file-filter", "profile", vdom=vdom, mkey=mkey)
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
        return fos.set("file-filter", "profile", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "file-filter", "profile", mkey=converted_data["name"], vdom=vdom
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


def fortios_file_filter(data, fos, check_mode):
    fos.do_member_operation("file-filter", "profile")
    if data["file_filter_profile"]:
        resp = file_filter_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("file_filter_profile"))
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
        "name": {"v_range": [["v6.4.0", ""]], "type": "string", "required": True},
        "comment": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "feature_set": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "flow"}, {"value": "proxy"}],
        },
        "replacemsg_group": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "log": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "extended_log": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "scan_archive_contents": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "rules": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "required": True,
                },
                "comment": {"v_range": [["v6.4.0", ""]], "type": "string"},
                "protocol": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "http"},
                        {"value": "ftp"},
                        {"value": "smtp"},
                        {"value": "imap"},
                        {"value": "pop3"},
                        {"value": "mapi"},
                        {"value": "cifs"},
                        {"value": "ssh"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "action": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "log-only"}, {"value": "block"}],
                },
                "direction": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "incoming"},
                        {"value": "outgoing"},
                        {"value": "any"},
                    ],
                },
                "password_protected": {
                    "v_range": [["v6.4.0", ""]],
                    "type": "string",
                    "options": [{"value": "yes"}, {"value": "any"}],
                },
                "file_type": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.4.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.4.0", ""]],
                },
            },
            "v_range": [["v6.4.0", ""]],
        },
    },
    "v_range": [["v6.4.0", ""]],
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
        "file_filter_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["file_filter_profile"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["file_filter_profile"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "file_filter_profile"
        )

        is_error, has_changed, result, diff = fortios_file_filter(
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
