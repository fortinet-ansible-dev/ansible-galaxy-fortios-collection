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
module: fortios_ssh_filter_profile
short_description: Configure SSH filter profile in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify ssh_filter feature and profile category.
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
    ssh_filter_profile:
        description:
            - Configure SSH filter profile.
        default: null
        type: dict
        suboptions:
            block:
                description:
                    - SSH blocking options.
                type: list
                elements: str
                choices:
                    - 'x11'
                    - 'shell'
                    - 'exec'
                    - 'port-forward'
                    - 'tun-forward'
                    - 'sftp'
                    - 'scp'
                    - 'unknown'
            default_command_log:
                description:
                    - Enable/disable logging unmatched shell commands.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            file_filter:
                description:
                    - File filter.
                type: dict
                suboptions:
                    entries:
                        description:
                            - File filter entries.
                        type: list
                        elements: dict
                        suboptions:
                            action:
                                description:
                                    - Action taken for matched file.
                                type: str
                                choices:
                                    - 'log'
                                    - 'block'
                            comment:
                                description:
                                    - Comment.
                                type: str
                            direction:
                                description:
                                    - Match files transmitted in the session"s originating or reply direction.
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
                            filter:
                                description:
                                    - Add a file filter.
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
                                    - Protocols to apply with.
                                type: list
                                elements: str
                                choices:
                                    - 'ssh'
                    log:
                        description:
                            - Enable/disable file filter logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    scan_archive_contents:
                        description:
                            - Enable/disable file filter archive contents scan.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    status:
                        description:
                            - Enable/disable file filter.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            log:
                description:
                    - SSH logging options.
                type: list
                elements: str
                choices:
                    - 'x11'
                    - 'shell'
                    - 'exec'
                    - 'port-forward'
                    - 'tun-forward'
                    - 'sftp'
                    - 'scp'
                    - 'unknown'
            name:
                description:
                    - SSH filter profile name.
                required: true
                type: str
            shell_commands:
                description:
                    - SSH command filter.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Action to take for SSH shell command matches.
                        type: str
                        choices:
                            - 'block'
                            - 'allow'
                    alert:
                        description:
                            - Enable/disable alert.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    id:
                        description:
                            - Id. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    log:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    pattern:
                        description:
                            - SSH shell command pattern.
                        type: str
                    severity:
                        description:
                            - Log severity.
                        type: str
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    type:
                        description:
                            - Matching type.
                        type: str
                        choices:
                            - 'simple'
                            - 'regex'
"""

EXAMPLES = """
- name: Configure SSH filter profile.
  fortinet.fortios.fortios_ssh_filter_profile:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      ssh_filter_profile:
          block: "x11"
          default_command_log: "enable"
          file_filter:
              entries:
                  -
                      action: "log"
                      comment: "Comment."
                      direction: "incoming"
                      file_type:
                          -
                              name: "default_name_11 (source antivirus.filetype.name)"
                      filter: "<your_own_value>"
                      password_protected: "yes"
                      protocol: "ssh"
              log: "enable"
              scan_archive_contents: "enable"
              status: "enable"
          log: "x11"
          name: "default_name_19"
          shell_commands:
              -
                  action: "block"
                  alert: "enable"
                  id: "23"
                  log: "enable"
                  pattern: "<your_own_value>"
                  severity: "low"
                  type: "simple"
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


def filter_ssh_filter_profile_data(json):
    option_list = [
        "block",
        "default_command_log",
        "file_filter",
        "log",
        "name",
        "shell_commands",
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
        ["block"],
        ["log"],
        ["file_filter", "entries", "protocol"],
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


def ssh_filter_profile(data, fos, check_mode=False):
    state = None
    vdom = data["vdom"]

    state = data["state"]

    ssh_filter_profile_data = data["ssh_filter_profile"]

    filtered_data = filter_ssh_filter_profile_data(ssh_filter_profile_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("ssh-filter", "profile", filtered_data, vdom=vdom)
        current_data = fos.get("ssh-filter", "profile", vdom=vdom, mkey=mkey)
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
    data_copy["ssh_filter_profile"] = converted_data
    fos.do_member_operation(
        "ssh-filter",
        "profile",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("ssh-filter", "profile", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "ssh-filter", "profile", mkey=converted_data["name"], vdom=vdom
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


def fortios_ssh_filter(data, fos, check_mode):
    if data["ssh_filter_profile"]:
        resp = ssh_filter_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("ssh_filter_profile"))
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
        "block": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "x11"},
                {"value": "shell"},
                {"value": "exec"},
                {"value": "port-forward"},
                {"value": "tun-forward"},
                {"value": "sftp"},
                {"value": "scp", "v_range": [["v6.2.0", ""]]},
                {"value": "unknown"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "log": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "x11"},
                {"value": "shell"},
                {"value": "exec"},
                {"value": "port-forward"},
                {"value": "tun-forward"},
                {"value": "sftp"},
                {"value": "scp", "v_range": [["v6.2.0", ""]]},
                {"value": "unknown"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "default_command_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "shell_commands": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "type": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "simple"}, {"value": "regex"}],
                },
                "pattern": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "action": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "block"}, {"value": "allow"}],
                },
                "log": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "alert": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "severity": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "file_filter": {
            "v_range": [["v6.2.0", "v6.2.7"]],
            "type": "dict",
            "children": {
                "status": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "log": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "scan_archive_contents": {
                    "v_range": [["v6.2.0", "v6.2.7"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "entries": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "filter": {
                            "v_range": [["v6.2.0", "v6.2.7"]],
                            "type": "string",
                            "required": True,
                        },
                        "comment": {
                            "v_range": [["v6.2.0", "v6.2.7"]],
                            "type": "string",
                        },
                        "action": {
                            "v_range": [["v6.2.0", "v6.2.7"]],
                            "type": "string",
                            "options": [{"value": "log"}, {"value": "block"}],
                        },
                        "direction": {
                            "v_range": [["v6.2.0", "v6.2.7"]],
                            "type": "string",
                            "options": [
                                {"value": "incoming"},
                                {"value": "outgoing"},
                                {"value": "any"},
                            ],
                        },
                        "password_protected": {
                            "v_range": [["v6.2.0", "v6.2.7"]],
                            "type": "string",
                            "options": [{"value": "yes"}, {"value": "any"}],
                        },
                        "file_type": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "name": {
                                    "v_range": [["v6.2.0", "v6.2.7"]],
                                    "type": "string",
                                    "required": True,
                                }
                            },
                            "v_range": [["v6.2.0", "v6.2.7"]],
                        },
                        "protocol": {
                            "v_range": [["v6.2.3", "v6.2.3"]],
                            "type": "list",
                            "options": [{"value": "ssh"}],
                            "multiple_values": True,
                            "elements": "str",
                        },
                    },
                    "v_range": [["v6.2.0", "v6.2.7"]],
                },
            },
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
        "ssh_filter_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["ssh_filter_profile"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["ssh_filter_profile"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "ssh_filter_profile"
        )

        is_error, has_changed, result, diff = fortios_ssh_filter(
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
