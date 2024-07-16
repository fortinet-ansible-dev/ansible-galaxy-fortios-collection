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
module: fortios_dlp_profile
short_description: Configure DLP profiles in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify dlp feature and profile category.
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

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - 'present'
            - 'absent'
    dlp_profile:
        description:
            - Configure DLP profiles.
        default: null
        type: dict
        suboptions:
            comment:
                description:
                    - Comment.
                type: str
            dlp_log:
                description:
                    - Enable/disable DLP logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            extended_log:
                description:
                    - Enable/disable extended logging for data loss prevention.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            feature_set:
                description:
                    - Flow/proxy feature set.
                type: str
                choices:
                    - 'flow'
                    - 'proxy'
            full_archive_proto:
                description:
                    - Protocols to always content archive.
                type: list
                elements: str
                choices:
                    - 'smtp'
                    - 'pop3'
                    - 'imap'
                    - 'http-get'
                    - 'http-post'
                    - 'ftp'
                    - 'nntp'
                    - 'mapi'
                    - 'ssh'
                    - 'cifs'
            nac_quar_log:
                description:
                    - Enable/disable NAC quarantine logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            name:
                description:
                    - Name of the DLP profile.
                required: true
                type: str
            replacemsg_group:
                description:
                    - Replacement message group used by this DLP profile. Source system.replacemsg-group.name.
                type: str
            rule:
                description:
                    - Set up DLP rules for this profile.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Action to take with content that this DLP profile matches.
                        type: str
                        choices:
                            - 'allow'
                            - 'log-only'
                            - 'block'
                            - 'quarantine-ip'
                    archive:
                        description:
                            - Enable/disable DLP archiving.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    expiry:
                        description:
                            - Quarantine duration in days, hours, minutes (format = dddhhmm).
                        type: str
                    file_size:
                        description:
                            - Match files greater than or equal to this size (KB).
                        type: int
                    file_type:
                        description:
                            - Select the number of a DLP file pattern table to match. Source dlp.filepattern.id.
                        type: int
                    filter_by:
                        description:
                            - Select the type of content to match.
                        type: str
                        choices:
                            - 'sensor'
                            - 'mip'
                            - 'fingerprint'
                            - 'encrypted'
                            - 'none'
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    label:
                        description:
                            - MIP label dictionary. Source dlp.dictionary.name.
                        type: str
                    match_percentage:
                        description:
                            - Percentage of fingerprints in the fingerprint databases designated with the selected sensitivity to match.
                        type: int
                    name:
                        description:
                            - Filter name.
                        type: str
                    proto:
                        description:
                            - Check messages or files over one or more of these protocols.
                        type: list
                        elements: str
                        choices:
                            - 'smtp'
                            - 'pop3'
                            - 'imap'
                            - 'http-get'
                            - 'http-post'
                            - 'ftp'
                            - 'nntp'
                            - 'mapi'
                            - 'ssh'
                            - 'cifs'
                    sensitivity:
                        description:
                            - Select a DLP file pattern sensitivity to match.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Select a DLP sensitivity. Source dlp.sensitivity.name.
                                required: true
                                type: str
                    sensor:
                        description:
                            - Select DLP sensors.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Address name. Source dlp.sensor.name.
                                required: true
                                type: str
                    severity:
                        description:
                            - Select the severity or threat level that matches this filter.
                        type: str
                        choices:
                            - 'info'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    type:
                        description:
                            - Select whether to check the content of messages (an email message) or files (downloaded files or email attachments).
                        type: str
                        choices:
                            - 'file'
                            - 'fos_message'
            summary_proto:
                description:
                    - Protocols to always log summary.
                type: list
                elements: str
                choices:
                    - 'smtp'
                    - 'pop3'
                    - 'imap'
                    - 'http-get'
                    - 'http-post'
                    - 'ftp'
                    - 'nntp'
                    - 'mapi'
                    - 'ssh'
                    - 'cifs'
"""

EXAMPLES = """
- name: Configure DLP profiles.
  fortinet.fortios.fortios_dlp_profile:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      dlp_profile:
          comment: "Comment."
          dlp_log: "enable"
          extended_log: "enable"
          feature_set: "flow"
          full_archive_proto: "smtp"
          nac_quar_log: "enable"
          name: "default_name_9"
          replacemsg_group: "<your_own_value> (source system.replacemsg-group.name)"
          rule:
              -
                  action: "allow"
                  archive: "disable"
                  expiry: "<your_own_value>"
                  file_size: "0"
                  file_type: "0"
                  filter_by: "sensor"
                  id: "18"
                  label: "<your_own_value> (source dlp.dictionary.name)"
                  match_percentage: "10"
                  name: "default_name_21"
                  proto: "smtp"
                  sensitivity:
                      -
                          name: "default_name_24 (source dlp.sensitivity.name)"
                  sensor:
                      -
                          name: "default_name_26 (source dlp.sensor.name)"
                  severity: "info"
                  type: "file"
          summary_proto: "smtp"
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


def filter_dlp_profile_data(json):
    option_list = [
        "comment",
        "dlp_log",
        "extended_log",
        "feature_set",
        "full_archive_proto",
        "nac_quar_log",
        "name",
        "replacemsg_group",
        "rule",
        "summary_proto",
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
        ["rule", "proto"],
        ["full_archive_proto"],
        ["summary_proto"],
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


def valid_attr_to_invalid_attr(data):
    speciallist = {"message": "fos_message"}

    for k, v in speciallist.items():
        if v == data:
            return k

    return data


def valid_attr_to_invalid_attrs(data):
    if isinstance(data, list):
        new_data = []
        for elem in data:
            elem = valid_attr_to_invalid_attrs(elem)
            new_data.append(elem)
        data = new_data
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[valid_attr_to_invalid_attr(k)] = valid_attr_to_invalid_attrs(v)
        data = new_data

    return valid_attr_to_invalid_attr(data)


def dlp_profile(data, fos):
    state = None
    vdom = data["vdom"]

    state = data["state"]

    dlp_profile_data = data["dlp_profile"]
    dlp_profile_data = flatten_multilists_attributes(dlp_profile_data)
    filtered_data = filter_dlp_profile_data(dlp_profile_data)
    converted_data = underscore_to_hyphen(valid_attr_to_invalid_attrs(filtered_data))

    if state == "present" or state is True:
        return fos.set("dlp", "profile", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("dlp", "profile", mkey=converted_data["name"], vdom=vdom)
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


def fortios_dlp(data, fos):
    fos.do_member_operation("dlp", "profile")
    if data["dlp_profile"]:
        resp = dlp_profile(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("dlp_profile"))

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
        "name": {"v_range": [["v7.2.0", ""]], "type": "string", "required": True},
        "comment": {"v_range": [["v7.2.0", ""]], "type": "string"},
        "feature_set": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "flow"}, {"value": "proxy"}],
        },
        "replacemsg_group": {"v_range": [["v7.2.0", ""]], "type": "string"},
        "rule": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "name": {"v_range": [["v7.2.0", ""]], "type": "string"},
                "severity": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "info"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
                "type": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "file"}, {"value": "fos_message"}],
                },
                "proto": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "smtp"},
                        {"value": "pop3"},
                        {"value": "imap"},
                        {"value": "http-get"},
                        {"value": "http-post"},
                        {"value": "ftp"},
                        {"value": "nntp"},
                        {"value": "mapi"},
                        {"value": "ssh"},
                        {"value": "cifs"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "filter_by": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "sensor"},
                        {"value": "mip"},
                        {
                            "value": "fingerprint",
                            "v_range": [["v7.2.0", "v7.4.1"], ["v7.4.3", ""]],
                        },
                        {"value": "encrypted"},
                        {"value": "none"},
                    ],
                },
                "file_size": {"v_range": [["v7.2.0", ""]], "type": "integer"},
                "sensitivity": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.2.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.2.0", "v7.4.1"], ["v7.4.3", ""]],
                },
                "match_percentage": {
                    "v_range": [["v7.2.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "integer",
                },
                "file_type": {"v_range": [["v7.2.0", ""]], "type": "integer"},
                "sensor": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.2.0", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.2.0", ""]],
                },
                "label": {"v_range": [["v7.2.0", ""]], "type": "string"},
                "archive": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "action": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "log-only"},
                        {"value": "block"},
                        {"value": "quarantine-ip"},
                    ],
                },
                "expiry": {"v_range": [["v7.2.0", ""]], "type": "string"},
            },
            "v_range": [["v7.2.0", ""]],
        },
        "dlp_log": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "extended_log": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "nac_quar_log": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "full_archive_proto": {
            "v_range": [["v7.2.0", ""]],
            "type": "list",
            "options": [
                {"value": "smtp"},
                {"value": "pop3"},
                {"value": "imap"},
                {"value": "http-get"},
                {"value": "http-post"},
                {"value": "ftp"},
                {"value": "nntp"},
                {"value": "mapi"},
                {"value": "ssh"},
                {"value": "cifs"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "summary_proto": {
            "v_range": [["v7.2.0", ""]],
            "type": "list",
            "options": [
                {"value": "smtp"},
                {"value": "pop3"},
                {"value": "imap"},
                {"value": "http-get"},
                {"value": "http-post"},
                {"value": "ftp"},
                {"value": "nntp"},
                {"value": "mapi"},
                {"value": "ssh"},
                {"value": "cifs"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
    },
    "v_range": [["v7.2.0", ""]],
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
        "dlp_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["dlp_profile"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["dlp_profile"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "dlp_profile"
        )

        is_error, has_changed, result, diff = fortios_dlp(module.params, fos)

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
