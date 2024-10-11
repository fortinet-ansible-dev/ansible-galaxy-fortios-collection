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
module: fortios_dlp_fp_doc_source
short_description: Create a DLP fingerprint database by allowing the FortiGate to access a file server containing files from which to create fingerprints in
   Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify dlp feature and fp_doc_source category.
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
    dlp_fp_doc_source:
        description:
            - Create a DLP fingerprint database by allowing the FortiGate to access a file server containing files from which to create fingerprints.
        default: null
        type: dict
        suboptions:
            date:
                description:
                    - Day of the month on which to scan the server (1 - 31).
                type: int
            file_path:
                description:
                    - Path on the server to the fingerprint files (max 119 characters).
                type: str
            file_pattern:
                description:
                    - Files matching this pattern on the server are fingerprinted. Optionally use the * and ? wildcards.
                type: str
            keep_modified:
                description:
                    - Enable so that when a file is changed on the server the FortiGate keeps the old fingerprint and adds a new fingerprint to the database.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            name:
                description:
                    - Name of the DLP fingerprint database.
                required: true
                type: str
            password:
                description:
                    - Password required to log into the file server.
                type: str
            period:
                description:
                    - Frequency for which the FortiGate checks the server for new or changed files.
                type: str
                choices:
                    - 'none'
                    - 'daily'
                    - 'weekly'
                    - 'monthly'
            remove_deleted:
                description:
                    - Enable to keep the fingerprint database up to date when a file is deleted from the server.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            scan_on_creation:
                description:
                    - Enable to keep the fingerprint database up to date when a file is added or changed on the server.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            scan_subdirectories:
                description:
                    - Enable/disable scanning subdirectories to find files to create fingerprints from.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sensitivity:
                description:
                    - Select a sensitivity or threat level for matches with this fingerprint database. Add sensitivities using sensitivity. Source dlp
                      .sensitivity.name.
                type: str
            server:
                description:
                    - IPv4 or IPv6 address of the server.
                type: str
            server_type:
                description:
                    - Protocol used to communicate with the file server. Currently only Samba (SMB) servers are supported.
                type: str
                choices:
                    - 'samba'
            tod_hour:
                description:
                    - Hour of the day on which to scan the server (0 - 23).
                type: int
            tod_min:
                description:
                    - Minute of the hour on which to scan the server (0 - 59).
                type: int
            username:
                description:
                    - User name required to log into the file server.
                type: str
            vdom:
                description:
                    - Select the VDOM that can communicate with the file server.
                type: str
                choices:
                    - 'mgmt'
                    - 'current'
            weekday:
                description:
                    - Day of the week on which to scan the server.
                type: str
                choices:
                    - 'sunday'
                    - 'monday'
                    - 'tuesday'
                    - 'wednesday'
                    - 'thursday'
                    - 'friday'
                    - 'saturday'
"""

EXAMPLES = """
- name: Create a DLP fingerprint database by allowing the FortiGate to access a file server containing files from which to create fingerprints.
  fortinet.fortios.fortios_dlp_fp_doc_source:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      dlp_fp_doc_source:
          date: "1"
          file_path: "<your_own_value>"
          file_pattern: "<your_own_value>"
          keep_modified: "enable"
          name: "default_name_7"
          password: "<your_own_value>"
          period: "none"
          remove_deleted: "enable"
          scan_on_creation: "enable"
          scan_subdirectories: "enable"
          sensitivity: "<your_own_value> (source dlp.sensitivity.name)"
          server: "192.168.100.40"
          server_type: "samba"
          tod_hour: "1"
          tod_min: "0"
          username: "<your_own_value>"
          vdom: "mgmt"
          weekday: "sunday"
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


def filter_dlp_fp_doc_source_data(json):
    option_list = [
        "date",
        "file_path",
        "file_pattern",
        "keep_modified",
        "name",
        "password",
        "period",
        "remove_deleted",
        "scan_on_creation",
        "scan_subdirectories",
        "sensitivity",
        "server",
        "server_type",
        "tod_hour",
        "tod_min",
        "username",
        "vdom",
        "weekday",
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


def dlp_fp_doc_source(data, fos, check_mode=False):
    state = None
    vdom = data["vdom"]

    state = data["state"]

    dlp_fp_doc_source_data = data["dlp_fp_doc_source"]

    filtered_data = filter_dlp_fp_doc_source_data(dlp_fp_doc_source_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("dlp", "fp-doc-source", filtered_data, vdom=vdom)
        current_data = fos.get("dlp", "fp-doc-source", vdom=vdom, mkey=mkey)
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
    data_copy["dlp_fp_doc_source"] = converted_data
    fos.do_member_operation(
        "dlp",
        "fp-doc-source",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("dlp", "fp-doc-source", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "dlp", "fp-doc-source", mkey=converted_data["name"], vdom=vdom
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


def fortios_dlp(data, fos, check_mode):
    if data["dlp_fp_doc_source"]:
        resp = dlp_fp_doc_source(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("dlp_fp_doc_source"))
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
        "server_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "samba"}],
        },
        "server": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "period": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "none"},
                {"value": "daily"},
                {"value": "weekly"},
                {"value": "monthly"},
            ],
        },
        "vdom": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "mgmt"}, {"value": "current"}],
        },
        "scan_subdirectories": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "scan_on_creation": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "remove_deleted": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "keep_modified": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "username": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "password": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "file_path": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "file_pattern": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "sensitivity": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "tod_hour": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "tod_min": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "weekday": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "sunday"},
                {"value": "monday"},
                {"value": "tuesday"},
                {"value": "wednesday"},
                {"value": "thursday"},
                {"value": "friday"},
                {"value": "saturday"},
            ],
        },
        "date": {"v_range": [["v6.0.0", ""]], "type": "integer"},
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
        "dlp_fp_doc_source": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["dlp_fp_doc_source"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["dlp_fp_doc_source"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "dlp_fp_doc_source"
        )

        is_error, has_changed, result, diff = fortios_dlp(
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
