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
module: fortios_log_fortiguard_setting
short_description: Configure logging to FortiCloud in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify log_fortiguard feature and setting category.
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

    log_fortiguard_setting:
        description:
            - Configure logging to FortiCloud.
        default: null
        type: dict
        suboptions:
            access_config:
                description:
                    - Enable/disable FortiCloud access to configuration and data.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            conn_timeout:
                description:
                    - FortiGate Cloud connection timeout in seconds.
                type: int
            enc_algorithm:
                description:
                    - Configure the level of SSL protection for secure communication with FortiCloud.
                type: str
                choices:
                    - 'high-medium'
                    - 'high'
                    - 'low'
            interface:
                description:
                    - Specify outgoing interface to reach server. Source system.interface.name.
                type: str
            interface_select_method:
                description:
                    - Specify how to select outgoing interface to reach server.
                type: str
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            max_log_rate:
                description:
                    - FortiCloud maximum log rate in MBps (0 = unlimited).
                type: int
            priority:
                description:
                    - Set log transmission priority.
                type: str
                choices:
                    - 'default'
                    - 'low'
            source_ip:
                description:
                    - Source IP address used to connect FortiCloud.
                type: str
            ssl_min_proto_version:
                description:
                    - Minimum supported protocol version for SSL/TLS connections .
                type: str
                choices:
                    - 'default'
                    - 'SSLv3'
                    - 'TLSv1'
                    - 'TLSv1-1'
                    - 'TLSv1-2'
                    - 'TLSv1-3'
            status:
                description:
                    - Enable/disable logging to FortiCloud.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            upload_day:
                description:
                    - Day of week to roll logs.
                type: str
            upload_interval:
                description:
                    - Frequency of uploading log files to FortiCloud.
                type: str
                choices:
                    - 'daily'
                    - 'weekly'
                    - 'monthly'
            upload_option:
                description:
                    - Configure how log messages are sent to FortiCloud.
                type: str
                choices:
                    - 'store-and-upload'
                    - 'realtime'
                    - '1-minute'
                    - '5-minute'
            upload_time:
                description:
                    - 'Time of day to roll logs (hh:mm).'
                type: str
"""

EXAMPLES = """
- name: Configure logging to FortiCloud.
  fortinet.fortios.fortios_log_fortiguard_setting:
      vdom: "{{ vdom }}"
      log_fortiguard_setting:
          access_config: "enable"
          conn_timeout: "10"
          enc_algorithm: "high-medium"
          interface: "<your_own_value> (source system.interface.name)"
          interface_select_method: "auto"
          max_log_rate: "0"
          priority: "default"
          source_ip: "84.230.14.43"
          ssl_min_proto_version: "default"
          status: "enable"
          upload_day: "<your_own_value>"
          upload_interval: "daily"
          upload_option: "store-and-upload"
          upload_time: "<your_own_value>"
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


def filter_log_fortiguard_setting_data(json):
    option_list = [
        "access_config",
        "conn_timeout",
        "enc_algorithm",
        "interface",
        "interface_select_method",
        "max_log_rate",
        "priority",
        "source_ip",
        "ssl_min_proto_version",
        "status",
        "upload_day",
        "upload_interval",
        "upload_option",
        "upload_time",
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


def log_fortiguard_setting(data, fos):
    state = None
    vdom = data["vdom"]
    log_fortiguard_setting_data = data["log_fortiguard_setting"]

    filtered_data = filter_log_fortiguard_setting_data(log_fortiguard_setting_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # pass post processed data to member operations
    data_copy = data.copy()
    data_copy["log_fortiguard_setting"] = converted_data
    fos.do_member_operation(
        "log.fortiguard",
        "setting",
        data_copy,
    )

    return fos.set("log.fortiguard", "setting", data=converted_data, vdom=vdom)


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


def fortios_log_fortiguard(data, fos):
    if data["log_fortiguard_setting"]:
        resp = log_fortiguard_setting(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("log_fortiguard_setting"))

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
        "upload_option": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "store-and-upload"},
                {"value": "realtime"},
                {"value": "1-minute"},
                {"value": "5-minute"},
            ],
        },
        "upload_interval": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "daily"}, {"value": "weekly"}, {"value": "monthly"}],
        },
        "upload_day": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "upload_time": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "priority": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "default"}, {"value": "low"}],
        },
        "max_log_rate": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "access_config": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "enc_algorithm": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "high-medium"}, {"value": "high"}, {"value": "low"}],
        },
        "ssl_min_proto_version": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "default"},
                {"value": "SSLv3"},
                {"value": "TLSv1"},
                {"value": "TLSv1-1"},
                {"value": "TLSv1-2"},
                {"value": "TLSv1-3", "v_range": [["v7.4.1", ""]]},
            ],
        },
        "conn_timeout": {
            "v_range": [["v6.0.0", "v6.0.0"], ["v6.0.11", ""]],
            "type": "integer",
        },
        "source_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "interface_select_method": {
            "v_range": [["v6.2.7", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "auto"}, {"value": "sdwan"}, {"value": "specify"}],
        },
        "interface": {
            "v_range": [["v6.2.7", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
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
        "log_fortiguard_setting": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["log_fortiguard_setting"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["log_fortiguard_setting"]["options"][attribute_name][
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
            fos, versioned_schema, "log_fortiguard_setting"
        )

        is_error, has_changed, result, diff = fortios_log_fortiguard(module.params, fos)

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
