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
module: fortios_system_ntp
short_description: Configure system NTP information in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and ntp category.
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

    system_ntp:
        description:
            - Configure system NTP information.
        default: null
        type: dict
        suboptions:
            authentication:
                description:
                    - Enable/disable authentication.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            interface:
                description:
                    - FortiGate interface(s) with NTP server mode enabled. Devices on your network can contact these interfaces for NTP services.
                type: list
                elements: dict
                suboptions:
                    interface_name:
                        description:
                            - Interface name. Source system.interface.name.
                        required: true
                        type: str
            key:
                description:
                    - Key for authentication.
                type: str
            key_id:
                description:
                    - Key ID for authentication.
                type: int
            key_type:
                description:
                    - Key type for authentication (MD5, SHA1, SHA256).
                type: str
                choices:
                    - 'MD5'
                    - 'SHA1'
                    - 'SHA256'
            ntpserver:
                description:
                    - Configure the FortiGate to connect to any available third-party NTP server.
                type: list
                elements: dict
                suboptions:
                    authentication:
                        description:
                            - Enable/disable authentication.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    id:
                        description:
                            - NTP server ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
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
                    ip_type:
                        description:
                            - Choose to connect to IPv4 or/and IPv6 NTP server.
                        type: str
                        choices:
                            - 'IPv6'
                            - 'IPv4'
                            - 'Both'
                    key:
                        description:
                            - Key for MD5(NTPv3)/SHA1(NTPv4)/SHA256(NTPv4) authentication.
                        type: str
                    key_id:
                        description:
                            - Key ID for authentication.
                        type: int
                    key_type:
                        description:
                            - Select NTP authentication type.
                        type: str
                        choices:
                            - 'MD5'
                            - 'SHA1'
                            - 'SHA256'
                    ntpv3:
                        description:
                            - Enable to use NTPv3 instead of NTPv4.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    server:
                        description:
                            - IP address or hostname of the NTP Server.
                        type: str
            ntpsync:
                description:
                    - Enable/disable setting the FortiGate system time by synchronizing with an NTP Server.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            server_mode:
                description:
                    - Enable/disable FortiGate NTP Server Mode. Your FortiGate becomes an NTP server for other devices on your network. The FortiGate relays
                       NTP requests to its configured NTP server.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            source_ip:
                description:
                    - Source IP address for communication to the NTP server.
                type: str
            source_ip6:
                description:
                    - Source IPv6 address for communication to the NTP server.
                type: str
            syncinterval:
                description:
                    - NTP synchronization interval (1 - 1440 min).
                type: int
            type:
                description:
                    - Use the FortiGuard NTP server or any other available NTP Server.
                type: str
                choices:
                    - 'fortiguard'
                    - 'custom'
"""

EXAMPLES = """
- name: Configure system NTP information.
  fortinet.fortios.fortios_system_ntp:
      vdom: "{{ vdom }}"
      system_ntp:
          authentication: "enable"
          interface:
              -
                  interface_name: "<your_own_value> (source system.interface.name)"
          key: "<your_own_value>"
          key_id: "0"
          key_type: "MD5"
          ntpserver:
              -
                  authentication: "enable"
                  id: "11"
                  interface: "<your_own_value> (source system.interface.name)"
                  interface_select_method: "auto"
                  ip_type: "IPv6"
                  key: "<your_own_value>"
                  key_id: "0"
                  key_type: "MD5"
                  ntpv3: "enable"
                  server: "192.168.100.40"
          ntpsync: "enable"
          server_mode: "enable"
          source_ip: "84.230.14.43"
          source_ip6: "<your_own_value>"
          syncinterval: "60"
          type: "fortiguard"
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


def filter_system_ntp_data(json):
    option_list = [
        "authentication",
        "interface",
        "key",
        "key_id",
        "key_type",
        "ntpserver",
        "ntpsync",
        "server_mode",
        "source_ip",
        "source_ip6",
        "syncinterval",
        "type",
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


def system_ntp(data, fos):
    state = None
    vdom = data["vdom"]
    system_ntp_data = data["system_ntp"]

    filtered_data = filter_system_ntp_data(system_ntp_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # pass post processed data to member operations
    data_copy = data.copy()
    data_copy["system_ntp"] = converted_data
    fos.do_member_operation(
        "system",
        "ntp",
        data_copy,
    )

    return fos.set("system", "ntp", data=converted_data, vdom=vdom)


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
    if data["system_ntp"]:
        resp = system_ntp(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_ntp"))

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
        "ntpsync": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "fortiguard"}, {"value": "custom"}],
        },
        "syncinterval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ntpserver": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "server": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "ntpv3": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "authentication": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "key_type": {
                    "v_range": [["v7.4.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "MD5"},
                        {"value": "SHA1"},
                        {"value": "SHA256"},
                    ],
                },
                "key": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "key_id": {"v_range": [["v6.0.0", ""]], "type": "integer"},
                "ip_type": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [
                        {"value": "IPv6"},
                        {"value": "IPv4"},
                        {"value": "Both"},
                    ],
                },
                "interface_select_method": {
                    "v_range": [
                        ["v6.2.0", "v6.2.0"],
                        ["v6.2.5", "v6.4.0"],
                        ["v6.4.4", ""],
                    ],
                    "type": "string",
                    "options": [
                        {"value": "auto"},
                        {"value": "sdwan"},
                        {"value": "specify"},
                    ],
                },
                "interface": {
                    "v_range": [
                        ["v6.2.0", "v6.2.0"],
                        ["v6.2.5", "v6.4.0"],
                        ["v6.4.4", ""],
                    ],
                    "type": "string",
                },
            },
            "v_range": [["v6.0.0", ""]],
        },
        "source_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "source_ip6": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "server_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "authentication": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "key_type": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [
                {"value": "MD5"},
                {"value": "SHA1"},
                {"value": "SHA256", "v_range": [["v7.4.4", ""]]},
            ],
        },
        "key": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "key_id": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "interface": {
            "type": "list",
            "elements": "dict",
            "children": {
                "interface_name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
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
        "system_ntp": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_ntp"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_ntp"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_ntp"
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
