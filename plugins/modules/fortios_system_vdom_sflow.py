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
module: fortios_system_vdom_sflow
short_description: Configure sFlow per VDOM to add or change the IP address and UDP port that FortiGate sFlow agents in this VDOM use to send sFlow datagrams
   to an sFlow collector in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and vdom_sflow category.
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

    system_vdom_sflow:
        description:
            - Configure sFlow per VDOM to add or change the IP address and UDP port that FortiGate sFlow agents in this VDOM use to send sFlow datagrams to an
               sFlow collector.
        default: null
        type: dict
        suboptions:
            collector_ip:
                description:
                    - IP address of the sFlow collector that sFlow agents added to interfaces in this VDOM send sFlow datagrams to .
                type: str
            collector_port:
                description:
                    - UDP port number used for sending sFlow datagrams (configure only if required by your sFlow collector or your network configuration) (0 -
                       65535).
                type: int
            collectors:
                description:
                    - sFlow collectors.
                type: list
                elements: dict
                suboptions:
                    collector_ip:
                        description:
                            - IP addresses of the sFlow collectors that sFlow agents added to interfaces in this VDOM send sFlow datagrams to.
                        type: str
                    collector_port:
                        description:
                            - UDP port number used for sending sFlow datagrams (configure only if required by your sFlow collector or your network
                               configuration) (0 - 65535).
                        type: int
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
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
                    source_ip:
                        description:
                            - Source IP address for sFlow agent.
                        type: str
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
            source_ip:
                description:
                    - Source IP address for sFlow agent.
                type: str
            vdom_sflow:
                description:
                    - Enable/disable the sFlow configuration for the current VDOM.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure sFlow per VDOM to add or change the IP address and UDP port that FortiGate sFlow agents in this VDOM use to send sFlow datagrams to an sFlow
   collector.
  fortinet.fortios.fortios_system_vdom_sflow:
      vdom: "{{ vdom }}"
      system_vdom_sflow:
          collector_ip: "<your_own_value>"
          collector_port: "6343"
          collectors:
              -
                  collector_ip: "<your_own_value>"
                  collector_port: "6343"
                  id: "8"
                  interface: "<your_own_value> (source system.interface.name)"
                  interface_select_method: "auto"
                  source_ip: "84.230.14.43"
          interface: "<your_own_value> (source system.interface.name)"
          interface_select_method: "auto"
          source_ip: "84.230.14.43"
          vdom_sflow: "enable"
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


def filter_system_vdom_sflow_data(json):
    option_list = [
        "collector_ip",
        "collector_port",
        "collectors",
        "interface",
        "interface_select_method",
        "source_ip",
        "vdom_sflow",
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


def system_vdom_sflow(data, fos):
    state = None
    vdom = data["vdom"]
    system_vdom_sflow_data = data["system_vdom_sflow"]

    filtered_data = filter_system_vdom_sflow_data(system_vdom_sflow_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # pass post processed data to member operations
    data_copy = data.copy()
    data_copy["system_vdom_sflow"] = converted_data
    fos.do_member_operation(
        "system",
        "vdom-sflow",
        data_copy,
    )

    return fos.set("system", "vdom-sflow", data=converted_data, vdom=vdom)


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
    if data["system_vdom_sflow"]:
        resp = system_vdom_sflow(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_vdom_sflow"))

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
        "vdom_sflow": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "collectors": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "integer",
                    "required": True,
                },
                "collector_ip": {"v_range": [["v7.4.2", ""]], "type": "string"},
                "collector_port": {"v_range": [["v7.4.2", ""]], "type": "integer"},
                "source_ip": {"v_range": [["v7.4.2", ""]], "type": "string"},
                "interface_select_method": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [
                        {"value": "auto"},
                        {"value": "sdwan"},
                        {"value": "specify"},
                    ],
                },
                "interface": {"v_range": [["v7.4.2", ""]], "type": "string"},
            },
            "v_range": [["v7.4.2", ""]],
        },
        "collector_ip": {"v_range": [["v6.0.0", "v7.4.1"]], "type": "string"},
        "collector_port": {"v_range": [["v6.0.0", "v7.4.1"]], "type": "integer"},
        "source_ip": {"v_range": [["v6.0.0", "v7.4.1"]], "type": "string"},
        "interface_select_method": {
            "v_range": [["v7.0.1", "v7.4.1"]],
            "type": "string",
            "options": [{"value": "auto"}, {"value": "sdwan"}, {"value": "specify"}],
        },
        "interface": {"v_range": [["v7.0.1", "v7.4.1"]], "type": "string"},
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
        "system_vdom_sflow": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_vdom_sflow"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_vdom_sflow"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_vdom_sflow"
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
