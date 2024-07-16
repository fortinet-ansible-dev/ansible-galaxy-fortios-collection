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
module: fortios_firewall_on_demand_sniffer
short_description: Configure on-demand packet sniffer in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and on_demand_sniffer category.
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
    firewall_on_demand_sniffer:
        description:
            - Configure on-demand packet sniffer.
        default: null
        type: dict
        suboptions:
            advanced_filter:
                description:
                    - Advanced freeform filter that will be used over existing filter settings if set. Can only be used by super admin.
                type: str
            hosts:
                description:
                    - IPv4 or IPv6 hosts to filter in this traffic sniffer.
                type: list
                elements: dict
                suboptions:
                    host:
                        description:
                            - IPv4 or IPv6 host.
                        required: true
                        type: str
            interface:
                description:
                    - Interface name that on-demand packet sniffer will take place. Source system.interface.name.
                type: str
            max_packet_count:
                description:
                    - Maximum number of packets to capture per on-demand packet sniffer.
                type: int
            name:
                description:
                    - On-demand packet sniffer name.
                required: true
                type: str
            non_ip_packet:
                description:
                    - Include non-IP packets.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ports:
                description:
                    - Ports to filter for in this traffic sniffer.
                type: list
                elements: dict
                suboptions:
                    port:
                        description:
                            - Port to filter in this traffic sniffer. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
            protocols:
                description:
                    - Protocols to filter in this traffic sniffer.
                type: list
                elements: dict
                suboptions:
                    protocol:
                        description:
                            - Integer value for the protocol type as defined by IANA (0 - 255). see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
"""

EXAMPLES = """
- name: Configure on-demand packet sniffer.
  fortinet.fortios.fortios_firewall_on_demand_sniffer:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_on_demand_sniffer:
          advanced_filter: "<your_own_value>"
          hosts:
              -
                  host: "myhostname"
          interface: "<your_own_value> (source system.interface.name)"
          max_packet_count: "0"
          name: "default_name_8"
          non_ip_packet: "enable"
          ports:
              -
                  port: "<you_own_value>"
          protocols:
              -
                  protocol: "<you_own_value>"
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


def filter_firewall_on_demand_sniffer_data(json):
    option_list = [
        "advanced_filter",
        "hosts",
        "interface",
        "max_packet_count",
        "name",
        "non_ip_packet",
        "ports",
        "protocols",
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


def firewall_on_demand_sniffer(data, fos):
    state = None
    vdom = data["vdom"]

    state = data["state"]

    firewall_on_demand_sniffer_data = data["firewall_on_demand_sniffer"]
    filtered_data = filter_firewall_on_demand_sniffer_data(
        firewall_on_demand_sniffer_data
    )
    converted_data = underscore_to_hyphen(filtered_data)

    if state == "present" or state is True:
        return fos.set("firewall", "on-demand-sniffer", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "firewall", "on-demand-sniffer", mkey=converted_data["name"], vdom=vdom
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


def fortios_firewall(data, fos):
    fos.do_member_operation("firewall", "on-demand-sniffer")
    if data["firewall_on_demand_sniffer"]:
        resp = firewall_on_demand_sniffer(data, fos)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("firewall_on_demand_sniffer")
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
        "name": {"v_range": [["v7.4.4", ""]], "type": "string", "required": True},
        "interface": {"v_range": [["v7.4.4", ""]], "type": "string"},
        "max_packet_count": {"v_range": [["v7.4.4", ""]], "type": "integer"},
        "hosts": {
            "type": "list",
            "elements": "dict",
            "children": {
                "host": {
                    "v_range": [["v7.4.4", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.4.4", ""]],
        },
        "ports": {
            "type": "list",
            "elements": "dict",
            "children": {
                "port": {
                    "v_range": [["v7.4.4", ""]],
                    "type": "integer",
                    "required": True,
                }
            },
            "v_range": [["v7.4.4", ""]],
        },
        "protocols": {
            "type": "list",
            "elements": "dict",
            "children": {
                "protocol": {
                    "v_range": [["v7.4.4", ""]],
                    "type": "integer",
                    "required": True,
                }
            },
            "v_range": [["v7.4.4", ""]],
        },
        "non_ip_packet": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "advanced_filter": {"v_range": [["v7.4.4", ""]], "type": "string"},
    },
    "v_range": [["v7.4.4", ""]],
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
        "firewall_on_demand_sniffer": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_on_demand_sniffer"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_on_demand_sniffer"]["options"][attribute_name][
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
            fos, versioned_schema, "firewall_on_demand_sniffer"
        )

        is_error, has_changed, result, diff = fortios_firewall(module.params, fos)

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
