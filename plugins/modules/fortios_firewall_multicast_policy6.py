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
module: fortios_firewall_multicast_policy6
short_description: Configure IPv6 multicast NAT policies in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and multicast_policy6 category.
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
    firewall_multicast_policy6:
        description:
            - Configure IPv6 multicast NAT policies.
        default: null
        type: dict
        suboptions:
            action:
                description:
                    - Accept or deny traffic matching the policy.
                type: str
                choices:
                    - 'accept'
                    - 'deny'
            auto_asic_offload:
                description:
                    - Enable/disable offloading policy traffic for hardware acceleration.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            comments:
                description:
                    - Comment.
                type: str
            dstaddr:
                description:
                    - IPv6 destination address name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.multicast-address6.name.
                        required: true
                        type: str
            dstintf:
                description:
                    - IPv6 destination interface name. Source system.interface.name system.zone.name.
                type: str
            end_port:
                description:
                    - Integer value for ending TCP/UDP/SCTP destination port in range (1 - 65535).
                type: int
            id:
                description:
                    - Policy ID (0 - 4294967294). see <a href='#notes'>Notes</a>.
                required: true
                type: int
            ips_sensor:
                description:
                    - Name of an existing IPS sensor. Source ips.sensor.name.
                type: str
            logtraffic:
                description:
                    - Enable or disable logging. Log all sessions or security profile sessions.
                type: str
                choices:
                    - 'all'
                    - 'utm'
                    - 'disable'
                    - 'enable'
            name:
                description:
                    - Policy name.
                type: str
            protocol:
                description:
                    - Integer value for the protocol type as defined by IANA (0 - 255).
                type: int
            srcaddr:
                description:
                    - IPv6 source address name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name firewall.addrgrp6.name.
                        required: true
                        type: str
            srcintf:
                description:
                    - IPv6 source interface name. Source system.interface.name system.zone.name.
                type: str
            start_port:
                description:
                    - Integer value for starting TCP/UDP/SCTP destination port in range (1 - 65535).
                type: int
            status:
                description:
                    - Enable/disable this policy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            utm_status:
                description:
                    - Enable to add an IPS security profile to the policy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            uuid:
                description:
                    - Universally Unique Identifier (UUID; automatically assigned but can be manually reset).
                type: str
"""

EXAMPLES = """
- name: Configure IPv6 multicast NAT policies.
  fortinet.fortios.fortios_firewall_multicast_policy6:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_multicast_policy6:
          action: "accept"
          auto_asic_offload: "enable"
          comments: "<your_own_value>"
          dstaddr:
              -
                  name: "default_name_7 (source firewall.multicast-address6.name)"
          dstintf: "<your_own_value> (source system.interface.name system.zone.name)"
          end_port: "65535"
          id: "10"
          ips_sensor: "<your_own_value> (source ips.sensor.name)"
          logtraffic: "all"
          name: "default_name_13"
          protocol: "0"
          srcaddr:
              -
                  name: "default_name_16 (source firewall.address6.name firewall.addrgrp6.name)"
          srcintf: "<your_own_value> (source system.interface.name system.zone.name)"
          start_port: "1"
          status: "enable"
          utm_status: "enable"
          uuid: "<your_own_value>"
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


def filter_firewall_multicast_policy6_data(json):
    option_list = [
        "action",
        "auto_asic_offload",
        "comments",
        "dstaddr",
        "dstintf",
        "end_port",
        "id",
        "ips_sensor",
        "logtraffic",
        "name",
        "protocol",
        "srcaddr",
        "srcintf",
        "start_port",
        "status",
        "utm_status",
        "uuid",
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


def firewall_multicast_policy6(data, fos, check_mode=False):
    state = None
    vdom = data["vdom"]

    state = data["state"]

    firewall_multicast_policy6_data = data["firewall_multicast_policy6"]

    filtered_data = filter_firewall_multicast_policy6_data(
        firewall_multicast_policy6_data
    )
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("firewall", "multicast-policy6", filtered_data, vdom=vdom)
        current_data = fos.get("firewall", "multicast-policy6", vdom=vdom, mkey=mkey)
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
    data_copy["firewall_multicast_policy6"] = converted_data
    fos.do_member_operation(
        "firewall",
        "multicast-policy6",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("firewall", "multicast-policy6", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "firewall", "multicast-policy6", mkey=converted_data["id"], vdom=vdom
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


def fortios_firewall(data, fos, check_mode):
    if data["firewall_multicast_policy6"]:
        resp = firewall_multicast_policy6(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("firewall_multicast_policy6")
        )
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
        "id": {"v_range": [["v6.0.0", ""]], "type": "integer", "required": True},
        "uuid": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "name": {"v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]], "type": "string"},
        "srcintf": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dstintf": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "srcaddr": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "dstaddr": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "action": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "accept"}, {"value": "deny"}],
        },
        "protocol": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "start_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "end_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "utm_status": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ips_sensor": {"v_range": [["v7.4.2", ""]], "type": "string"},
        "logtraffic": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "all", "v_range": [["v7.4.2", ""]]},
                {"value": "utm", "v_range": [["v7.4.2", ""]]},
                {"value": "disable"},
                {"value": "enable", "v_range": [["v6.0.0", "v7.4.1"]]},
            ],
        },
        "auto_asic_offload": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "comments": {"v_range": [["v7.0.0", ""]], "type": "string"},
    },
    "v_range": [["v6.0.0", ""]],
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
        "firewall_multicast_policy6": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_multicast_policy6"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_multicast_policy6"]["options"][attribute_name][
                "required"
            ] = True

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
            fos, versioned_schema, "firewall_multicast_policy6"
        )

        is_error, has_changed, result, diff = fortios_firewall(
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
