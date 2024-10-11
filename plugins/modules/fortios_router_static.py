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
module: fortios_router_static
short_description: Configure IPv4 static routing tables in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify router feature and static category.
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
    - We highly recommend using your own value as the seq_num instead of 0, while '0' is a special placeholder that allows the backend to assign the latest
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
    router_static:
        description:
            - Configure IPv4 static routing tables.
        default: null
        type: dict
        suboptions:
            bfd:
                description:
                    - Enable/disable Bidirectional Forwarding Detection (BFD).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            blackhole:
                description:
                    - Enable/disable black hole.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            comment:
                description:
                    - Optional comments.
                type: str
            device:
                description:
                    - Gateway out interface or tunnel. Source system.interface.name.
                type: str
            distance:
                description:
                    - Administrative distance (1 - 255).
                type: int
            dst:
                description:
                    - Destination IP and mask for this route.
                type: str
            dstaddr:
                description:
                    - Name of firewall address or address group. Source firewall.address.name firewall.addrgrp.name.
                type: str
            dynamic_gateway:
                description:
                    - Enable use of dynamic gateway retrieved from a DHCP or PPP server.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gateway:
                description:
                    - Gateway IP for this route.
                type: str
            internet_service:
                description:
                    - Application ID in the Internet service database. Source firewall.internet-service.id.
                type: int
            internet_service_custom:
                description:
                    - Application name in the Internet service custom database. Source firewall.internet-service-custom.name.
                type: str
            link_monitor_exempt:
                description:
                    - Enable/disable withdrawal of this static route when link monitor or health check is down.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            preferred_source:
                description:
                    - Preferred source IP for this route.
                type: str
            priority:
                description:
                    - Administrative priority (1 - 65535).
                type: int
            sdwan:
                description:
                    - Enable/disable egress through SD-WAN.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sdwan_zone:
                description:
                    - Choose SD-WAN Zone.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - SD-WAN zone name. Source system.sdwan.zone.name.
                        required: true
                        type: str
            seq_num:
                description:
                    - Sequence number. see <a href='#notes'>Notes</a>.
                required: true
                type: int
            src:
                description:
                    - Source prefix for this route.
                type: str
            status:
                description:
                    - Enable/disable this static route.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            tag:
                description:
                    - Route tag.
                type: int
            virtual_wan_link:
                description:
                    - Enable/disable egress through the virtual-wan-link.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            vrf:
                description:
                    - Virtual Routing Forwarding ID.
                type: int
            weight:
                description:
                    - Administrative weight (0 - 255).
                type: int
"""

EXAMPLES = """
- name: Configure IPv4 static routing tables.
  fortinet.fortios.fortios_router_static:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      router_static:
          bfd: "enable"
          blackhole: "enable"
          comment: "Optional comments."
          device: "<your_own_value> (source system.interface.name)"
          distance: "10"
          dst: "<your_own_value>"
          dstaddr: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
          dynamic_gateway: "enable"
          gateway: "<your_own_value>"
          internet_service: "0"
          internet_service_custom: "<your_own_value> (source firewall.internet-service-custom.name)"
          link_monitor_exempt: "enable"
          preferred_source: "<your_own_value>"
          priority: "1"
          sdwan: "enable"
          sdwan_zone:
              -
                  name: "default_name_19 (source system.sdwan.zone.name)"
          seq_num: "<you_own_value>"
          src: "<your_own_value>"
          status: "enable"
          tag: "0"
          virtual_wan_link: "enable"
          vrf: "unspecified"
          weight: "0"
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


def filter_router_static_data(json):
    option_list = [
        "bfd",
        "blackhole",
        "comment",
        "device",
        "distance",
        "dst",
        "dstaddr",
        "dynamic_gateway",
        "gateway",
        "internet_service",
        "internet_service_custom",
        "link_monitor_exempt",
        "preferred_source",
        "priority",
        "sdwan",
        "sdwan_zone",
        "seq_num",
        "src",
        "status",
        "tag",
        "virtual_wan_link",
        "vrf",
        "weight",
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


def router_static(data, fos, check_mode=False):
    state = None
    vdom = data["vdom"]

    state = data["state"]

    router_static_data = data["router_static"]

    filtered_data = filter_router_static_data(router_static_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("router", "static", filtered_data, vdom=vdom)
        current_data = fos.get("router", "static", vdom=vdom, mkey=mkey)
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
    data_copy["router_static"] = converted_data
    fos.do_member_operation(
        "router",
        "static",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("router", "static", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("router", "static", mkey=converted_data["seq-num"], vdom=vdom)
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


def fortios_router(data, fos, check_mode):
    if data["router_static"]:
        resp = router_static(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("router_static"))
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
        "seq_num": {"v_range": [["v6.0.0", ""]], "type": "integer", "required": True},
        "status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dst": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "src": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "gateway": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "preferred_source": {"v_range": [["v7.4.0", ""]], "type": "string"},
        "distance": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "weight": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "priority": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "device": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "comment": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "blackhole": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dynamic_gateway": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sdwan_zone": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.0.1", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.0.1", ""]],
        },
        "dstaddr": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "internet_service": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "internet_service_custom": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "link_monitor_exempt": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "tag": {"v_range": [["v7.2.4", ""]], "type": "integer"},
        "vrf": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "bfd": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sdwan": {
            "v_range": [["v6.4.0", "v7.0.0"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "virtual_wan_link": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
    },
    "v_range": [["v6.0.0", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "seq-num"
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
        "router_static": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["router_static"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["router_static"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "router_static"
        )

        is_error, has_changed, result, diff = fortios_router(
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
