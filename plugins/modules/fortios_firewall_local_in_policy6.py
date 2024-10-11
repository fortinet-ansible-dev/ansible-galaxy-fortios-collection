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
module: fortios_firewall_local_in_policy6
short_description: Configure user defined IPv6 local-in policies in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and local_in_policy6 category.
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
    - We highly recommend using your own value as the policyid instead of 0, while '0' is a special placeholder that allows the backend to assign the latest
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
    firewall_local_in_policy6:
        description:
            - Configure user defined IPv6 local-in policies.
        default: null
        type: dict
        suboptions:
            action:
                description:
                    - Action performed on traffic matching the policy .
                type: str
                choices:
                    - 'accept'
                    - 'deny'
            comments:
                description:
                    - Comment.
                type: str
            dstaddr:
                description:
                    - Destination address object from available options.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name firewall.addrgrp6.name system.external-resource.name.
                        required: true
                        type: str
            dstaddr_negate:
                description:
                    - When enabled dstaddr specifies what the destination address must NOT be.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            internet_service6_src:
                description:
                    - Enable/disable use of IPv6 Internet Services in source for this local-in policy.If enabled, source address is not used.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            internet_service6_src_custom:
                description:
                    - Custom IPv6 Internet Service source name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Custom Internet Service name. Source firewall.internet-service-custom.name.
                        required: true
                        type: str
            internet_service6_src_custom_group:
                description:
                    - Custom Internet Service6 source group name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Custom Internet Service6 group name. Source firewall.internet-service-custom-group.name.
                        required: true
                        type: str
            internet_service6_src_group:
                description:
                    - Internet Service6 source group name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Internet Service group name. Source firewall.internet-service-group.name.
                        required: true
                        type: str
            internet_service6_src_name:
                description:
                    - IPv6 Internet Service source name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Internet Service name. Source firewall.internet-service-name.name.
                        required: true
                        type: str
            internet_service6_src_negate:
                description:
                    - When enabled internet-service6-src specifies what the service must NOT be.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            intf:
                description:
                    - Incoming interface name from available options. Source system.zone.name system.interface.name.
                type: str
            intf_dict:
                description:
                    - Incoming interface name from available options.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source system.zone.name system.interface.name.
                        required: true
                        type: str
            logtraffic:
                description:
                    - Enable/disable local-in traffic logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            policyid:
                description:
                    - User defined local in policy ID. see <a href='#notes'>Notes</a>.
                required: true
                type: int
            schedule:
                description:
                    - Schedule object from available options. Source firewall.schedule.onetime.name firewall.schedule.recurring.name firewall.schedule.group
                      .name.
                type: str
            service:
                description:
                    - Service object from available options. Separate names with a space.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Service name. Source firewall.service.custom.name firewall.service.group.name.
                        required: true
                        type: str
            service_negate:
                description:
                    - When enabled service specifies what the service must NOT be.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            srcaddr:
                description:
                    - Source address object from available options.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name firewall.addrgrp6.name system.external-resource.name.
                        required: true
                        type: str
            srcaddr_negate:
                description:
                    - When enabled srcaddr specifies what the source address must NOT be.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            status:
                description:
                    - Enable/disable this local-in policy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            uuid:
                description:
                    - Universally Unique Identifier (UUID; automatically assigned but can be manually reset).
                type: str
            virtual_patch:
                description:
                    - Enable/disable the virtual patching feature.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure user defined IPv6 local-in policies.
  fortinet.fortios.fortios_firewall_local_in_policy6:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_local_in_policy6:
          action: "accept"
          comments: "<your_own_value>"
          dstaddr:
              -
                  name: "default_name_6 (source firewall.address6.name firewall.addrgrp6.name system.external-resource.name)"
          dstaddr_negate: "enable"
          internet_service6_src: "enable"
          internet_service6_src_custom:
              -
                  name: "default_name_10 (source firewall.internet-service-custom.name)"
          internet_service6_src_custom_group:
              -
                  name: "default_name_12 (source firewall.internet-service-custom-group.name)"
          internet_service6_src_group:
              -
                  name: "default_name_14 (source firewall.internet-service-group.name)"
          internet_service6_src_name:
              -
                  name: "default_name_16 (source firewall.internet-service-name.name)"
          internet_service6_src_negate: "enable"
          intf: "<your_own_value> (source system.zone.name system.interface.name)"
          intf_dict:
              -
                  name: "default_name_20 (source system.zone.name system.interface.name)"
          logtraffic: "enable"
          policyid: "<you_own_value>"
          schedule: "<your_own_value> (source firewall.schedule.onetime.name firewall.schedule.recurring.name firewall.schedule.group.name)"
          service:
              -
                  name: "default_name_25 (source firewall.service.custom.name firewall.service.group.name)"
          service_negate: "enable"
          srcaddr:
              -
                  name: "default_name_28 (source firewall.address6.name firewall.addrgrp6.name system.external-resource.name)"
          srcaddr_negate: "enable"
          status: "enable"
          uuid: "<your_own_value>"
          virtual_patch: "enable"
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


def filter_firewall_local_in_policy6_data(json):
    option_list = [
        "action",
        "comments",
        "dstaddr",
        "dstaddr_negate",
        "internet_service6_src",
        "internet_service6_src_custom",
        "internet_service6_src_custom_group",
        "internet_service6_src_group",
        "internet_service6_src_name",
        "internet_service6_src_negate",
        "intf",
        "intf_dict",
        "logtraffic",
        "policyid",
        "schedule",
        "service",
        "service_negate",
        "srcaddr",
        "srcaddr_negate",
        "status",
        "uuid",
        "virtual_patch",
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


def remap_attribute_name(data):
    speciallist = {"intf-dict": "intf"}

    if data in speciallist:
        return speciallist[data]
    return data


def remap_attribute_names(data):
    if isinstance(data, list):
        new_data = []
        for elem in data:
            elem = remap_attribute_names(elem)
            new_data.append(elem)
        data = new_data
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[remap_attribute_name(k)] = remap_attribute_names(v)
        data = new_data

    return data


def firewall_local_in_policy6(data, fos, check_mode=False):
    state = None
    vdom = data["vdom"]

    state = data["state"]

    firewall_local_in_policy6_data = data["firewall_local_in_policy6"]

    filtered_data = filter_firewall_local_in_policy6_data(
        firewall_local_in_policy6_data
    )
    converted_data = underscore_to_hyphen(filtered_data)
    converted_data = remap_attribute_names(converted_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("firewall", "local-in-policy6", filtered_data, vdom=vdom)
        current_data = fos.get("firewall", "local-in-policy6", vdom=vdom, mkey=mkey)
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
    data_copy["firewall_local_in_policy6"] = converted_data
    fos.do_member_operation(
        "firewall",
        "local-in-policy6",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("firewall", "local-in-policy6", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "firewall", "local-in-policy6", mkey=converted_data["policyid"], vdom=vdom
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
    if data["firewall_local_in_policy6"]:
        resp = firewall_local_in_policy6(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("firewall_local_in_policy6")
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
        "policyid": {"v_range": [["v6.0.0", ""]], "type": "integer", "required": True},
        "uuid": {"v_range": [["v6.4.0", ""]], "type": "string"},
        "intf_dict": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.4.2", ""]],
        },
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
        "srcaddr_negate": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
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
        "internet_service6_src": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "internet_service6_src_name": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.4.4", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.4.4", ""]],
        },
        "internet_service6_src_group": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.4.4", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.4.4", ""]],
        },
        "internet_service6_src_custom": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.4.4", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.4.4", ""]],
        },
        "internet_service6_src_custom_group": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.4.4", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.4.4", ""]],
        },
        "dstaddr_negate": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "action": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "accept"}, {"value": "deny"}],
        },
        "service": {
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
        "service_negate": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "internet_service6_src_negate": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "schedule": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "virtual_patch": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "logtraffic": {
            "v_range": [["v7.6.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "comments": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "intf": {"v_range": [["v6.0.0", "v7.4.1"]], "type": "string"},
    },
    "v_range": [["v6.0.0", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "policyid"
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
        "firewall_local_in_policy6": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_local_in_policy6"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_local_in_policy6"]["options"][attribute_name][
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
            fos, versioned_schema, "firewall_local_in_policy6"
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
