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
module: fortios_application_name
short_description: Configure application signatures in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify application feature and name category.
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
    application_name:
        description:
            - Configure application signatures.
        default: null
        type: dict
        suboptions:
            behavior:
                description:
                    - Application behavior.
                type: str
            category:
                description:
                    - Application category ID.
                type: int
            id:
                description:
                    - Application ID.
                type: int
            metadata:
                description:
                    - Meta data.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    metaid:
                        description:
                            - Meta ID.
                        type: int
                    valueid:
                        description:
                            - Value ID.
                        type: int
            name:
                description:
                    - Application name.
                required: true
                type: str
            parameter:
                description:
                    - Application parameter name.
                type: str
            parameters:
                description:
                    - Application parameters.
                type: list
                elements: dict
                suboptions:
                    default_value:
                        description:
                            - Parameter default value.
                        type: str
                    name:
                        description:
                            - Parameter name.
                        required: true
                        type: str
            popularity:
                description:
                    - Application popularity.
                type: int
            protocol:
                description:
                    - Application protocol.
                type: str
            risk:
                description:
                    - Application risk.
                type: int
            sub_category:
                description:
                    - Application sub-category ID.
                type: int
            technology:
                description:
                    - Application technology.
                type: str
            vendor:
                description:
                    - Application vendor.
                type: str
            weight:
                description:
                    - Application weight.
                type: int
"""

EXAMPLES = """
- name: Configure application signatures.
  fortinet.fortios.fortios_application_name:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      application_name:
          behavior: "<your_own_value>"
          category: "0"
          id: "5"
          metadata:
              -
                  id: "7"
                  metaid: "0"
                  valueid: "0"
          name: "default_name_10"
          parameter: "<your_own_value>"
          parameters:
              -
                  default_value: "<your_own_value>"
                  name: "default_name_14"
          popularity: "0"
          protocol: "<your_own_value>"
          risk: "0"
          sub_category: "127"
          technology: "<your_own_value>"
          vendor: "<your_own_value>"
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


def filter_application_name_data(json):
    option_list = [
        "behavior",
        "category",
        "id",
        "metadata",
        "name",
        "parameter",
        "parameters",
        "popularity",
        "protocol",
        "risk",
        "sub_category",
        "technology",
        "vendor",
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


def valid_attr_to_invalid_attr(data):
    speciallist = {"default value": "default_value"}

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


def application_name(data, fos, check_mode=False):
    state = None
    vdom = data["vdom"]

    state = data["state"]

    application_name_data = data["application_name"]

    filtered_data = filter_application_name_data(application_name_data)
    converted_data = underscore_to_hyphen(valid_attr_to_invalid_attrs(filtered_data))

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("application", "name", filtered_data, vdom=vdom)
        current_data = fos.get("application", "name", vdom=vdom, mkey=mkey)
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
    data_copy["application_name"] = converted_data
    fos.do_member_operation(
        "application",
        "name",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("application", "name", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("application", "name", mkey=converted_data["name"], vdom=vdom)
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


def fortios_application(data, fos, check_mode):
    if data["application_name"]:
        resp = application_name(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("application_name"))
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
        "name": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "string",
            "required": True,
        },
        "id": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
        "category": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
        "popularity": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
        "risk": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
        "weight": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
        "protocol": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "string",
        },
        "technology": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "string",
        },
        "behavior": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "string",
        },
        "vendor": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "string",
        },
        "parameters": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.4.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                    "required": True,
                },
                "default_value": {
                    "v_range": [["v6.4.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "string",
                },
            },
            "v_range": [["v6.4.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
        },
        "metadata": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "integer",
                    "required": True,
                },
                "metaid": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "integer",
                },
                "valueid": {
                    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
                    "type": "integer",
                },
            },
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
        },
        "sub_category": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "integer"},
        "parameter": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
    },
    "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
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
        "application_name": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["application_name"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["application_name"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "application_name"
        )

        is_error, has_changed, result, diff = fortios_application(
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
