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
module: fortios_casb_profile
short_description: Configure CASB profile in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify casb feature and profile category.
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
    casb_profile:
        description:
            - Configure CASB profile.
        default: null
        type: dict
        suboptions:
            comment:
                description:
                    - Comment.
                type: str
            name:
                description:
                    - CASB profile name.
                required: true
                type: str
            saas_application:
                description:
                    - CASB profile SaaS application.
                type: list
                elements: dict
                suboptions:
                    access_rule:
                        description:
                            - CASB profile access rule.
                        type: list
                        elements: dict
                        suboptions:
                            action:
                                description:
                                    - CASB access rule action.
                                type: str
                                choices:
                                    - 'monitor'
                                    - 'bypass'
                                    - 'block'
                            bypass:
                                description:
                                    - CASB bypass options.
                                type: list
                                elements: str
                                choices:
                                    - 'av'
                                    - 'dlp'
                                    - 'web-filter'
                                    - 'file-filter'
                                    - 'video-filter'
                            name:
                                description:
                                    - CASB access rule activity name. Source casb.user-activity.name.
                                required: true
                                type: str
                    custom_control:
                        description:
                            - CASB profile custom control.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - CASB custom control user activity name. Source casb.user-activity.name.
                                required: true
                                type: str
                            option:
                                description:
                                    - CASB custom control option.
                                type: list
                                elements: dict
                                suboptions:
                                    name:
                                        description:
                                            - CASB custom control option name.
                                        required: true
                                        type: str
                                    user_input:
                                        description:
                                            - CASB custom control user input.
                                        type: list
                                        elements: dict
                                        suboptions:
                                            value:
                                                description:
                                                    - user input value.
                                                required: true
                                                type: str
                    domain_control:
                        description:
                            - Enable/disable domain control.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    domain_control_domains:
                        description:
                            - CASB profile domain control domains.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Domain control domain name.
                                required: true
                                type: str
                    log:
                        description:
                            - Enable/disable log settings.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    name:
                        description:
                            - CASB profile SaaS application name. Source casb.saas-application.name.
                        required: true
                        type: str
                    safe_search:
                        description:
                            - Enable/disable safe search.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    safe_search_control:
                        description:
                            - CASB profile safe search control.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Safe search control name.
                                required: true
                                type: str
                    status:
                        description:
                            - Enable/disable setting.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    tenant_control:
                        description:
                            - Enable/disable tenant control.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    tenant_control_tenants:
                        description:
                            - CASB profile tenant control tenants.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Tenant control tenants name.
                                required: true
                                type: str
"""

EXAMPLES = """
- name: Configure CASB profile.
  fortinet.fortios.fortios_casb_profile:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      casb_profile:
          comment: "Comment."
          name: "default_name_4"
          saas_application:
              -
                  access_rule:
                      -
                          action: "monitor"
                          bypass: "av"
                          name: "default_name_9 (source casb.user-activity.name)"
                  custom_control:
                      -
                          name: "default_name_11 (source casb.user-activity.name)"
                          option:
                              -
                                  name: "default_name_13"
                                  user_input:
                                      -
                                          value: "<your_own_value>"
                  domain_control: "enable"
                  domain_control_domains:
                      -
                          name: "default_name_18"
                  log: "enable"
                  name: "default_name_20 (source casb.saas-application.name)"
                  safe_search: "enable"
                  safe_search_control:
                      -
                          name: "default_name_23"
                  status: "enable"
                  tenant_control: "enable"
                  tenant_control_tenants:
                      -
                          name: "default_name_27"
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


def filter_casb_profile_data(json):
    option_list = ["comment", "name", "saas_application"]

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
        ["saas_application", "access_rule", "bypass"],
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


def casb_profile(data, fos):
    state = None
    vdom = data["vdom"]

    state = data["state"]

    casb_profile_data = data["casb_profile"]
    casb_profile_data = flatten_multilists_attributes(casb_profile_data)
    filtered_data = filter_casb_profile_data(casb_profile_data)
    converted_data = underscore_to_hyphen(filtered_data)

    if state == "present" or state is True:
        return fos.set("casb", "profile", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("casb", "profile", mkey=converted_data["name"], vdom=vdom)
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


def fortios_casb(data, fos):
    fos.do_member_operation("casb", "profile")
    if data["casb_profile"]:
        resp = casb_profile(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("casb_profile"))

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
        "name": {"v_range": [["v7.4.1", ""]], "type": "string", "required": True},
        "comment": {"v_range": [["v7.4.4", ""]], "type": "string"},
        "saas_application": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "required": True,
                },
                "status": {
                    "v_range": [["v7.4.2", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "safe_search": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "safe_search_control": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.4.1", ""]],
                },
                "tenant_control": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "tenant_control_tenants": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.4.1", ""]],
                },
                "domain_control": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "domain_control_domains": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.4.1", ""]],
                },
                "log": {
                    "v_range": [["v7.4.1", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "access_rule": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "action": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "string",
                            "options": [
                                {"value": "monitor"},
                                {"value": "bypass"},
                                {"value": "block"},
                            ],
                        },
                        "bypass": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "list",
                            "options": [
                                {"value": "av"},
                                {"value": "dlp"},
                                {"value": "web-filter"},
                                {"value": "file-filter"},
                                {"value": "video-filter"},
                            ],
                            "multiple_values": True,
                            "elements": "str",
                        },
                    },
                    "v_range": [["v7.4.1", ""]],
                },
                "custom_control": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.4.1", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "option": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "name": {
                                    "v_range": [["v7.4.1", ""]],
                                    "type": "string",
                                    "required": True,
                                },
                                "user_input": {
                                    "type": "list",
                                    "elements": "dict",
                                    "children": {
                                        "value": {
                                            "v_range": [["v7.4.1", ""]],
                                            "type": "string",
                                            "required": True,
                                        }
                                    },
                                    "v_range": [["v7.4.1", ""]],
                                },
                            },
                            "v_range": [["v7.4.1", ""]],
                        },
                    },
                    "v_range": [["v7.4.1", ""]],
                },
            },
            "v_range": [["v7.4.1", ""]],
        },
    },
    "v_range": [["v7.4.1", ""]],
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
        "casb_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["casb_profile"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["casb_profile"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "casb_profile"
        )

        is_error, has_changed, result, diff = fortios_casb(module.params, fos)

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
