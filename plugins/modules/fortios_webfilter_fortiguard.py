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
module: fortios_webfilter_fortiguard
short_description: Configure FortiGuard Web Filter service in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify webfilter feature and fortiguard category.
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

    webfilter_fortiguard:
        description:
            - Configure FortiGuard Web Filter service.
        default: null
        type: dict
        suboptions:
            cache_mem_percent:
                description:
                    - Maximum percentage of available memory allocated to caching (1 - 15).
                type: int
            cache_mem_permille:
                description:
                    - Maximum permille of available memory allocated to caching (1 - 150).
                type: int
            cache_mode:
                description:
                    - Cache entry expiration mode.
                type: str
                choices:
                    - 'ttl'
                    - 'db-ver'
            cache_prefix_match:
                description:
                    - Enable/disable prefix matching in the cache.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            close_ports:
                description:
                    - Close ports used for HTTP/HTTPS override authentication and disable user overrides.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            embed_image:
                description:
                    - Enable/disable embedding images into replacement messages .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ovrd_auth_https:
                description:
                    - Enable/disable use of HTTPS for override authentication.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ovrd_auth_port:
                description:
                    - Port to use for FortiGuard Web Filter override authentication.
                type: int
            ovrd_auth_port_http:
                description:
                    - Port to use for FortiGuard Web Filter HTTP override authentication.
                type: int
            ovrd_auth_port_https:
                description:
                    - Port to use for FortiGuard Web Filter HTTPS override authentication in proxy mode.
                type: int
            ovrd_auth_port_https_flow:
                description:
                    - Port to use for FortiGuard Web Filter HTTPS override authentication in flow mode.
                type: int
            ovrd_auth_port_warning:
                description:
                    - Port to use for FortiGuard Web Filter Warning override authentication.
                type: int
            request_packet_size_limit:
                description:
                    - Limit size of URL request packets sent to FortiGuard server (0 for default).
                type: int
            warn_auth_https:
                description:
                    - Enable/disable use of HTTPS for warning and authentication.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure FortiGuard Web Filter service.
  fortinet.fortios.fortios_webfilter_fortiguard:
      vdom: "{{ vdom }}"
      webfilter_fortiguard:
          cache_mem_percent: "2"
          cache_mem_permille: "1"
          cache_mode: "ttl"
          cache_prefix_match: "enable"
          close_ports: "enable"
          embed_image: "enable"
          ovrd_auth_https: "enable"
          ovrd_auth_port: "32767"
          ovrd_auth_port_http: "8008"
          ovrd_auth_port_https: "8010"
          ovrd_auth_port_https_flow: "8015"
          ovrd_auth_port_warning: "8020"
          request_packet_size_limit: "0"
          warn_auth_https: "enable"
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


def filter_webfilter_fortiguard_data(json):
    option_list = [
        "cache_mem_percent",
        "cache_mem_permille",
        "cache_mode",
        "cache_prefix_match",
        "close_ports",
        "embed_image",
        "ovrd_auth_https",
        "ovrd_auth_port",
        "ovrd_auth_port_http",
        "ovrd_auth_port_https",
        "ovrd_auth_port_https_flow",
        "ovrd_auth_port_warning",
        "request_packet_size_limit",
        "warn_auth_https",
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


def webfilter_fortiguard(data, fos):
    state = None
    vdom = data["vdom"]
    webfilter_fortiguard_data = data["webfilter_fortiguard"]
    filtered_data = filter_webfilter_fortiguard_data(webfilter_fortiguard_data)
    converted_data = underscore_to_hyphen(filtered_data)

    return fos.set("webfilter", "fortiguard", data=converted_data, vdom=vdom)


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


def fortios_webfilter(data, fos):
    fos.do_member_operation("webfilter", "fortiguard")
    if data["webfilter_fortiguard"]:
        resp = webfilter_fortiguard(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("webfilter_fortiguard"))

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
        "cache_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "ttl"}, {"value": "db-ver"}],
        },
        "cache_prefix_match": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "cache_mem_permille": {"v_range": [["v7.4.0", ""]], "type": "integer"},
        "ovrd_auth_port_http": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ovrd_auth_port_https": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ovrd_auth_port_https_flow": {"v_range": [["v6.2.0", ""]], "type": "integer"},
        "ovrd_auth_port_warning": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ovrd_auth_https": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "warn_auth_https": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "close_ports": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "request_packet_size_limit": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "embed_image": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "cache_mem_percent": {"v_range": [["v6.0.0", "v7.2.4"]], "type": "integer"},
        "ovrd_auth_port": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "integer",
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
        "webfilter_fortiguard": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["webfilter_fortiguard"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["webfilter_fortiguard"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "webfilter_fortiguard"
        )

        is_error, has_changed, result, diff = fortios_webfilter(module.params, fos)

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
