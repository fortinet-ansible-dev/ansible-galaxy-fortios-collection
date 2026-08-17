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
module: fortios_llm_proxy
short_description: Configure LLM Proxy in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify llm feature and proxy category.
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
    - ansible>=2.16
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
    llm_proxy:
        description:
            - Configure LLM Proxy.
        default: null
        type: dict
        suboptions:
            hostname:
                description:
                    - hostname. Source firewall.address.name.
                type: str
            incoming_http_port:
                description:
                    - LLM Proxy HTTP incoming port.
                type: int
            incoming_https_port:
                description:
                    - LLM Proxy HTTPS incoming port.
                type: int
            incoming_ip:
                description:
                    - LLM Proxy incoming IP.
                type: str
            incoming_ip6:
                description:
                    - LLM Proxy incoming IPv6.
                type: str
            interface:
                description:
                    - Name of the interfaces to use LLM Proxy.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Interface list. Source system.interface.name.
                        required: true
                        type: str
            ipv6_status:
                description:
                    - Enable/disable the LLM proxy on IPv6.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            name:
                description:
                    - LLM Proxy name.
                required: true
                type: str
            protocol:
                description:
                    - Supported protocols.
                type: list
                elements: str
                choices:
                    - 'http'
                    - 'https'
            srv_pool_max_concurrent_request:
                description:
                    - Maximum number of concurrent requests that a server can handle .
                type: int
            srv_pool_max_request:
                description:
                    - Maximum number of requests that a server can handle before disconnecting sessions .
                type: int
            srv_pool_ttl:
                description:
                    - Time-to-live for idle connections to servers.
                type: int
            ssl_certificate:
                description:
                    - Name of the certificates to use for SSL handshake.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Certificate list. Source vpn.certificate.local.name.
                        required: true
                        type: str
            ssl_max_version:
                description:
                    - Highest SSL/TLS version acceptable from a client.
                type: str
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            ssl_min_version:
                description:
                    - Lowest SSL/TLS version acceptable from a client.
                type: str
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            status:
                description:
                    - Enable/disable the LLM proxy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""
EXAMPLES = """
- name: Configure LLM Proxy.
  fortinet.fortios.fortios_llm_proxy:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      llm_proxy:
          hostname: "myhostname (source firewall.address.name)"
          incoming_http_port: "8098"
          incoming_https_port: "8099"
          incoming_ip: "<your_own_value>"
          incoming_ip6: "<your_own_value>"
          interface:
              -
                  name: "default_name_9 (source system.interface.name)"
          ipv6_status: "enable"
          name: "default_name_11"
          protocol: "http"
          srv_pool_max_concurrent_request: "0"
          srv_pool_max_request: "0"
          srv_pool_ttl: "30"
          ssl_certificate:
              -
                  name: "default_name_17 (source vpn.certificate.local.name)"
          ssl_max_version: "ssl-3.0"
          ssl_min_version: "ssl-3.0"
          status: "enable"
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


def filter_llm_proxy_data(json):
    option_list = [
        "hostname",
        "incoming_http_port",
        "incoming_https_port",
        "incoming_ip",
        "incoming_ip6",
        "interface",
        "ipv6_status",
        "name",
        "protocol",
        "srv_pool_max_concurrent_request",
        "srv_pool_max_request",
        "srv_pool_ttl",
        "ssl_certificate",
        "ssl_max_version",
        "ssl_min_version",
        "status",
    ]

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
        or (not data[path[index]] and not isinstance(data[path[index]], list))
    ):
        return

    if index == len(path) - 1:
        data[path[index]] = " ".join(str(elem) for elem in data[path[index]])
        if len(data[path[index]]) == 0:
            data[path[index]] = None
    elif isinstance(data[path[index]], list):
        for value in data[path[index]]:
            flatten_single_path(value, path, index + 1)
    else:
        flatten_single_path(data[path[index]], path, index + 1)


def flatten_multilists_attributes(data):
    multilist_attrs = [
        ["protocol"],
    ]

    for attr in multilist_attrs:
        flatten_single_path(data, attr, 0)

    return data


def underscore_to_hyphen(data):
    new_data = None
    if isinstance(data, list):
        new_data = []
        for i, elem in enumerate(data):
            new_data.append(underscore_to_hyphen(elem))
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace("_", "-")] = underscore_to_hyphen(v)
    else:
        return data
    return new_data


def llm_proxy(data, fos):
    state = None
    vdom = data["vdom"]
    parameters = None
    state = data.get("state", None)
    llm_proxy_data = data["llm_proxy"]

    filtered_data = filter_llm_proxy_data(llm_proxy_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # pass post processed data to member operations
    # no need to do underscore_to_hyphen since do_member_operation handles it by itself
    data_copy = data.copy()
    data_copy["llm_proxy"] = filtered_data
    fos.do_member_operation(
        "llm",
        "proxy",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set(
            "llm", "proxy", data=converted_data, vdom=vdom, parameters=parameters
        )

    elif state == "absent":
        return fos.delete(
            "llm",
            "proxy",
            mkey=converted_data["name"],
            vdom=vdom,
            parameters=parameters,
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


def fortios_llm(data, fos):

    if data["llm_proxy"]:
        resp = llm_proxy(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("llm_proxy"))

    return (
        not is_successful_status(resp),
        is_successful_status(resp)
        and (resp["revision_changed"] if "revision_changed" in resp else True),
        resp,
        {},
    )


versioned_schema = {
    "v_range": [["v8.0.0", ""]],
    "type": "dict",
    "children": {
        "name": {"v_range": [["v8.0.0", ""]], "type": "string"},
        "status": {
            "v_range": [["v8.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "protocol": {
            "v_range": [["v8.0.0", ""]],
            "type": "list",
            "options": [{"value": "http"}, {"value": "https"}],
            "multiple_values": True,
            "elements": "str",
        },
        "ipv6_status": {
            "v_range": [["v8.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "interface": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v8.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v8.0.0", ""]],
        },
        "incoming_http_port": {"v_range": [["v8.0.0", ""]], "type": "integer"},
        "incoming_https_port": {"v_range": [["v8.0.0", ""]], "type": "integer"},
        "incoming_ip": {"v_range": [["v8.0.0", ""]], "type": "string"},
        "incoming_ip6": {"v_range": [["v8.0.0", ""]], "type": "string"},
        "hostname": {"v_range": [["v8.0.0", ""]], "type": "string"},
        "ssl_certificate": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v8.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v8.0.0", ""]],
        },
        "ssl_min_version": {
            "v_range": [["v8.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "ssl-3.0"},
                {"value": "tls-1.0"},
                {"value": "tls-1.1"},
                {"value": "tls-1.2"},
                {"value": "tls-1.3"},
            ],
        },
        "ssl_max_version": {
            "v_range": [["v8.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "ssl-3.0"},
                {"value": "tls-1.0"},
                {"value": "tls-1.1"},
                {"value": "tls-1.2"},
                {"value": "tls-1.3"},
            ],
        },
        "srv_pool_ttl": {"v_range": [["v8.0.0", ""]], "type": "integer"},
        "srv_pool_max_request": {"v_range": [["v8.0.0", ""]], "type": "integer"},
        "srv_pool_max_concurrent_request": {
            "v_range": [["v8.0.0", ""]],
            "type": "integer",
        },
    },
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
        "llm_proxy": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["llm_proxy"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["llm_proxy"]["options"][attribute_name]["required"] = True

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
        fos = FortiOSHandler(connection, module, mkeyname, admin_passwd_header=False)
        versions_check_result = check_schema_versioning(
            fos, versioned_schema, "llm_proxy"
        )

        is_error, has_changed, result, diff = fortios_llm(module.params, fos)

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
