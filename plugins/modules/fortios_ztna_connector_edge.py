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
module: fortios_ztna_connector_edge
short_description: Configure ZTNA connector edge in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify ztna feature and connector_edge category.
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

    ztna_connector_edge:
        description:
            - Configure ZTNA connector edge.
        default: null
        type: dict
        suboptions:
            interface:
                description:
                    - Connector edge interface.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Interface name. Source system.interface.name.
                        required: true
                        type: str
            port:
                description:
                    - Connector service edge port(1-65535).
                type: int
            server_cert:
                description:
                    - Server certificate for mTLS. Source vpn.certificate.local.name.
                type: str
            ssl_max_version:
                description:
                    - Highest TLS version accepted by server.
                type: str
                choices:
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            ssl_min_version:
                description:
                    - Lowest TLS version accepted by server.
                type: str
                choices:
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            status:
                description:
                    - Connector service edge status.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            trusted_client_ca:
                description:
                    - CA certificate used for client certificate verification.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - CA certificate list. Source vpn.certificate.ca.name.
                        required: true
                        type: str
"""
EXAMPLES = """
- name: Configure ZTNA connector edge.
  fortinet.fortios.fortios_ztna_connector_edge:
      vdom: "{{ vdom }}"
      ztna_connector_edge:
          interface:
              -
                  name: "default_name_4 (source system.interface.name)"
          port: "8443"
          server_cert: "<your_own_value> (source vpn.certificate.local.name)"
          ssl_max_version: "tls-1.1"
          ssl_min_version: "tls-1.1"
          status: "enable"
          trusted_client_ca:
              -
                  name: "default_name_11 (source vpn.certificate.ca.name)"
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


def filter_ztna_connector_edge_data(json):
    option_list = [
        "interface",
        "port",
        "server_cert",
        "ssl_max_version",
        "ssl_min_version",
        "status",
        "trusted_client_ca",
    ]

    json = remove_invalid_fields(json)
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


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


def ztna_connector_edge(data, fos):
    state = None
    vdom = data["vdom"]
    parameters = None
    state = data.get("state", None)
    ztna_connector_edge_data = data["ztna_connector_edge"]

    filtered_data = filter_ztna_connector_edge_data(ztna_connector_edge_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # pass post processed data to member operations
    # no need to do underscore_to_hyphen since do_member_operation handles it by itself
    data_copy = data.copy()
    data_copy["ztna_connector_edge"] = filtered_data
    fos.do_member_operation(
        "ztna",
        "connector-edge",
        data_copy,
    )

    return fos.set(
        "ztna", "connector-edge", data=converted_data, vdom=vdom, parameters=parameters
    )


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


def fortios_ztna(data, fos):

    if data["ztna_connector_edge"]:
        resp = ztna_connector_edge(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("ztna_connector_edge"))

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
        "status": {
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
        "port": {"v_range": [["v8.0.0", ""]], "type": "integer"},
        "ssl_min_version": {
            "v_range": [["v8.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "tls-1.1"},
                {"value": "tls-1.2"},
                {"value": "tls-1.3"},
            ],
        },
        "ssl_max_version": {
            "v_range": [["v8.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "tls-1.1"},
                {"value": "tls-1.2"},
                {"value": "tls-1.3"},
            ],
        },
        "server_cert": {"v_range": [["v8.0.0", ""]], "type": "string"},
        "trusted_client_ca": {
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
        "ztna_connector_edge": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["ztna_connector_edge"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["ztna_connector_edge"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "ztna_connector_edge"
        )

        is_error, has_changed, result, diff = fortios_ztna(module.params, fos)

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
