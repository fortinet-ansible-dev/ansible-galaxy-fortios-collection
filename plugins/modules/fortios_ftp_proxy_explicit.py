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
module: fortios_ftp_proxy_explicit
short_description: Configure explicit FTP proxy settings in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify ftp_proxy feature and explicit category.
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

    ftp_proxy_explicit:
        description:
            - Configure explicit FTP proxy settings.
        default: null
        type: dict
        suboptions:
            incoming_ip:
                description:
                    - Accept incoming FTP requests from this IP address. An interface must have this IP address.
                type: str
            incoming_port:
                description:
                    - Accept incoming FTP requests on one or more ports.
                type: str
            outgoing_ip:
                description:
                    - Outgoing FTP requests will leave from this IP address. An interface must have this IP address.
                type: list
                elements: str
            sec_default_action:
                description:
                    - Accept or deny explicit FTP proxy sessions when no FTP proxy firewall policy exists.
                type: str
                choices:
                    - 'accept'
                    - 'deny'
            server_data_mode:
                description:
                    - Determine mode of data session on FTP server side.
                type: str
                choices:
                    - 'client'
                    - 'passive'
            ssl:
                description:
                    - Enable/disable the explicit FTPS proxy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ssl_algorithm:
                description:
                    - Relative strength of encryption algorithms accepted in negotiation.
                type: str
                choices:
                    - 'high'
                    - 'medium'
                    - 'low'
            ssl_cert:
                description:
                    - List of certificate names to use for SSL connections to this server. Source certificate.local.name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Certificate list. Source vpn.certificate.local.name.
                        required: true
                        type: str
            ssl_cert_dict:
                description:
                    - List of certificate names to use for SSL connections to this server. Use the parameter ssl-cert if the fortiOS firmware version <= 7.4.1
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Certificate list. Source vpn.certificate.local.name.
                        required: true
                        type: str
            ssl_dh_bits:
                description:
                    - Bit-size of Diffie-Hellman (DH) prime used in DHE-RSA negotiation .
                type: str
                choices:
                    - '768'
                    - '1024'
                    - '1536'
                    - '2048'
            status:
                description:
                    - Enable/disable the explicit FTP proxy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure explicit FTP proxy settings.
  fortinet.fortios.fortios_ftp_proxy_explicit:
      vdom: "{{ vdom }}"
      ftp_proxy_explicit:
          incoming_ip: "<your_own_value>"
          incoming_port: "<your_own_value>"
          outgoing_ip: "<your_own_value>"
          sec_default_action: "accept"
          server_data_mode: "client"
          ssl: "enable"
          ssl_algorithm: "high"
          ssl_cert:
              -
                  name: "default_name_11 (source vpn.certificate.local.name)"
          ssl_cert_dict:
              -
                  name: "default_name_13 (source vpn.certificate.local.name)"
          ssl_dh_bits: "768"
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


def filter_ftp_proxy_explicit_data(json):
    option_list = [
        "incoming_ip",
        "incoming_port",
        "outgoing_ip",
        "sec_default_action",
        "server_data_mode",
        "ssl",
        "ssl_algorithm",
        "ssl_cert",
        "ssl_cert_dict",
        "ssl_dh_bits",
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
        ["outgoing_ip"],
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


def remap_attribute_name(data):
    speciallist = {"ssl-cert-dict": "ssl-cert"}

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


def ftp_proxy_explicit(data, fos):
    state = None
    vdom = data["vdom"]
    ftp_proxy_explicit_data = data["ftp_proxy_explicit"]
    ftp_proxy_explicit_data = flatten_multilists_attributes(ftp_proxy_explicit_data)
    filtered_data = filter_ftp_proxy_explicit_data(ftp_proxy_explicit_data)
    converted_data = underscore_to_hyphen(filtered_data)
    converted_data = remap_attribute_names(converted_data)

    return fos.set("ftp-proxy", "explicit", data=converted_data, vdom=vdom)


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


def fortios_ftp_proxy(data, fos):
    fos.do_member_operation("ftp-proxy", "explicit")
    if data["ftp_proxy_explicit"]:
        resp = ftp_proxy_explicit(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("ftp_proxy_explicit"))

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
        "status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "incoming_port": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "incoming_ip": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "outgoing_ip": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "multiple_values": True,
            "elements": "str",
        },
        "sec_default_action": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "accept"}, {"value": "deny"}],
        },
        "server_data_mode": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "client"}, {"value": "passive"}],
        },
        "ssl": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssl_cert": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.4.4", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.2.0", "v7.4.1"], ["v7.4.4", ""]],
        },
        "ssl_dh_bits": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [
                {"value": "768"},
                {"value": "1024"},
                {"value": "1536"},
                {"value": "2048"},
            ],
        },
        "ssl_algorithm": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "high"}, {"value": "medium"}, {"value": "low"}],
        },
        "ssl_cert_dict": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.4.2", "v7.4.3"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.4.2", "v7.4.3"]],
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
        "ftp_proxy_explicit": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["ftp_proxy_explicit"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["ftp_proxy_explicit"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "ftp_proxy_explicit"
        )

        is_error, has_changed, result, diff = fortios_ftp_proxy(module.params, fos)

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
