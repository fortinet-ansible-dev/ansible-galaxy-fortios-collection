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
module: fortios_system_ssh_config
short_description: Configure SSH config in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and ssh_config category.
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

    system_ssh_config:
        description:
            - Configure SSH config.
        default: null
        type: dict
        suboptions:
            ssh_enc_algo:
                description:
                    - Select one or more SSH ciphers.
                type: list
                elements: str
                choices:
                    - 'chacha20-poly1305@openssh.com'
                    - 'aes128-ctr'
                    - 'aes192-ctr'
                    - 'aes256-ctr'
                    - 'arcfour256'
                    - 'arcfour128'
                    - 'aes128-cbc'
                    - '3des-cbc'
                    - 'blowfish-cbc'
                    - 'cast128-cbc'
                    - 'aes192-cbc'
                    - 'aes256-cbc'
                    - 'arcfour'
                    - 'rijndael-cbc@lysator.liu.se'
                    - 'aes128-gcm@openssh.com'
                    - 'aes256-gcm@openssh.com'
            ssh_hsk:
                description:
                    - Config SSH host key.
                type: str
            ssh_hsk_algo:
                description:
                    - Select one or more SSH hostkey algorithms.
                type: list
                elements: str
                choices:
                    - 'ssh-rsa'
                    - 'ecdsa-sha2-nistp521'
                    - 'ecdsa-sha2-nistp384'
                    - 'ecdsa-sha2-nistp256'
                    - 'rsa-sha2-256'
                    - 'rsa-sha2-512'
                    - 'ssh-ed25519'
            ssh_hsk_override:
                description:
                    - Enable/disable SSH host key override in SSH daemon.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            ssh_hsk_password:
                description:
                    - Password for ssh-hostkey.
                type: str
            ssh_kex_algo:
                description:
                    - Select one or more SSH kex algorithms.
                type: list
                elements: str
                choices:
                    - 'diffie-hellman-group1-sha1'
                    - 'diffie-hellman-group14-sha1'
                    - 'diffie-hellman-group14-sha256'
                    - 'diffie-hellman-group16-sha512'
                    - 'diffie-hellman-group18-sha512'
                    - 'diffie-hellman-group-exchange-sha1'
                    - 'diffie-hellman-group-exchange-sha256'
                    - 'curve25519-sha256@libssh.org'
                    - 'ecdh-sha2-nistp256'
                    - 'ecdh-sha2-nistp384'
                    - 'ecdh-sha2-nistp521'
            ssh_mac_algo:
                description:
                    - Select one or more SSH MAC algorithms.
                type: list
                elements: str
                choices:
                    - 'hmac-md5'
                    - 'hmac-md5-etm@openssh.com'
                    - 'hmac-md5-96'
                    - 'hmac-md5-96-etm@openssh.com'
                    - 'hmac-sha1'
                    - 'hmac-sha1-etm@openssh.com'
                    - 'hmac-sha2-256'
                    - 'hmac-sha2-256-etm@openssh.com'
                    - 'hmac-sha2-512'
                    - 'hmac-sha2-512-etm@openssh.com'
                    - 'hmac-ripemd160'
                    - 'hmac-ripemd160@openssh.com'
                    - 'hmac-ripemd160-etm@openssh.com'
                    - 'umac-64@openssh.com'
                    - 'umac-128@openssh.com'
                    - 'umac-64-etm@openssh.com'
                    - 'umac-128-etm@openssh.com'
"""

EXAMPLES = """
- name: Configure SSH config.
  fortinet.fortios.fortios_system_ssh_config:
      vdom: "{{ vdom }}"
      system_ssh_config:
          ssh_enc_algo: "chacha20-poly1305@openssh.com"
          ssh_hsk: "<your_own_value>"
          ssh_hsk_algo: "ssh-rsa"
          ssh_hsk_override: "disable"
          ssh_hsk_password: "<your_own_value>"
          ssh_kex_algo: "diffie-hellman-group1-sha1"
          ssh_mac_algo: "hmac-md5"
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


def filter_system_ssh_config_data(json):
    option_list = [
        "ssh_enc_algo",
        "ssh_hsk",
        "ssh_hsk_algo",
        "ssh_hsk_override",
        "ssh_hsk_password",
        "ssh_kex_algo",
        "ssh_mac_algo",
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
        ["ssh_kex_algo"],
        ["ssh_enc_algo"],
        ["ssh_mac_algo"],
        ["ssh_hsk_algo"],
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


def system_ssh_config(data, fos):
    state = None
    vdom = data["vdom"]
    system_ssh_config_data = data["system_ssh_config"]
    system_ssh_config_data = flatten_multilists_attributes(system_ssh_config_data)
    filtered_data = filter_system_ssh_config_data(system_ssh_config_data)
    converted_data = underscore_to_hyphen(filtered_data)

    return fos.set("system", "ssh-config", data=converted_data, vdom=vdom)


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


def fortios_system(data, fos):
    fos.do_member_operation("system", "ssh-config")
    if data["system_ssh_config"]:
        resp = system_ssh_config(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_ssh_config"))

    return (
        not is_successful_status(resp),
        is_successful_status(resp)
        and (resp["revision_changed"] if "revision_changed" in resp else True),
        resp,
        {},
    )


versioned_schema = {
    "v_range": [["v7.4.4", ""]],
    "type": "dict",
    "children": {
        "ssh_kex_algo": {
            "v_range": [["v7.4.4", ""]],
            "type": "list",
            "options": [
                {"value": "diffie-hellman-group1-sha1"},
                {"value": "diffie-hellman-group14-sha1"},
                {"value": "diffie-hellman-group14-sha256"},
                {"value": "diffie-hellman-group16-sha512"},
                {"value": "diffie-hellman-group18-sha512"},
                {"value": "diffie-hellman-group-exchange-sha1"},
                {"value": "diffie-hellman-group-exchange-sha256"},
                {"value": "curve25519-sha256@libssh.org"},
                {"value": "ecdh-sha2-nistp256"},
                {"value": "ecdh-sha2-nistp384"},
                {"value": "ecdh-sha2-nistp521"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "ssh_enc_algo": {
            "v_range": [["v7.4.4", ""]],
            "type": "list",
            "options": [
                {"value": "chacha20-poly1305@openssh.com"},
                {"value": "aes128-ctr"},
                {"value": "aes192-ctr"},
                {"value": "aes256-ctr"},
                {"value": "arcfour256"},
                {"value": "arcfour128"},
                {"value": "aes128-cbc"},
                {"value": "3des-cbc"},
                {"value": "blowfish-cbc"},
                {"value": "cast128-cbc"},
                {"value": "aes192-cbc"},
                {"value": "aes256-cbc"},
                {"value": "arcfour"},
                {"value": "rijndael-cbc@lysator.liu.se"},
                {"value": "aes128-gcm@openssh.com"},
                {"value": "aes256-gcm@openssh.com"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "ssh_mac_algo": {
            "v_range": [["v7.4.4", ""]],
            "type": "list",
            "options": [
                {"value": "hmac-md5"},
                {"value": "hmac-md5-etm@openssh.com"},
                {"value": "hmac-md5-96"},
                {"value": "hmac-md5-96-etm@openssh.com"},
                {"value": "hmac-sha1"},
                {"value": "hmac-sha1-etm@openssh.com"},
                {"value": "hmac-sha2-256"},
                {"value": "hmac-sha2-256-etm@openssh.com"},
                {"value": "hmac-sha2-512"},
                {"value": "hmac-sha2-512-etm@openssh.com"},
                {"value": "hmac-ripemd160"},
                {"value": "hmac-ripemd160@openssh.com"},
                {"value": "hmac-ripemd160-etm@openssh.com"},
                {"value": "umac-64@openssh.com"},
                {"value": "umac-128@openssh.com"},
                {"value": "umac-64-etm@openssh.com"},
                {"value": "umac-128-etm@openssh.com"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "ssh_hsk_algo": {
            "v_range": [["v7.4.4", ""]],
            "type": "list",
            "options": [
                {"value": "ssh-rsa"},
                {"value": "ecdsa-sha2-nistp521"},
                {"value": "ecdsa-sha2-nistp384"},
                {"value": "ecdsa-sha2-nistp256"},
                {"value": "rsa-sha2-256"},
                {"value": "rsa-sha2-512"},
                {"value": "ssh-ed25519"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "ssh_hsk_override": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ssh_hsk_password": {"v_range": [["v7.4.4", ""]], "type": "string"},
        "ssh_hsk": {"v_range": [["v7.4.4", ""]], "type": "string"},
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
        "system_ssh_config": {
            "required": False,
            "type": "dict",
            "default": None,
            "no_log": True,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_ssh_config"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_ssh_config"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_ssh_config"
        )

        is_error, has_changed, result, diff = fortios_system(module.params, fos)

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
