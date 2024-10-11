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
module: fortios_user_exchange
short_description: Configure MS Exchange server entries in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify user feature and exchange category.
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
    user_exchange:
        description:
            - Configure MS Exchange server entries.
        default: null
        type: dict
        suboptions:
            auth_level:
                description:
                    - Authentication security level used for the RPC protocol layer.
                type: str
                choices:
                    - 'connect'
                    - 'call'
                    - 'packet'
                    - 'integrity'
                    - 'privacy'
            auth_type:
                description:
                    - Authentication security type used for the RPC protocol layer.
                type: str
                choices:
                    - 'spnego'
                    - 'ntlm'
                    - 'kerberos'
            auto_discover_kdc:
                description:
                    - Enable/disable automatic discovery of KDC IP addresses.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            connect_protocol:
                description:
                    - Connection protocol used to connect to MS Exchange service.
                type: str
                choices:
                    - 'rpc-over-tcp'
                    - 'rpc-over-http'
                    - 'rpc-over-https'
            domain_name:
                description:
                    - MS Exchange server fully qualified domain name.
                type: str
            http_auth_type:
                description:
                    - Authentication security type used for the HTTP transport.
                type: str
                choices:
                    - 'basic'
                    - 'ntlm'
            ip:
                description:
                    - Server IPv4 address.
                type: str
            kdc_ip:
                description:
                    - KDC IPv4 addresses for Kerberos authentication.
                type: list
                elements: dict
                suboptions:
                    ipv4:
                        description:
                            - KDC IPv4 addresses for Kerberos authentication.
                        required: true
                        type: str
            name:
                description:
                    - MS Exchange server entry name.
                required: true
                type: str
            password:
                description:
                    - Password for the specified username.
                type: str
            server_name:
                description:
                    - MS Exchange server hostname.
                type: str
            ssl_min_proto_version:
                description:
                    - Minimum SSL/TLS protocol version for HTTPS transport .
                type: str
                choices:
                    - 'default'
                    - 'SSLv3'
                    - 'TLSv1'
                    - 'TLSv1-1'
                    - 'TLSv1-2'
                    - 'TLSv1-3'
            username:
                description:
                    - User name used to sign in to the server. Must have proper permissions for service.
                type: str
"""

EXAMPLES = """
- name: Configure MS Exchange server entries.
  fortinet.fortios.fortios_user_exchange:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      user_exchange:
          auth_level: "connect"
          auth_type: "spnego"
          auto_discover_kdc: "enable"
          connect_protocol: "rpc-over-tcp"
          domain_name: "<your_own_value>"
          http_auth_type: "basic"
          ip: "<your_own_value>"
          kdc_ip:
              -
                  ipv4: "<your_own_value>"
          name: "default_name_12"
          password: "<your_own_value>"
          server_name: "<your_own_value>"
          ssl_min_proto_version: "default"
          username: "<your_own_value>"
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


def filter_user_exchange_data(json):
    option_list = [
        "auth_level",
        "auth_type",
        "auto_discover_kdc",
        "connect_protocol",
        "domain_name",
        "http_auth_type",
        "ip",
        "kdc_ip",
        "name",
        "password",
        "server_name",
        "ssl_min_proto_version",
        "username",
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


def user_exchange(data, fos, check_mode=False):
    state = None
    vdom = data["vdom"]

    state = data["state"]

    user_exchange_data = data["user_exchange"]

    filtered_data = filter_user_exchange_data(user_exchange_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("user", "exchange", filtered_data, vdom=vdom)
        current_data = fos.get("user", "exchange", vdom=vdom, mkey=mkey)
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
    data_copy["user_exchange"] = converted_data
    fos.do_member_operation(
        "user",
        "exchange",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("user", "exchange", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("user", "exchange", mkey=converted_data["name"], vdom=vdom)
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


def fortios_user(data, fos, check_mode):
    if data["user_exchange"]:
        resp = user_exchange(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("user_exchange"))
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
        "name": {"v_range": [["v6.2.0", ""]], "type": "string", "required": True},
        "server_name": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "domain_name": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "username": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "password": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "ip": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "connect_protocol": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [
                {"value": "rpc-over-tcp"},
                {"value": "rpc-over-http"},
                {"value": "rpc-over-https"},
            ],
        },
        "auth_type": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "spnego"}, {"value": "ntlm"}, {"value": "kerberos"}],
        },
        "auth_level": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [
                {"value": "connect"},
                {"value": "call"},
                {"value": "packet"},
                {"value": "integrity"},
                {"value": "privacy"},
            ],
        },
        "http_auth_type": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "basic"}, {"value": "ntlm"}],
        },
        "ssl_min_proto_version": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [
                {"value": "default"},
                {"value": "SSLv3"},
                {"value": "TLSv1"},
                {"value": "TLSv1-1"},
                {"value": "TLSv1-2"},
                {"value": "TLSv1-3", "v_range": [["v7.4.1", ""]]},
            ],
        },
        "auto_discover_kdc": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "kdc_ip": {
            "type": "list",
            "elements": "dict",
            "children": {
                "ipv4": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.2.0", ""]],
        },
    },
    "v_range": [["v6.2.0", ""]],
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
        "user_exchange": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["user_exchange"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["user_exchange"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "user_exchange"
        )

        is_error, has_changed, result, diff = fortios_user(
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
