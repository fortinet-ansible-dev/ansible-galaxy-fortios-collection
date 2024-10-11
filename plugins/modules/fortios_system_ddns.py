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
module: fortios_system_ddns
short_description: Configure DDNS in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and ddns category.
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
    - We highly recommend using your own value as the ddnsid instead of 0, while '0' is a special placeholder that allows the backend to assign the latest
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
    system_ddns:
        description:
            - Configure DDNS.
        default: null
        type: dict
        suboptions:
            addr_type:
                description:
                    - Address type of interface address in DDNS update.
                type: str
                choices:
                    - 'ipv4'
                    - 'ipv6'
            bound_ip:
                description:
                    - Bound IP address.
                type: str
            clear_text:
                description:
                    - Enable/disable use of clear text connections.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            ddns_auth:
                description:
                    - Enable/disable TSIG authentication for your DDNS server.
                type: str
                choices:
                    - 'disable'
                    - 'tsig'
            ddns_domain:
                description:
                    - Your fully qualified domain name. For example, yourname.ddns.com.
                type: str
            ddns_key:
                description:
                    - DDNS update key (base 64 encoding).
                type: str
            ddns_keyname:
                description:
                    - DDNS update key name.
                type: str
            ddns_password:
                description:
                    - DDNS password.
                type: str
            ddns_server:
                description:
                    - Select a DDNS service provider.
                type: str
                choices:
                    - 'dyndns.org'
                    - 'dyns.net'
                    - 'tzo.com'
                    - 'vavic.com'
                    - 'dipdns.net'
                    - 'now.net.cn'
                    - 'dhs.org'
                    - 'easydns.com'
                    - 'genericDDNS'
                    - 'FortiGuardDDNS'
                    - 'noip.com'
            ddns_server_addr:
                description:
                    - Generic DDNS server IP/FQDN list.
                type: list
                elements: dict
                suboptions:
                    addr:
                        description:
                            - IP address or FQDN of the server.
                        required: true
                        type: str
            ddns_server_ip:
                description:
                    - Generic DDNS server IP.
                type: str
            ddns_sn:
                description:
                    - DDNS Serial Number.
                type: str
            ddns_ttl:
                description:
                    - Time-to-live for DDNS packets.
                type: int
            ddns_username:
                description:
                    - DDNS user name.
                type: str
            ddns_zone:
                description:
                    - Zone of your domain name (for example, DDNS.com).
                type: str
            ddnsid:
                description:
                    - DDNS ID. see <a href='#notes'>Notes</a>.
                required: true
                type: int
            monitor_interface:
                description:
                    - Monitored interface.
                type: list
                elements: dict
                suboptions:
                    interface_name:
                        description:
                            - Interface name. Source system.interface.name.
                        required: true
                        type: str
            server_type:
                description:
                    - Address type of the DDNS server.
                type: str
                choices:
                    - 'ipv4'
                    - 'ipv6'
            ssl_certificate:
                description:
                    - Name of local certificate for SSL connections. Source certificate.local.name.
                type: str
            update_interval:
                description:
                    - DDNS update interval (60 - 2592000 sec, 0 means default).
                type: int
            use_public_ip:
                description:
                    - Enable/disable use of public IP address.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
"""

EXAMPLES = """
- name: Configure DDNS.
  fortinet.fortios.fortios_system_ddns:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      system_ddns:
          addr_type: "ipv4"
          bound_ip: "<your_own_value>"
          clear_text: "disable"
          ddns_auth: "disable"
          ddns_domain: "<your_own_value>"
          ddns_key: "<your_own_value>"
          ddns_keyname: "<your_own_value>"
          ddns_password: "<your_own_value>"
          ddns_server: "dyndns.org"
          ddns_server_addr:
              -
                  addr: "<your_own_value>"
          ddns_server_ip: "<your_own_value>"
          ddns_sn: "<your_own_value>"
          ddns_ttl: "300"
          ddns_username: "<your_own_value>"
          ddns_zone: "<your_own_value>"
          ddnsid: "<you_own_value>"
          monitor_interface:
              -
                  interface_name: "<your_own_value> (source system.interface.name)"
          server_type: "ipv4"
          ssl_certificate: "<your_own_value> (source certificate.local.name)"
          update_interval: "300"
          use_public_ip: "disable"
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


def filter_system_ddns_data(json):
    option_list = [
        "addr_type",
        "bound_ip",
        "clear_text",
        "ddns_auth",
        "ddns_domain",
        "ddns_key",
        "ddns_keyname",
        "ddns_password",
        "ddns_server",
        "ddns_server_addr",
        "ddns_server_ip",
        "ddns_sn",
        "ddns_ttl",
        "ddns_username",
        "ddns_zone",
        "ddnsid",
        "monitor_interface",
        "server_type",
        "ssl_certificate",
        "update_interval",
        "use_public_ip",
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


def system_ddns(data, fos, check_mode=False):
    state = None
    vdom = data["vdom"]

    state = data["state"]

    system_ddns_data = data["system_ddns"]

    filtered_data = filter_system_ddns_data(system_ddns_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("system", "ddns", filtered_data, vdom=vdom)
        current_data = fos.get("system", "ddns", vdom=vdom, mkey=mkey)
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
    data_copy["system_ddns"] = converted_data
    fos.do_member_operation(
        "system",
        "ddns",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("system", "ddns", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("system", "ddns", mkey=converted_data["ddnsid"], vdom=vdom)
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


def fortios_system(data, fos, check_mode):
    if data["system_ddns"]:
        resp = system_ddns(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_ddns"))
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
        "ddnsid": {"v_range": [["v6.0.0", ""]], "type": "integer", "required": True},
        "ddns_server": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "dyndns.org"},
                {"value": "dyns.net"},
                {"value": "tzo.com"},
                {"value": "vavic.com"},
                {"value": "dipdns.net"},
                {"value": "now.net.cn"},
                {"value": "dhs.org"},
                {"value": "easydns.com"},
                {"value": "genericDDNS"},
                {"value": "FortiGuardDDNS"},
                {"value": "noip.com"},
            ],
        },
        "addr_type": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "ipv4"}, {"value": "ipv6"}],
        },
        "server_type": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "ipv4"}, {"value": "ipv6"}],
        },
        "ddns_server_addr": {
            "type": "list",
            "elements": "dict",
            "children": {
                "addr": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.0.0", ""]],
        },
        "ddns_zone": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ddns_ttl": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ddns_auth": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "tsig"}],
        },
        "ddns_keyname": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ddns_key": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ddns_domain": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ddns_username": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ddns_sn": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ddns_password": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "use_public_ip": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "update_interval": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "clear_text": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "ssl_certificate": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "monitor_interface": {
            "type": "list",
            "elements": "dict",
            "children": {
                "interface_name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "bound_ip": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "string",
        },
        "ddns_server_ip": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "string"},
    },
    "v_range": [["v6.0.0", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "ddnsid"
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
        "system_ddns": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_ddns"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_ddns"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_ddns"
        )

        is_error, has_changed, result, diff = fortios_system(
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
