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
module: fortios_user_domain_controller
short_description: Configure domain controller entries in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify user feature and domain_controller category.
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
    user_domain_controller:
        description:
            - Configure domain controller entries.
        default: null
        type: dict
        suboptions:
            ad_mode:
                description:
                    - Set Active Directory mode.
                type: str
                choices:
                    - 'none'
                    - 'ds'
                    - 'lds'
            adlds_dn:
                description:
                    - AD LDS distinguished name.
                type: str
            adlds_ip_address:
                description:
                    - AD LDS IPv4 address.
                type: str
            adlds_ip6:
                description:
                    - AD LDS IPv6 address.
                type: str
            adlds_port:
                description:
                    - Port number of AD LDS service .
                type: int
            change_detection:
                description:
                    - Enable/disable detection of a configuration change in the Active Directory server.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            change_detection_period:
                description:
                    - Minutes to detect a configuration change in the Active Directory server (5 - 10080 minutes (7 days)).
                type: int
            dns_srv_lookup:
                description:
                    - Enable/disable DNS service lookup.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            domain_name:
                description:
                    - Domain DNS name.
                type: str
            extra_server:
                description:
                    - Extra servers.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Server ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    ip_address:
                        description:
                            - Domain controller IP address.
                        type: str
                    port:
                        description:
                            - Port to be used for communication with the domain controller .
                        type: int
                    source_ip_address:
                        description:
                            - FortiGate IPv4 address to be used for communication with the domain controller.
                        type: str
                    source_port:
                        description:
                            - Source port to be used for communication with the domain controller.
                        type: int
            hostname:
                description:
                    - Hostname of the server to connect to.
                type: str
            interface:
                description:
                    - Specify outgoing interface to reach server. Source system.interface.name.
                type: str
            interface_select_method:
                description:
                    - Specify how to select outgoing interface to reach server.
                type: str
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            ip_address:
                description:
                    - Domain controller IPv4 address.
                type: str
            ip6:
                description:
                    - Domain controller IPv6 address.
                type: str
            ldap_server:
                description:
                    - LDAP server name(s). Source user.ldap.name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - LDAP server name. Source user.ldap.name.
                        required: true
                        type: str
            name:
                description:
                    - Domain controller entry name.
                required: true
                type: str
            password:
                description:
                    - Password for specified username.
                type: str
            port:
                description:
                    - Port to be used for communication with the domain controller .
                type: int
            replication_port:
                description:
                    - Port to be used for communication with the domain controller for replication service. Port number 0 indicates automatic discovery.
                type: int
            source_ip_address:
                description:
                    - FortiGate IPv4 address to be used for communication with the domain controller.
                type: str
            source_ip6:
                description:
                    - FortiGate IPv6 address to be used for communication with the domain controller.
                type: str
            source_port:
                description:
                    - Source port to be used for communication with the domain controller.
                type: int
            username:
                description:
                    - User name to sign in with. Must have proper permissions for service.
                type: str
"""

EXAMPLES = """
- name: Configure domain controller entries.
  fortinet.fortios.fortios_user_domain_controller:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      user_domain_controller:
          ad_mode: "none"
          adlds_dn: "<your_own_value>"
          adlds_ip_address: "<your_own_value>"
          adlds_ip6: "<your_own_value>"
          adlds_port: "389"
          change_detection: "enable"
          change_detection_period: "60"
          dns_srv_lookup: "enable"
          domain_name: "<your_own_value>"
          extra_server:
              -
                  id: "13"
                  ip_address: "<your_own_value>"
                  port: "445"
                  source_ip_address: "<your_own_value>"
                  source_port: "0"
          hostname: "myhostname"
          interface: "<your_own_value> (source system.interface.name)"
          interface_select_method: "auto"
          ip_address: "<your_own_value>"
          ip6: "<your_own_value>"
          ldap_server:
              -
                  name: "default_name_24 (source user.ldap.name)"
          name: "default_name_25"
          password: "<your_own_value>"
          port: "445"
          replication_port: "0"
          source_ip_address: "<your_own_value>"
          source_ip6: "<your_own_value>"
          source_port: "0"
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


def filter_user_domain_controller_data(json):
    option_list = [
        "ad_mode",
        "adlds_dn",
        "adlds_ip_address",
        "adlds_ip6",
        "adlds_port",
        "change_detection",
        "change_detection_period",
        "dns_srv_lookup",
        "domain_name",
        "extra_server",
        "hostname",
        "interface",
        "interface_select_method",
        "ip_address",
        "ip6",
        "ldap_server",
        "name",
        "password",
        "port",
        "replication_port",
        "source_ip_address",
        "source_ip6",
        "source_port",
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


def user_domain_controller(data, fos, check_mode=False):
    state = None
    vdom = data["vdom"]

    state = data["state"]

    user_domain_controller_data = data["user_domain_controller"]

    filtered_data = filter_user_domain_controller_data(user_domain_controller_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("user", "domain-controller", filtered_data, vdom=vdom)
        current_data = fos.get("user", "domain-controller", vdom=vdom, mkey=mkey)
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
    data_copy["user_domain_controller"] = converted_data
    fos.do_member_operation(
        "user",
        "domain-controller",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("user", "domain-controller", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "user", "domain-controller", mkey=converted_data["name"], vdom=vdom
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


def fortios_user(data, fos, check_mode):
    if data["user_domain_controller"]:
        resp = user_domain_controller(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("user_domain_controller"))
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
        "name": {"v_range": [["v6.0.0", ""]], "type": "string", "required": True},
        "ad_mode": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "none"}, {"value": "ds"}, {"value": "lds"}],
        },
        "hostname": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "username": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "password": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "ip_address": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ip6": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "source_ip_address": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "source_ip6": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "source_port": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "interface_select_method": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "auto"}, {"value": "sdwan"}, {"value": "specify"}],
        },
        "interface": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "extra_server": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "ip_address": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "port": {"v_range": [["v6.2.0", ""]], "type": "integer"},
                "source_ip_address": {"v_range": [["v7.0.0", ""]], "type": "string"},
                "source_port": {"v_range": [["v7.0.0", ""]], "type": "integer"},
            },
            "v_range": [["v6.2.0", ""]],
        },
        "domain_name": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "replication_port": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "ldap_server": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.4.4", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "change_detection": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "change_detection_period": {"v_range": [["v7.4.0", ""]], "type": "integer"},
        "dns_srv_lookup": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "adlds_dn": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "adlds_ip_address": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "adlds_ip6": {"v_range": [["v7.0.0", ""]], "type": "string"},
        "adlds_port": {"v_range": [["v7.0.0", ""]], "type": "integer"},
    },
    "v_range": [["v6.0.0", ""]],
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
        "user_domain_controller": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["user_domain_controller"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["user_domain_controller"]["options"][attribute_name][
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
            fos, versioned_schema, "user_domain_controller"
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
