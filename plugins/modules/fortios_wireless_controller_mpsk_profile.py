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
module: fortios_wireless_controller_mpsk_profile
short_description: Configure MPSK profile in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify wireless_controller feature and mpsk_profile category.
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
    wireless_controller_mpsk_profile:
        description:
            - Configure MPSK profile.
        default: null
        type: dict
        suboptions:
            mpsk_concurrent_clients:
                description:
                    - Maximum number of concurrent clients that connect using the same passphrase in multiple PSK authentication (0 - 65535).
                type: int
            mpsk_external_server:
                description:
                    - RADIUS server to be used to authenticate MPSK users. Source user.radius.name.
                type: str
            mpsk_external_server_auth:
                description:
                    - Enable/Disable MPSK external server authentication .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            mpsk_group:
                description:
                    - List of multiple PSK groups.
                type: list
                elements: dict
                suboptions:
                    mpsk_key:
                        description:
                            - List of multiple PSK entries.
                        type: list
                        elements: dict
                        suboptions:
                            comment:
                                description:
                                    - Comment.
                                type: str
                            concurrent_client_limit_type:
                                description:
                                    - MPSK client limit type options.
                                type: str
                                choices:
                                    - 'default'
                                    - 'unlimited'
                                    - 'specified'
                            concurrent_clients:
                                description:
                                    - Number of clients that can connect using this pre-shared key (1 - 65535).
                                type: int
                            key_type:
                                description:
                                    - Select the type of the key.
                                type: str
                                choices:
                                    - 'wpa2-personal'
                                    - 'wpa3-sae'
                            mac:
                                description:
                                    - MAC address.
                                type: str
                            mpsk_schedules:
                                description:
                                    - Firewall schedule for MPSK passphrase. The passphrase will be effective only when at least one schedule is valid.
                                type: list
                                elements: dict
                                suboptions:
                                    name:
                                        description:
                                            - Schedule name. Source firewall.schedule.group.name firewall.schedule.recurring.name firewall.schedule.onetime
                                              .name.
                                        required: true
                                        type: str
                            name:
                                description:
                                    - Pre-shared key name.
                                required: true
                                type: str
                            passphrase:
                                description:
                                    - WPA Pre-shared key.
                                type: str
                            sae_password:
                                description:
                                    - WPA3 SAE password.
                                type: str
                            sae_pk:
                                description:
                                    - Enable/disable WPA3 SAE-PK .
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            sae_private_key:
                                description:
                                    - Private key used for WPA3 SAE-PK authentication.
                                type: str
                    name:
                        description:
                            - MPSK group name.
                        required: true
                        type: str
                    vlan_id:
                        description:
                            - Optional VLAN ID.
                        type: int
                    vlan_type:
                        description:
                            - MPSK group VLAN options.
                        type: str
                        choices:
                            - 'no-vlan'
                            - 'fixed-vlan'
            mpsk_type:
                description:
                    - Select the security type of keys for this profile.
                type: str
                choices:
                    - 'wpa2-personal'
                    - 'wpa3-sae'
                    - 'wpa3-sae-transition'
            name:
                description:
                    - MPSK profile name.
                required: true
                type: str
"""

EXAMPLES = """
- name: Configure MPSK profile.
  fortinet.fortios.fortios_wireless_controller_mpsk_profile:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      wireless_controller_mpsk_profile:
          mpsk_concurrent_clients: "0"
          mpsk_external_server: "<your_own_value> (source user.radius.name)"
          mpsk_external_server_auth: "enable"
          mpsk_group:
              -
                  mpsk_key:
                      -
                          comment: "Comment."
                          concurrent_client_limit_type: "default"
                          concurrent_clients: "256"
                          key_type: "wpa2-personal"
                          mac: "<your_own_value>"
                          mpsk_schedules:
                              -
                                  name: "default_name_14 (source firewall.schedule.group.name firewall.schedule.recurring.name firewall.schedule.onetime.name)"
                          name: "default_name_15"
                          passphrase: "<your_own_value>"
                          sae_password: "<your_own_value>"
                          sae_pk: "enable"
                          sae_private_key: "<your_own_value>"
                  name: "default_name_20"
                  vlan_id: "0"
                  vlan_type: "no-vlan"
          mpsk_type: "wpa2-personal"
          name: "default_name_24"
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


def filter_wireless_controller_mpsk_profile_data(json):
    option_list = [
        "mpsk_concurrent_clients",
        "mpsk_external_server",
        "mpsk_external_server_auth",
        "mpsk_group",
        "mpsk_type",
        "name",
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


def wireless_controller_mpsk_profile(data, fos, check_mode=False):
    state = None
    vdom = data["vdom"]

    state = data["state"]

    wireless_controller_mpsk_profile_data = data["wireless_controller_mpsk_profile"]
    filtered_data = filter_wireless_controller_mpsk_profile_data(
        wireless_controller_mpsk_profile_data
    )
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey(
            "wireless-controller", "mpsk-profile", filtered_data, vdom=vdom
        )
        current_data = fos.get(
            "wireless-controller", "mpsk-profile", vdom=vdom, mkey=mkey
        )
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
            if is_existed:
                is_same = is_same_comparison(
                    serialize(current_data["results"][0]), serialize(filtered_data)
                )

                current_values = find_current_values(
                    current_data["results"][0], filtered_data
                )

                return (
                    False,
                    not is_same,
                    filtered_data,
                    {"before": current_values, "after": filtered_data},
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

    if state == "present" or state is True:
        return fos.set(
            "wireless-controller", "mpsk-profile", data=converted_data, vdom=vdom
        )

    elif state == "absent":
        return fos.delete(
            "wireless-controller",
            "mpsk-profile",
            mkey=converted_data["name"],
            vdom=vdom,
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


def fortios_wireless_controller(data, fos, check_mode):
    fos.do_member_operation("wireless-controller", "mpsk-profile")
    if data["wireless_controller_mpsk_profile"]:
        resp = wireless_controller_mpsk_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("wireless_controller_mpsk_profile")
        )
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
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "string",
            "required": True,
        },
        "mpsk_concurrent_clients": {
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
            "type": "integer",
        },
        "mpsk_external_server_auth": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "mpsk_external_server": {"v_range": [["v7.4.4", ""]], "type": "string"},
        "mpsk_type": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [
                {"value": "wpa2-personal"},
                {"value": "wpa3-sae"},
                {"value": "wpa3-sae-transition"},
            ],
        },
        "mpsk_group": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                    "required": True,
                },
                "vlan_type": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                    "options": [{"value": "no-vlan"}, {"value": "fixed-vlan"}],
                },
                "vlan_id": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "integer",
                },
                "mpsk_key": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                            "type": "string",
                            "required": True,
                        },
                        "key_type": {
                            "v_range": [["v7.4.4", ""]],
                            "type": "string",
                            "options": [
                                {"value": "wpa2-personal"},
                                {"value": "wpa3-sae"},
                            ],
                        },
                        "mac": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                            "type": "string",
                        },
                        "passphrase": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                            "type": "string",
                        },
                        "sae_password": {"v_range": [["v7.4.4", ""]], "type": "string"},
                        "sae_pk": {
                            "v_range": [["v7.4.4", ""]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "sae_private_key": {
                            "v_range": [["v7.4.4", ""]],
                            "type": "string",
                        },
                        "concurrent_client_limit_type": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                            "type": "string",
                            "options": [
                                {"value": "default"},
                                {"value": "unlimited"},
                                {"value": "specified"},
                            ],
                        },
                        "concurrent_clients": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                            "type": "integer",
                        },
                        "comment": {
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                            "type": "string",
                        },
                        "mpsk_schedules": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "name": {
                                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                                    "type": "string",
                                    "required": True,
                                }
                            },
                            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                        },
                    },
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                },
            },
            "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
        },
    },
    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
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
        "wireless_controller_mpsk_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["wireless_controller_mpsk_profile"]["options"][
            attribute_name
        ] = module_spec["options"][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["wireless_controller_mpsk_profile"]["options"][attribute_name][
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
            fos, versioned_schema, "wireless_controller_mpsk_profile"
        )

        is_error, has_changed, result, diff = fortios_wireless_controller(
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
