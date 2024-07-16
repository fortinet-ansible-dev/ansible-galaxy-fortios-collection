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
module: fortios_user_local
short_description: Configure local users in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify user feature and local category.
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
    user_local:
        description:
            - Configure local users.
        default: null
        type: dict
        suboptions:
            auth_concurrent_override:
                description:
                    - Enable/disable overriding the policy-auth-concurrent under config system global.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auth_concurrent_value:
                description:
                    - Maximum number of concurrent logins permitted from the same user.
                type: int
            authtimeout:
                description:
                    - Time in minutes before the authentication timeout for a user is reached.
                type: int
            email_to:
                description:
                    - Two-factor recipient"s email address.
                type: str
            fortitoken:
                description:
                    - Two-factor recipient"s FortiToken serial number. Source user.fortitoken.serial-number.
                type: str
            id:
                description:
                    - User ID.
                type: int
            ldap_server:
                description:
                    - Name of LDAP server with which the user must authenticate. Source user.ldap.name.
                type: str
            name:
                description:
                    - Local user name.
                required: true
                type: str
            passwd:
                description:
                    - User"s password.
                type: str
            passwd_policy:
                description:
                    - Password policy to apply to this user, as defined in config user password-policy. Source user.password-policy.name.
                type: str
            passwd_time:
                description:
                    - Time of the last password update.
                type: str
            ppk_identity:
                description:
                    - IKEv2 Postquantum Preshared Key Identity.
                type: str
            ppk_secret:
                description:
                    - IKEv2 Postquantum Preshared Key (ASCII string or hexadecimal encoded with a leading 0x).
                type: str
            qkd_profile:
                description:
                    - Quantum Key Distribution (QKD) profile. Source vpn.qkd.name.
                type: str
            radius_server:
                description:
                    - Name of RADIUS server with which the user must authenticate. Source user.radius.name.
                type: str
            sms_custom_server:
                description:
                    - Two-factor recipient"s SMS server. Source system.sms-server.name.
                type: str
            sms_phone:
                description:
                    - Two-factor recipient"s mobile phone number.
                type: str
            sms_server:
                description:
                    - Send SMS through FortiGuard or other external server.
                type: str
                choices:
                    - 'fortiguard'
                    - 'custom'
            status:
                description:
                    - Enable/disable allowing the local user to authenticate with the FortiGate unit.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            tacacs_plus_server:
                description:
                    - Name of TACACS+ server with which the user must authenticate. Source user.tacacs+.name.
                type: str
            two_factor:
                description:
                    - Enable/disable two-factor authentication.
                type: str
                choices:
                    - 'disable'
                    - 'fortitoken'
                    - 'fortitoken-cloud'
                    - 'email'
                    - 'sms'
            two_factor_authentication:
                description:
                    - Authentication method by FortiToken Cloud.
                type: str
                choices:
                    - 'fortitoken'
                    - 'email'
                    - 'sms'
            two_factor_notification:
                description:
                    - Notification method for user activation by FortiToken Cloud.
                type: str
                choices:
                    - 'email'
                    - 'sms'
            type:
                description:
                    - Authentication method.
                type: str
                choices:
                    - 'password'
                    - 'radius'
                    - 'tacacs+'
                    - 'ldap'
            username_case_sensitivity:
                description:
                    - Enable/disable case sensitivity when performing username matching (uppercase and lowercase letters are treated either as distinct or
                       equivalent).
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            username_sensitivity:
                description:
                    - Enable/disable case and accent sensitivity when performing username matching (accents are stripped and case is ignored when disabled).
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            workstation:
                description:
                    - Name of the remote user workstation, if you want to limit the user to authenticate only from a particular workstation.
                type: str
"""

EXAMPLES = """
- name: Configure local users.
  fortinet.fortios.fortios_user_local:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      user_local:
          auth_concurrent_override: "enable"
          auth_concurrent_value: "0"
          authtimeout: "0"
          email_to: "<your_own_value>"
          fortitoken: "<your_own_value> (source user.fortitoken.serial-number)"
          id: "8"
          ldap_server: "<your_own_value> (source user.ldap.name)"
          name: "default_name_10"
          passwd: "<your_own_value>"
          passwd_policy: "<your_own_value> (source user.password-policy.name)"
          passwd_time: "<your_own_value>"
          ppk_identity: "<your_own_value>"
          ppk_secret: "<your_own_value>"
          qkd_profile: "<your_own_value> (source vpn.qkd.name)"
          radius_server: "<your_own_value> (source user.radius.name)"
          sms_custom_server: "<your_own_value> (source system.sms-server.name)"
          sms_phone: "<your_own_value>"
          sms_server: "fortiguard"
          status: "enable"
          tacacs_plus_server: "<your_own_value> (source user.tacacs+.name)"
          two_factor: "disable"
          two_factor_authentication: "fortitoken"
          two_factor_notification: "email"
          type: "password"
          username_case_sensitivity: "disable"
          username_sensitivity: "disable"
          workstation: "<your_own_value>"
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


def filter_user_local_data(json):
    option_list = [
        "auth_concurrent_override",
        "auth_concurrent_value",
        "authtimeout",
        "email_to",
        "fortitoken",
        "id",
        "ldap_server",
        "name",
        "passwd",
        "passwd_policy",
        "passwd_time",
        "ppk_identity",
        "ppk_secret",
        "qkd_profile",
        "radius_server",
        "sms_custom_server",
        "sms_phone",
        "sms_server",
        "status",
        "tacacs_plus_server",
        "two_factor",
        "two_factor_authentication",
        "two_factor_notification",
        "type",
        "username_case_sensitivity",
        "username_sensitivity",
        "workstation",
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


def valid_attr_to_invalid_attr(data):
    speciallist = {"tacacs+_server": "tacacs_plus_server"}

    for k, v in speciallist.items():
        if v == data:
            return k

    return data


def valid_attr_to_invalid_attrs(data):
    if isinstance(data, list):
        new_data = []
        for elem in data:
            elem = valid_attr_to_invalid_attrs(elem)
            new_data.append(elem)
        data = new_data
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[valid_attr_to_invalid_attr(k)] = valid_attr_to_invalid_attrs(v)
        data = new_data

    return valid_attr_to_invalid_attr(data)


def user_local(data, fos, check_mode=False):
    state = None
    vdom = data["vdom"]

    state = data["state"]

    user_local_data = data["user_local"]
    filtered_data = filter_user_local_data(user_local_data)
    converted_data = underscore_to_hyphen(valid_attr_to_invalid_attrs(filtered_data))

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("user", "local", filtered_data, vdom=vdom)
        current_data = fos.get("user", "local", vdom=vdom, mkey=mkey)
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
        return fos.set("user", "local", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("user", "local", mkey=converted_data["name"], vdom=vdom)
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
    fos.do_member_operation("user", "local")
    if data["user_local"]:
        resp = user_local(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("user_local"))
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
        "status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "password"},
                {"value": "radius"},
                {"value": "tacacs+"},
                {"value": "ldap"},
            ],
        },
        "passwd": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ldap_server": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "radius_server": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "two_factor": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "fortitoken"},
                {"value": "fortitoken-cloud", "v_range": [["v6.2.0", ""]]},
                {"value": "email"},
                {"value": "sms"},
            ],
        },
        "two_factor_authentication": {
            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
            "type": "string",
            "options": [{"value": "fortitoken"}, {"value": "email"}, {"value": "sms"}],
        },
        "two_factor_notification": {
            "v_range": [["v6.2.0", "v6.2.0"], ["v6.2.5", ""]],
            "type": "string",
            "options": [{"value": "email"}, {"value": "sms"}],
        },
        "fortitoken": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "email_to": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "sms_server": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "fortiguard"}, {"value": "custom"}],
        },
        "sms_custom_server": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "sms_phone": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "passwd_policy": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "passwd_time": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "authtimeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "workstation": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "auth_concurrent_override": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "auth_concurrent_value": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "ppk_secret": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ppk_identity": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "qkd_profile": {"v_range": [["v7.4.2", ""]], "type": "string"},
        "username_sensitivity": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "id": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
        "username_case_sensitivity": {
            "v_range": [
                ["v6.0.0", "v6.0.0"],
                ["v6.0.11", "v6.2.0"],
                ["v6.2.5", "v7.0.0"],
            ],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "tacacs_plus_server": {"v_range": [["v6.0.0", ""]], "type": "string"},
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
        "user_local": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["user_local"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["user_local"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "user_local"
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
