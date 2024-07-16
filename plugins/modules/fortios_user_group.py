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
module: fortios_user_group
short_description: Configure user groups in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify user feature and group category.
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
    user_group:
        description:
            - Configure user groups.
        default: null
        type: dict
        suboptions:
            auth_concurrent_override:
                description:
                    - Enable/disable overriding the global number of concurrent authentication sessions for this user group.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            auth_concurrent_value:
                description:
                    - Maximum number of concurrent authenticated connections per user (0 - 100).
                type: int
            authtimeout:
                description:
                    - Authentication timeout in minutes for this user group. 0 to use the global user setting auth-timeout.
                type: int
            company:
                description:
                    - Set the action for the company guest user field.
                type: str
                choices:
                    - 'optional'
                    - 'mandatory'
                    - 'disabled'
            email:
                description:
                    - Enable/disable the guest user email address field.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            expire:
                description:
                    - Time in seconds before guest user accounts expire (1 - 31536000).
                type: int
            expire_type:
                description:
                    - Determine when the expiration countdown begins.
                type: str
                choices:
                    - 'immediately'
                    - 'first-successful-login'
            group_type:
                description:
                    - Set the group to be for firewall authentication, FSSO, RSSO, or guest users.
                type: str
                choices:
                    - 'firewall'
                    - 'fsso-service'
                    - 'rsso'
                    - 'guest'
            guest:
                description:
                    - Guest User.
                type: list
                elements: dict
                suboptions:
                    comment:
                        description:
                            - Comment.
                        type: str
                    company:
                        description:
                            - Set the action for the company guest user field.
                        type: str
                    email:
                        description:
                            - Email.
                        type: str
                    expiration:
                        description:
                            - Expire time.
                        type: str
                    id:
                        description:
                            - Guest ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    mobile_phone:
                        description:
                            - Mobile phone.
                        type: str
                    name:
                        description:
                            - Guest name.
                        type: str
                    password:
                        description:
                            - Guest password.
                        type: str
                    sponsor:
                        description:
                            - Set the action for the sponsor guest user field.
                        type: str
                    user_id:
                        description:
                            - Guest ID.
                        type: str
            http_digest_realm:
                description:
                    - Realm attribute for MD5-digest authentication.
                type: str
            id:
                description:
                    - Group ID.
                type: int
            match:
                description:
                    - Group matches.
                type: list
                elements: dict
                suboptions:
                    group_name:
                        description:
                            - Name of matching user or group on remote authentication server.
                        type: str
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    server_name:
                        description:
                            - Name of remote auth server. Source user.radius.name user.ldap.name user.tacacs+.name user.saml.name user
                              .external-identity-provider.name.
                        type: str
            max_accounts:
                description:
                    - Maximum number of guest accounts that can be created for this group (0 means unlimited).
                type: int
            member:
                description:
                    - Names of users, peers, LDAP severs, RADIUS servers or external idp servers to add to the user group.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Group member name. Source user.peer.name user.local.name user.radius.name user.tacacs+.name user.ldap.name user.saml.name user
                              .external-identity-provider.name user.adgrp.name user.pop3.name user.certificate.name.
                        required: true
                        type: str
            mobile_phone:
                description:
                    - Enable/disable the guest user mobile phone number field.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            multiple_guest_add:
                description:
                    - Enable/disable addition of multiple guests.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            name:
                description:
                    - Group name.
                required: true
                type: str
            password:
                description:
                    - Guest user password type.
                type: str
                choices:
                    - 'auto-generate'
                    - 'specify'
                    - 'disable'
            sms_custom_server:
                description:
                    - SMS server. Source system.sms-server.name.
                type: str
            sms_server:
                description:
                    - Send SMS through FortiGuard or other external server.
                type: str
                choices:
                    - 'fortiguard'
                    - 'custom'
            sponsor:
                description:
                    - Set the action for the sponsor guest user field.
                type: str
                choices:
                    - 'optional'
                    - 'mandatory'
                    - 'disabled'
            sso_attribute_value:
                description:
                    - Name of the RADIUS user group that this local user group represents.
                type: str
            user_id:
                description:
                    - Guest user ID type.
                type: str
                choices:
                    - 'email'
                    - 'auto-generate'
                    - 'specify'
            user_name:
                description:
                    - Enable/disable the guest user name entry.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
"""

EXAMPLES = """
- name: Configure user groups.
  fortinet.fortios.fortios_user_group:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      user_group:
          auth_concurrent_override: "enable"
          auth_concurrent_value: "0"
          authtimeout: "0"
          company: "optional"
          email: "disable"
          expire: "14400"
          expire_type: "immediately"
          group_type: "firewall"
          guest:
              -
                  comment: "Comment."
                  company: "<your_own_value>"
                  email: "<your_own_value>"
                  expiration: "<your_own_value>"
                  id: "16"
                  mobile_phone: "<your_own_value>"
                  name: "default_name_18"
                  password: "<your_own_value>"
                  sponsor: "<your_own_value>"
                  user_id: "<your_own_value>"
          http_digest_realm: "<your_own_value>"
          id: "23"
          match:
              -
                  group_name: "<your_own_value>"
                  id: "26"
                  server_name: "<your_own_value> (source user.radius.name user.ldap.name user.tacacs+.name user.saml.name user.external-identity-provider
                    .name)"
          max_accounts: "0"
          member:
              -
                  name: "default_name_30 (source user.peer.name user.local.name user.radius.name user.tacacs+.name user.ldap.name user.saml.name user
                    .external-identity-provider.name user.adgrp.name user.pop3.name user.certificate.name)"
          mobile_phone: "disable"
          multiple_guest_add: "disable"
          name: "default_name_33"
          password: "auto-generate"
          sms_custom_server: "<your_own_value> (source system.sms-server.name)"
          sms_server: "fortiguard"
          sponsor: "optional"
          sso_attribute_value: "<your_own_value>"
          user_id: "email"
          user_name: "disable"
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


def filter_user_group_data(json):
    option_list = [
        "auth_concurrent_override",
        "auth_concurrent_value",
        "authtimeout",
        "company",
        "email",
        "expire",
        "expire_type",
        "group_type",
        "guest",
        "http_digest_realm",
        "id",
        "match",
        "max_accounts",
        "member",
        "mobile_phone",
        "multiple_guest_add",
        "name",
        "password",
        "sms_custom_server",
        "sms_server",
        "sponsor",
        "sso_attribute_value",
        "user_id",
        "user_name",
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


def user_group(data, fos, check_mode=False):
    state = None
    vdom = data["vdom"]

    state = data["state"]

    user_group_data = data["user_group"]
    filtered_data = filter_user_group_data(user_group_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("user", "group", filtered_data, vdom=vdom)
        current_data = fos.get("user", "group", vdom=vdom, mkey=mkey)
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
        return fos.set("user", "group", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("user", "group", mkey=converted_data["name"], vdom=vdom)
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
    fos.do_member_operation("user", "group")
    if data["user_group"]:
        resp = user_group(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("user_group"))
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
        "group_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "firewall"},
                {"value": "fsso-service"},
                {"value": "rsso"},
                {"value": "guest"},
            ],
        },
        "authtimeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "auth_concurrent_override": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "auth_concurrent_value": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "http_digest_realm": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "sso_attribute_value": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "member": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v6.0.0", ""]],
        },
        "match": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "server_name": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "group_name": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "user_id": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "email"},
                {"value": "auto-generate"},
                {"value": "specify"},
            ],
        },
        "password": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "auto-generate"},
                {"value": "specify"},
                {"value": "disable"},
            ],
        },
        "user_name": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "sponsor": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "optional"},
                {"value": "mandatory"},
                {"value": "disabled"},
            ],
        },
        "company": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "optional"},
                {"value": "mandatory"},
                {"value": "disabled"},
            ],
        },
        "email": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "mobile_phone": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "sms_server": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "fortiguard"}, {"value": "custom"}],
        },
        "sms_custom_server": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "expire_type": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "immediately"}, {"value": "first-successful-login"}],
        },
        "expire": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "max_accounts": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "multiple_guest_add": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "guest": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "user_id": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "name": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "password": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "mobile_phone": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "sponsor": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "company": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "email": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "expiration": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "comment": {"v_range": [["v6.0.0", ""]], "type": "string"},
            },
            "v_range": [["v6.0.0", ""]],
        },
        "id": {
            "v_range": [["v6.0.0", "v7.0.5"], ["v7.2.0", "v7.2.0"]],
            "type": "integer",
        },
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
        "user_group": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["user_group"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["user_group"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "user_group"
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
