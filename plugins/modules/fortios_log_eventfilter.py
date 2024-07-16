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
module: fortios_log_eventfilter
short_description: Configure log event filters in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify log feature and eventfilter category.
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

    log_eventfilter:
        description:
            - Configure log event filters.
        default: null
        type: dict
        suboptions:
            cifs:
                description:
                    - Enable/disable CIFS logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            compliance_check:
                description:
                    - Enable/disable PCI DSS compliance check logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            connector:
                description:
                    - Enable/disable SDN connector logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            endpoint:
                description:
                    - Enable/disable endpoint event logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            event:
                description:
                    - Enable/disable event logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fortiextender:
                description:
                    - Enable/disable FortiExtender logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ha:
                description:
                    - Enable/disable ha event logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            rest_api:
                description:
                    - Enable/disable REST API logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            router:
                description:
                    - Enable/disable router event logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sdwan:
                description:
                    - Enable/disable SD-WAN logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            security_rating:
                description:
                    - Enable/disable Security Rating result logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            switch_controller:
                description:
                    - Enable/disable Switch-Controller logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            system:
                description:
                    - Enable/disable system event logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            user:
                description:
                    - Enable/disable user authentication event logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            vpn:
                description:
                    - Enable/disable VPN event logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            wan_opt:
                description:
                    - Enable/disable WAN optimization event logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            webproxy:
                description:
                    - Enable/disable web proxy event logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            wireless_activity:
                description:
                    - Enable/disable wireless event logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure log event filters.
  fortinet.fortios.fortios_log_eventfilter:
      vdom: "{{ vdom }}"
      log_eventfilter:
          cifs: "enable"
          compliance_check: "enable"
          connector: "enable"
          endpoint: "enable"
          event: "enable"
          fortiextender: "enable"
          ha: "enable"
          rest_api: "enable"
          router: "enable"
          sdwan: "enable"
          security_rating: "enable"
          switch_controller: "enable"
          system: "enable"
          user: "enable"
          vpn: "enable"
          wan_opt: "enable"
          webproxy: "enable"
          wireless_activity: "enable"
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


def filter_log_eventfilter_data(json):
    option_list = [
        "cifs",
        "compliance_check",
        "connector",
        "endpoint",
        "event",
        "fortiextender",
        "ha",
        "rest_api",
        "router",
        "sdwan",
        "security_rating",
        "switch_controller",
        "system",
        "user",
        "vpn",
        "wan_opt",
        "webproxy",
        "wireless_activity",
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


def log_eventfilter(data, fos):
    state = None
    vdom = data["vdom"]
    log_eventfilter_data = data["log_eventfilter"]
    filtered_data = filter_log_eventfilter_data(log_eventfilter_data)
    converted_data = underscore_to_hyphen(filtered_data)

    return fos.set("log", "eventfilter", data=converted_data, vdom=vdom)


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


def fortios_log(data, fos):
    fos.do_member_operation("log", "eventfilter")
    if data["log_eventfilter"]:
        resp = log_eventfilter(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("log_eventfilter"))

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
        "event": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "system": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "vpn": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "user": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "router": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "wireless_activity": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "wan_opt": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "endpoint": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ha": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "security_rating": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "fortiextender": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "connector": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sdwan": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "cifs": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "switch_controller": {
            "v_range": [["v6.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "rest_api": {
            "v_range": [["v7.0.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "webproxy": {
            "v_range": [["v7.2.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "compliance_check": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
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
        "log_eventfilter": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["log_eventfilter"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["log_eventfilter"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "log_eventfilter"
        )

        is_error, has_changed, result, diff = fortios_log(module.params, fos)

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
