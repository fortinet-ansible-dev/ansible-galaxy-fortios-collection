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
module: fortios_system_modem
short_description: Configure MODEM in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and modem category.
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

    system_modem:
        description:
            - Configure MODEM.
        default: null
        type: dict
        suboptions:
            action:
                description:
                    - Dial up/stop MODEM.
                type: str
                choices:
                    - 'dial'
                    - 'stop'
                    - 'none'
            altmode:
                description:
                    - Enable/disable altmode for installations using PPP in China.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            authtype1:
                description:
                    - Allowed authentication types for ISP 1.
                type: list
                elements: str
                choices:
                    - 'pap'
                    - 'chap'
                    - 'mschap'
                    - 'mschapv2'
            authtype2:
                description:
                    - Allowed authentication types for ISP 2.
                type: list
                elements: str
                choices:
                    - 'pap'
                    - 'chap'
                    - 'mschap'
                    - 'mschapv2'
            authtype3:
                description:
                    - Allowed authentication types for ISP 3.
                type: list
                elements: str
                choices:
                    - 'pap'
                    - 'chap'
                    - 'mschap'
                    - 'mschapv2'
            auto_dial:
                description:
                    - Enable/disable auto-dial after a reboot or disconnection.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            connect_timeout:
                description:
                    - Connection completion timeout (30 - 255 sec).
                type: int
            dial_cmd1:
                description:
                    - Dial command (this is often an ATD or ATDT command).
                type: str
            dial_cmd2:
                description:
                    - Dial command (this is often an ATD or ATDT command).
                type: str
            dial_cmd3:
                description:
                    - Dial command (this is often an ATD or ATDT command).
                type: str
            dial_on_demand:
                description:
                    - Enable/disable to dial the modem when packets are routed to the modem interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            distance:
                description:
                    - Distance of learned routes (1 - 255).
                type: int
            dont_send_CR1:
                description:
                    - Do not send CR when connected (ISP1).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dont_send_CR2:
                description:
                    - Do not send CR when connected (ISP2).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dont_send_CR3:
                description:
                    - Do not send CR when connected (ISP3).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            extra_init1:
                description:
                    - Extra initialization string to ISP 1.
                type: str
            extra_init2:
                description:
                    - Extra initialization string to ISP 2.
                type: str
            extra_init3:
                description:
                    - Extra initialization string to ISP 3.
                type: str
            holddown_timer:
                description:
                    - Hold down timer in seconds (1 - 60 sec).
                type: int
            idle_timer:
                description:
                    - MODEM connection idle time (1 - 9999 min).
                type: int
            interface:
                description:
                    - Name of redundant interface. Source system.interface.name.
                type: str
            lockdown_lac:
                description:
                    - Allow connection only to the specified Location Area Code (LAC).
                type: str
            mode:
                description:
                    - Set MODEM operation mode to redundant or standalone.
                type: str
                choices:
                    - 'standalone'
                    - 'redundant'
            network_init:
                description:
                    - AT command to set the Network name/type (AT+COPS=<mode>,[<format>,<oper>[,<AcT>]]).
                type: str
            passwd1:
                description:
                    - Password to access the specified dialup account.
                type: str
            passwd2:
                description:
                    - Password to access the specified dialup account.
                type: str
            passwd3:
                description:
                    - Password to access the specified dialup account.
                type: str
            peer_modem1:
                description:
                    - Specify peer MODEM type for phone1.
                type: str
                choices:
                    - 'generic'
                    - 'actiontec'
                    - 'ascend_TNT'
            peer_modem2:
                description:
                    - Specify peer MODEM type for phone2.
                type: str
                choices:
                    - 'generic'
                    - 'actiontec'
                    - 'ascend_TNT'
            peer_modem3:
                description:
                    - Specify peer MODEM type for phone3.
                type: str
                choices:
                    - 'generic'
                    - 'actiontec'
                    - 'ascend_TNT'
            phone1:
                description:
                    - Phone number to connect to the dialup account (must not contain spaces, and should include standard special characters).
                type: str
            phone2:
                description:
                    - Phone number to connect to the dialup account (must not contain spaces, and should include standard special characters).
                type: str
            phone3:
                description:
                    - Phone number to connect to the dialup account (must not contain spaces, and should include standard special characters).
                type: str
            pin_init:
                description:
                    - AT command to set the PIN (AT+PIN=<pin>).
                type: str
            ppp_echo_request1:
                description:
                    - Enable/disable PPP echo-request to ISP 1.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ppp_echo_request2:
                description:
                    - Enable/disable PPP echo-request to ISP 2.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ppp_echo_request3:
                description:
                    - Enable/disable PPP echo-request to ISP 3.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            priority:
                description:
                    - Priority of learned routes (1 - 65535).
                type: int
            redial:
                description:
                    - Redial limit (1 - 10 attempts, none = redial forever).
                type: str
                choices:
                    - 'none'
                    - '1'
                    - '2'
                    - '3'
                    - '4'
                    - '5'
                    - '6'
                    - '7'
                    - '8'
                    - '9'
                    - '10'
            reset:
                description:
                    - Number of dial attempts before resetting modem (0 = never reset).
                type: int
            status:
                description:
                    - Enable/disable Modem support (equivalent to bringing an interface up or down).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            traffic_check:
                description:
                    - Enable/disable traffic-check.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            username1:
                description:
                    - User name to access the specified dialup account.
                type: str
            username2:
                description:
                    - User name to access the specified dialup account.
                type: str
            username3:
                description:
                    - User name to access the specified dialup account.
                type: str
            wireless_port:
                description:
                    - 'Enter wireless port number: 0 for default, 1 for first port, and so on (0 - 4294967295).'
                type: int
"""

EXAMPLES = """
- name: Configure MODEM.
  fortinet.fortios.fortios_system_modem:
      vdom: "{{ vdom }}"
      system_modem:
          action: "dial"
          altmode: "enable"
          authtype1: "pap"
          authtype2: "pap"
          authtype3: "pap"
          auto_dial: "enable"
          connect_timeout: "90"
          dial_cmd1: "<your_own_value>"
          dial_cmd2: "<your_own_value>"
          dial_cmd3: "<your_own_value>"
          dial_on_demand: "enable"
          distance: "1"
          dont_send_CR1: "enable"
          dont_send_CR2: "enable"
          dont_send_CR3: "enable"
          extra_init1: "<your_own_value>"
          extra_init2: "<your_own_value>"
          extra_init3: "<your_own_value>"
          holddown_timer: "60"
          idle_timer: "5"
          interface: "<your_own_value> (source system.interface.name)"
          lockdown_lac: "<your_own_value>"
          mode: "standalone"
          network_init: "<your_own_value>"
          passwd1: "<your_own_value>"
          passwd2: "<your_own_value>"
          passwd3: "<your_own_value>"
          peer_modem1: "generic"
          peer_modem2: "generic"
          peer_modem3: "generic"
          phone1: "<your_own_value>"
          phone2: "<your_own_value>"
          phone3: "<your_own_value>"
          pin_init: "<your_own_value>"
          ppp_echo_request1: "enable"
          ppp_echo_request2: "enable"
          ppp_echo_request3: "enable"
          priority: "1"
          redial: "none"
          reset: "0"
          status: "enable"
          traffic_check: "enable"
          username1: "<your_own_value>"
          username2: "<your_own_value>"
          username3: "<your_own_value>"
          wireless_port: "0"
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


def filter_system_modem_data(json):
    option_list = [
        "action",
        "altmode",
        "authtype1",
        "authtype2",
        "authtype3",
        "auto_dial",
        "connect_timeout",
        "dial_cmd1",
        "dial_cmd2",
        "dial_cmd3",
        "dial_on_demand",
        "distance",
        "dont_send_CR1",
        "dont_send_CR2",
        "dont_send_CR3",
        "extra_init1",
        "extra_init2",
        "extra_init3",
        "holddown_timer",
        "idle_timer",
        "interface",
        "lockdown_lac",
        "mode",
        "network_init",
        "passwd1",
        "passwd2",
        "passwd3",
        "peer_modem1",
        "peer_modem2",
        "peer_modem3",
        "phone1",
        "phone2",
        "phone3",
        "pin_init",
        "ppp_echo_request1",
        "ppp_echo_request2",
        "ppp_echo_request3",
        "priority",
        "redial",
        "reset",
        "status",
        "traffic_check",
        "username1",
        "username2",
        "username3",
        "wireless_port",
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
        ["authtype1"],
        ["authtype2"],
        ["authtype3"],
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


def system_modem(data, fos):
    state = None
    vdom = data["vdom"]
    system_modem_data = data["system_modem"]
    system_modem_data = flatten_multilists_attributes(system_modem_data)
    filtered_data = filter_system_modem_data(system_modem_data)
    converted_data = underscore_to_hyphen(filtered_data)

    return fos.set("system", "modem", data=converted_data, vdom=vdom)


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
    fos.do_member_operation("system", "modem")
    if data["system_modem"]:
        resp = system_modem(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_modem"))

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
        "pin_init": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "network_init": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "lockdown_lac": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "standalone"}, {"value": "redundant"}],
        },
        "auto_dial": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dial_on_demand": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "idle_timer": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "redial": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "none"},
                {"value": "1"},
                {"value": "2"},
                {"value": "3"},
                {"value": "4"},
                {"value": "5"},
                {"value": "6"},
                {"value": "7"},
                {"value": "8"},
                {"value": "9"},
                {"value": "10"},
            ],
        },
        "reset": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "holddown_timer": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "connect_timeout": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "interface": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "wireless_port": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "dont_send_CR1": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "phone1": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dial_cmd1": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "username1": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "passwd1": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "extra_init1": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "peer_modem1": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "generic"},
                {"value": "actiontec"},
                {"value": "ascend_TNT"},
            ],
        },
        "ppp_echo_request1": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "authtype1": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "pap"},
                {"value": "chap"},
                {"value": "mschap"},
                {"value": "mschapv2"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "dont_send_CR2": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "phone2": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dial_cmd2": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "username2": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "passwd2": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "extra_init2": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "peer_modem2": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "generic"},
                {"value": "actiontec"},
                {"value": "ascend_TNT"},
            ],
        },
        "ppp_echo_request2": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "authtype2": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "pap"},
                {"value": "chap"},
                {"value": "mschap"},
                {"value": "mschapv2"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "dont_send_CR3": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "phone3": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dial_cmd3": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "username3": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "passwd3": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "extra_init3": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "peer_modem3": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "generic"},
                {"value": "actiontec"},
                {"value": "ascend_TNT"},
            ],
        },
        "ppp_echo_request3": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "altmode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "authtype3": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "pap"},
                {"value": "chap"},
                {"value": "mschap"},
                {"value": "mschapv2"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "traffic_check": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "action": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "dial"}, {"value": "stop"}, {"value": "none"}],
        },
        "distance": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "priority": {"v_range": [["v6.0.0", ""]], "type": "integer"},
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
        "system_modem": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_modem"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_modem"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_modem"
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
