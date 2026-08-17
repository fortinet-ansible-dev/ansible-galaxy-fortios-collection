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
module: fortios_ztna_service_connector
short_description: Configure ZTNA service connector in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify ztna feature and service_connector category.
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
    - ansible>=2.16
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
    ztna_service_connector:
        description:
            - Configure ZTNA service connector.
        default: null
        type: dict
        suboptions:
            certificate:
                description:
                    - The name of the certificate to use for SSL handshake. Source vpn.certificate.local.name.
                type: str
            connection_mode:
                description:
                    - Connection mode.
                type: str
                choices:
                    - 'forward'
                    - 'reverse'
            encryption:
                description:
                    - Enable/disable Encryption .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            forward_address:
                description:
                    - service-connector address(IP or FQDN).
                type: str
            forward_destination_cn:
                description:
                    - CN for forward server.
                type: str
            forward_port:
                description:
                    - Port number that forward traffic uses to connect to
                type: int
            health_check_interval:
                description:
                    - health check interval(0-600 seconds).
                type: int
            log:
                description:
                    - Enable/disable logging of traffic.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            name:
                description:
                    - Service-connector name
                required: true
                type: str
            relay_dev_info:
                description:
                    - Enable/disable device info relay.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            relay_user_info:
                description:
                    - Enable/disable user info relay.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ssl_max_version:
                description:
                    - Highest SSL/TLS version acceptable from a server.
                type: str
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            ssl_min_version:
                description:
                    - Lowest SSL/TLS version acceptable from a server.
                type: str
                choices:
                    - 'ssl-3.0'
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            trusted_ca:
                description:
                    - Trusted CA certificate used by SSL inspection. Source vpn.certificate.ca.name.
                type: str
            url_map:
                description:
                    - URL pattern to match.
                type: str
"""
EXAMPLES = """
- name: Configure ZTNA service connector.
  fortinet.fortios.fortios_ztna_service_connector:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      ztna_service_connector:
          certificate: "<your_own_value> (source vpn.certificate.local.name)"
          connection_mode: "forward"
          encryption: "enable"
          forward_address: "<your_own_value>"
          forward_destination_cn: "<your_own_value>"
          forward_port: "0"
          health_check_interval: "60"
          log: "enable"
          name: "default_name_11"
          relay_dev_info: "enable"
          relay_user_info: "enable"
          ssl_max_version: "ssl-3.0"
          ssl_min_version: "ssl-3.0"
          trusted_ca: "<your_own_value> (source vpn.certificate.ca.name)"
          url_map: "<your_own_value>"
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


def filter_ztna_service_connector_data(json):
    option_list = [
        "certificate",
        "connection_mode",
        "encryption",
        "forward_address",
        "forward_destination_cn",
        "forward_port",
        "health_check_interval",
        "log",
        "name",
        "relay_dev_info",
        "relay_user_info",
        "ssl_max_version",
        "ssl_min_version",
        "trusted_ca",
        "url_map",
    ]

    json = remove_invalid_fields(json)
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def underscore_to_hyphen(data):
    new_data = None
    if isinstance(data, list):
        new_data = []
        for i, elem in enumerate(data):
            new_data.append(underscore_to_hyphen(elem))
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace("_", "-")] = underscore_to_hyphen(v)
    else:
        return data
    return new_data


def ztna_service_connector(data, fos):
    state = None
    vdom = data["vdom"]
    parameters = None
    state = data.get("state", None)
    ztna_service_connector_data = data["ztna_service_connector"]

    filtered_data = filter_ztna_service_connector_data(ztna_service_connector_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # pass post processed data to member operations
    # no need to do underscore_to_hyphen since do_member_operation handles it by itself
    data_copy = data.copy()
    data_copy["ztna_service_connector"] = filtered_data
    fos.do_member_operation(
        "ztna",
        "service-connector",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set(
            "ztna",
            "service-connector",
            data=converted_data,
            vdom=vdom,
            parameters=parameters,
        )

    elif state == "absent":
        return fos.delete(
            "ztna",
            "service-connector",
            mkey=converted_data["name"],
            vdom=vdom,
            parameters=parameters,
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


def fortios_ztna(data, fos):

    if data["ztna_service_connector"]:
        resp = ztna_service_connector(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("ztna_service_connector"))

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
        "name": {"v_range": [["v8.0.0", ""]], "type": "string", "required": True},
        "connection_mode": {
            "v_range": [["v8.0.0", ""]],
            "type": "string",
            "options": [{"value": "forward"}, {"value": "reverse"}],
        },
        "forward_address": {"v_range": [["v8.0.0", ""]], "type": "string"},
        "forward_port": {"v_range": [["v8.0.0", ""]], "type": "integer"},
        "forward_destination_cn": {"v_range": [["v8.0.0", ""]], "type": "string"},
        "certificate": {"v_range": [["v8.0.0", ""]], "type": "string"},
        "trusted_ca": {"v_range": [["v8.0.0", ""]], "type": "string"},
        "encryption": {
            "v_range": [["v8.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ssl_max_version": {
            "v_range": [["v8.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "ssl-3.0"},
                {"value": "tls-1.0"},
                {"value": "tls-1.1"},
                {"value": "tls-1.2"},
                {"value": "tls-1.3"},
            ],
        },
        "ssl_min_version": {
            "v_range": [["v8.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "ssl-3.0"},
                {"value": "tls-1.0"},
                {"value": "tls-1.1"},
                {"value": "tls-1.2"},
                {"value": "tls-1.3"},
            ],
        },
        "url_map": {"v_range": [["v8.0.0", ""]], "type": "string"},
        "relay_dev_info": {
            "v_range": [["v8.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "relay_user_info": {
            "v_range": [["v8.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "log": {
            "v_range": [["v8.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "health_check_interval": {"v_range": [["v8.0.0", ""]], "type": "integer"},
    },
    "v_range": [["v8.0.0", ""]],
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
        "ztna_service_connector": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["ztna_service_connector"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["ztna_service_connector"]["options"][attribute_name][
                "required"
            ] = True

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
        fos = FortiOSHandler(connection, module, mkeyname, admin_passwd_header=False)
        versions_check_result = check_schema_versioning(
            fos, versioned_schema, "ztna_service_connector"
        )

        is_error, has_changed, result, diff = fortios_ztna(module.params, fos)

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
