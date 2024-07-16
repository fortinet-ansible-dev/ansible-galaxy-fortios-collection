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
module: fortios_firewall_interface_policy
short_description: Configure IPv4 interface policies in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and interface_policy category.
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
    - We highly recommend using your own value as the policyid instead of 0, while '0' is a special placeholder that allows the backend to assign the latest
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
    firewall_interface_policy:
        description:
            - Configure IPv4 interface policies.
        default: null
        type: dict
        suboptions:
            address_type:
                description:
                    - Policy address type (IPv4 or IPv6).
                type: str
                choices:
                    - 'ipv4'
                    - 'ipv6'
            application_list:
                description:
                    - Application list name. Source application.list.name.
                type: str
            application_list_status:
                description:
                    - Enable/disable application control.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            av_profile:
                description:
                    - Antivirus profile. Source antivirus.profile.name.
                type: str
            av_profile_status:
                description:
                    - Enable/disable antivirus.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            casb_profile:
                description:
                    - CASB profile. Source casb.profile.name.
                type: str
            casb_profile_status:
                description:
                    - Enable/disable CASB.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            comments:
                description:
                    - Comments.
                type: str
            dlp_profile:
                description:
                    - DLP profile name. Source dlp.profile.name.
                type: str
            dlp_profile_status:
                description:
                    - Enable/disable DLP.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dlp_sensor:
                description:
                    - DLP sensor name. Source dlp.sensor.name.
                type: str
            dlp_sensor_status:
                description:
                    - Enable/disable DLP.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dsri:
                description:
                    - Enable/disable DSRI.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dstaddr:
                description:
                    - Address object to limit traffic monitoring to network traffic sent to the specified address or range.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name.
                        required: true
                        type: str
            emailfilter_profile:
                description:
                    - Email filter profile. Source emailfilter.profile.name.
                type: str
            emailfilter_profile_status:
                description:
                    - Enable/disable email filter.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            interface:
                description:
                    - Monitored interface name from available interfaces. Source system.zone.name system.interface.name.
                type: str
            ips_sensor:
                description:
                    - IPS sensor name. Source ips.sensor.name.
                type: str
            ips_sensor_status:
                description:
                    - Enable/disable IPS.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            label:
                description:
                    - Label.
                type: str
            logtraffic:
                description:
                    - 'Logging type to be used in this policy (Options: all | utm | disable).'
                type: str
                choices:
                    - 'all'
                    - 'utm'
                    - 'disable'
            policyid:
                description:
                    - Policy ID (0 - 4294967295). see <a href='#notes'>Notes</a>.
                required: true
                type: int
            scan_botnet_connections:
                description:
                    - Enable/disable scanning for connections to Botnet servers.
                type: str
                choices:
                    - 'disable'
                    - 'block'
                    - 'monitor'
            service:
                description:
                    - Service object from available options.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Service name. Source firewall.service.custom.name firewall.service.group.name.
                        required: true
                        type: str
            spamfilter_profile:
                description:
                    - Antispam profile. Source spamfilter.profile.name.
                type: str
            spamfilter_profile_status:
                description:
                    - Enable/disable antispam.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            srcaddr:
                description:
                    - Address object to limit traffic monitoring to network traffic sent from the specified address or range.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name.
                        required: true
                        type: str
            status:
                description:
                    - Enable/disable this policy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            uuid:
                description:
                    - Universally Unique Identifier (UUID; automatically assigned but can be manually reset).
                type: str
            webfilter_profile:
                description:
                    - Web filter profile. Source webfilter.profile.name.
                type: str
            webfilter_profile_status:
                description:
                    - Enable/disable web filtering.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure IPv4 interface policies.
  fortinet.fortios.fortios_firewall_interface_policy:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_interface_policy:
          address_type: "ipv4"
          application_list: "<your_own_value> (source application.list.name)"
          application_list_status: "enable"
          av_profile: "<your_own_value> (source antivirus.profile.name)"
          av_profile_status: "enable"
          casb_profile: "<your_own_value> (source casb.profile.name)"
          casb_profile_status: "enable"
          comments: "<your_own_value>"
          dlp_profile: "<your_own_value> (source dlp.profile.name)"
          dlp_profile_status: "enable"
          dlp_sensor: "<your_own_value> (source dlp.sensor.name)"
          dlp_sensor_status: "enable"
          dsri: "enable"
          dstaddr:
              -
                  name: "default_name_17 (source firewall.address.name firewall.addrgrp.name)"
          emailfilter_profile: "<your_own_value> (source emailfilter.profile.name)"
          emailfilter_profile_status: "enable"
          interface: "<your_own_value> (source system.zone.name system.interface.name)"
          ips_sensor: "<your_own_value> (source ips.sensor.name)"
          ips_sensor_status: "enable"
          label: "<your_own_value>"
          logtraffic: "all"
          policyid: "<you_own_value>"
          scan_botnet_connections: "disable"
          service:
              -
                  name: "default_name_28 (source firewall.service.custom.name firewall.service.group.name)"
          spamfilter_profile: "<your_own_value> (source spamfilter.profile.name)"
          spamfilter_profile_status: "enable"
          srcaddr:
              -
                  name: "default_name_32 (source firewall.address.name firewall.addrgrp.name)"
          status: "enable"
          uuid: "<your_own_value>"
          webfilter_profile: "<your_own_value> (source webfilter.profile.name)"
          webfilter_profile_status: "enable"
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


def filter_firewall_interface_policy_data(json):
    option_list = [
        "address_type",
        "application_list",
        "application_list_status",
        "av_profile",
        "av_profile_status",
        "casb_profile",
        "casb_profile_status",
        "comments",
        "dlp_profile",
        "dlp_profile_status",
        "dlp_sensor",
        "dlp_sensor_status",
        "dsri",
        "dstaddr",
        "emailfilter_profile",
        "emailfilter_profile_status",
        "interface",
        "ips_sensor",
        "ips_sensor_status",
        "label",
        "logtraffic",
        "policyid",
        "scan_botnet_connections",
        "service",
        "spamfilter_profile",
        "spamfilter_profile_status",
        "srcaddr",
        "status",
        "uuid",
        "webfilter_profile",
        "webfilter_profile_status",
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


def firewall_interface_policy(data, fos, check_mode=False):
    state = None
    vdom = data["vdom"]

    state = data["state"]

    firewall_interface_policy_data = data["firewall_interface_policy"]
    filtered_data = filter_firewall_interface_policy_data(
        firewall_interface_policy_data
    )
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("firewall", "interface-policy", filtered_data, vdom=vdom)
        current_data = fos.get("firewall", "interface-policy", vdom=vdom, mkey=mkey)
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
        return fos.set("firewall", "interface-policy", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "firewall", "interface-policy", mkey=converted_data["policyid"], vdom=vdom
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


def fortios_firewall(data, fos, check_mode):
    fos.do_member_operation("firewall", "interface-policy")
    if data["firewall_interface_policy"]:
        resp = firewall_interface_policy(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("firewall_interface_policy")
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
        "policyid": {"v_range": [["v6.0.0", ""]], "type": "integer", "required": True},
        "uuid": {"v_range": [["v7.4.2", ""]], "type": "string"},
        "status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "comments": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "logtraffic": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "all"}, {"value": "utm"}, {"value": "disable"}],
        },
        "interface": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "srcaddr": {
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
        "dstaddr": {
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
        "service": {
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
        "application_list_status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "application_list": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "ips_sensor_status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ips_sensor": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "dsri": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "av_profile_status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "av_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "webfilter_profile_status": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "webfilter_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "casb_profile_status": {
            "v_range": [["v7.4.1", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "casb_profile": {"v_range": [["v7.4.1", ""]], "type": "string"},
        "emailfilter_profile_status": {
            "v_range": [["v6.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "emailfilter_profile": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "dlp_profile_status": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dlp_profile": {"v_range": [["v7.2.0", ""]], "type": "string"},
        "dlp_sensor_status": {
            "v_range": [["v6.0.0", "v7.0.12"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dlp_sensor": {"v_range": [["v6.0.0", "v7.0.12"]], "type": "string"},
        "address_type": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "string",
            "options": [{"value": "ipv4"}, {"value": "ipv6"}],
        },
        "label": {
            "v_range": [["v6.0.0", "v6.0.11"], ["v6.2.3", "v6.2.3"]],
            "type": "string",
        },
        "spamfilter_profile_status": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "spamfilter_profile": {"v_range": [["v6.0.0", "v6.0.11"]], "type": "string"},
        "scan_botnet_connections": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "block"}, {"value": "monitor"}],
        },
    },
    "v_range": [["v6.0.0", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "policyid"
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
        "firewall_interface_policy": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_interface_policy"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_interface_policy"]["options"][attribute_name][
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
            fos, versioned_schema, "firewall_interface_policy"
        )

        is_error, has_changed, result, diff = fortios_firewall(
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
