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
module: fortios_system_csf
short_description: Add this FortiGate to a Security Fabric or set up a new Security Fabric on this FortiGate in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and csf category.
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
    - ansible>=2.9
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
            - present
            - absent

    system_csf:
        description:
            - Add this FortiGate to a Security Fabric or set up a new Security Fabric on this FortiGate.
        default: null
        type: dict
        suboptions:
            accept_auth_by_cert:
                description:
                    - Accept connections with unknown certificates and ask admin for approval.
                type: str
                choices:
                    - disable
                    - enable
            authorization_request_type:
                description:
                    - Authorization request type.
                type: str
                choices:
                    - serial
                    - certificate
            certificate:
                description:
                    - Certificate. Source certificate.local.name.
                type: str
            configuration_sync:
                description:
                    - Configuration sync mode.
                type: str
                choices:
                    - default
                    - local
            downstream_access:
                description:
                    - Enable/disable downstream device access to this device"s configuration and data.
                type: str
                choices:
                    - enable
                    - disable
            downstream_accprofile:
                description:
                    - Default access profile for requests from downstream devices. Source system.accprofile.name.
                type: str
            fabric_connector:
                description:
                    - Fabric connector configuration.
                type: list
                elements: dict
                suboptions:
                    accprofile:
                        description:
                            - Override access profile. Source system.accprofile.name.
                        type: str
                    configuration_write_access:
                        description:
                            - Enable/disable downstream device write access to configuration.
                        type: str
                        choices:
                            - enable
                            - disable
                    serial:
                        description:
                            - Serial.
                        type: str
            fabric_device:
                description:
                    - Fabric device configuration.
                type: list
                elements: dict
                suboptions:
                    access_token:
                        description:
                            - Device access token.
                        type: varlen_password
                    device_ip:
                        description:
                            - Device IP.
                        type: str
                    device_type:
                        description:
                            - Device type.
                        type: str
                        choices:
                            - fortimail
                    https_port:
                        description:
                            - HTTPS port for fabric device.
                        type: int
                    login:
                        description:
                            - Device login name.
                        type: str
                    name:
                        description:
                            - Device name.
                        type: str
                    password:
                        description:
                            - Device login password.
                        type: str
            fabric_object_unification:
                description:
                    - Fabric CMDB Object Unification.
                type: str
                choices:
                    - default
                    - local
            fabric_workers:
                description:
                    - Number of worker processes for Security Fabric daemon.
                type: int
            fixed_key:
                description:
                    - Auto-generated fixed key used when this device is the root. (Will automatically be generated if not set.)
                type: str
            forticloud_account_enforcement:
                description:
                    - Fabric FortiCloud account unification.
                type: str
                choices:
                    - enable
                    - disable
            group_name:
                description:
                    - Security Fabric group name. All FortiGates in a Security Fabric must have the same group name.
                type: str
            group_password:
                description:
                    - Security Fabric group password. All FortiGates in a Security Fabric must have the same group password.
                type: str
            log_unification:
                description:
                    - Enable/disable broadcast of discovery messages for log unification.
                type: str
                choices:
                    - disable
                    - enable
            management_ip:
                description:
                    - Management IP address of this FortiGate. Used to log into this FortiGate from another FortiGate in the Security Fabric.
                type: str
            management_port:
                description:
                    - Overriding port for management connection (Overrides admin port).
                type: int
            saml_configuration_sync:
                description:
                    - SAML setting configuration synchronization.
                type: str
                choices:
                    - default
                    - local
            status:
                description:
                    - Enable/disable Security Fabric.
                type: str
                choices:
                    - enable
                    - disable
            trusted_list:
                description:
                    - Pre-authorized and blocked security fabric nodes.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Security fabric authorization action.
                        type: str
                        choices:
                            - accept
                            - deny
                    authorization_type:
                        description:
                            - Authorization type.
                        type: str
                        choices:
                            - serial
                            - certificate
                    certificate:
                        description:
                            - Certificate.
                        type: str
                    downstream_authorization:
                        description:
                            - Trust authorizations by this node"s administrator.
                        type: str
                        choices:
                            - enable
                            - disable
                    ha_members:
                        description:
                            - HA members.
                        type: str
                    name:
                        description:
                            - Name.
                        type: str
                    serial:
                        description:
                            - Serial.
                        type: str
            upstream:
                description:
                    - IP/FQDN of the FortiGate upstream from this FortiGate in the Security Fabric.
                type: str
            upstream_ip:
                description:
                    - IP address of the FortiGate upstream from this FortiGate in the Security Fabric.
                type: str
            upstream_port:
                description:
                    - The port number to use to communicate with the FortiGate upstream from this FortiGate in the Security Fabric .
                type: int
"""

EXAMPLES = """
- hosts: fortigates
  collections:
    - fortinet.fortios
  connection: httpapi
  vars:
   vdom: "root"
   ansible_httpapi_use_ssl: yes
   ansible_httpapi_validate_certs: no
   ansible_httpapi_port: 443
  tasks:
  - name: Add this FortiGate to a Security Fabric or set up a new Security Fabric on this FortiGate.
    fortios_system_csf:
      vdom:  "{{ vdom }}"
      system_csf:
        accept_auth_by_cert: "disable"
        authorization_request_type: "serial"
        certificate: "<your_own_value> (source certificate.local.name)"
        configuration_sync: "default"
        downstream_access: "enable"
        downstream_accprofile: "<your_own_value> (source system.accprofile.name)"
        fabric_connector:
         -
            accprofile: "<your_own_value> (source system.accprofile.name)"
            configuration_write_access: "enable"
            serial: "<your_own_value>"
        fabric_device:
         -
            access_token: "<your_own_value>"
            device_ip: "<your_own_value>"
            device_type: "fortimail"
            https_port: "17"
            login: "<your_own_value>"
            name: "default_name_19"
            password: "<your_own_value>"
        fabric_object_unification: "default"
        fabric_workers: "22"
        fixed_key: "<your_own_value>"
        forticloud_account_enforcement: "enable"
        group_name: "<your_own_value>"
        group_password: "<your_own_value>"
        log_unification: "disable"
        management_ip: "<your_own_value>"
        management_port: "29"
        saml_configuration_sync: "default"
        status: "enable"
        trusted_list:
         -
            action: "accept"
            authorization_type: "serial"
            certificate: "<your_own_value>"
            downstream_authorization: "enable"
            ha_members: "<your_own_value>"
            name: "default_name_38"
            serial: "<your_own_value>"
        upstream: "<your_own_value>"
        upstream_ip: "<your_own_value>"
        upstream_port: "42"

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
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.secret_field import (
    is_secret_field,
)


def filter_system_csf_data(json):
    option_list = [
        "accept_auth_by_cert",
        "authorization_request_type",
        "certificate",
        "configuration_sync",
        "downstream_access",
        "downstream_accprofile",
        "fabric_connector",
        "fabric_device",
        "fabric_object_unification",
        "fabric_workers",
        "fixed_key",
        "forticloud_account_enforcement",
        "group_name",
        "group_password",
        "log_unification",
        "management_ip",
        "management_port",
        "saml_configuration_sync",
        "status",
        "trusted_list",
        "upstream",
        "upstream_ip",
        "upstream_port",
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
        ["trusted_list", "ha_members"],
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


def system_csf(data, fos):
    vdom = data["vdom"]
    system_csf_data = data["system_csf"]
    system_csf_data = flatten_multilists_attributes(system_csf_data)
    filtered_data = underscore_to_hyphen(filter_system_csf_data(system_csf_data))

    return fos.set("system", "csf", data=filtered_data, vdom=vdom)


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

    fos.do_member_operation("system", "csf")
    if data["system_csf"]:
        resp = system_csf(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_csf"))

    return (
        not is_successful_status(resp),
        is_successful_status(resp)
        and (resp["revision_changed"] if "revision_changed" in resp else True),
        resp,
        {},
    )


versioned_schema = {
    "type": "dict",
    "children": {
        "configuration_sync": {
            "type": "string",
            "options": [
                {
                    "value": "default",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                {
                    "value": "local",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
            ],
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "upstream_port": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "fabric_object_unification": {
            "type": "string",
            "options": [
                {
                    "value": "default",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                {
                    "value": "local",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
            ],
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "group_name": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "fabric_device": {
            "elements": "dict",
            "type": "list",
            "children": {
                "name": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "access_token": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": False,
                    },
                },
                "device_ip": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "device_type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "fortimail",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        }
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "login": {
                    "type": "string",
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "password": {
                    "type": "string",
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "https_port": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": False,
                    },
                },
            },
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "downstream_accprofile": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": False,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "saml_configuration_sync": {
            "type": "string",
            "options": [
                {
                    "value": "default",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v7.2.0": True,
                    },
                },
                {
                    "value": "local",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v7.2.0": True,
                    },
                },
            ],
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": True,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "forticloud_account_enforcement": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {"v7.2.0": True, "v7.0.5": True, "v7.0.4": True},
                },
                {
                    "value": "disable",
                    "revisions": {"v7.2.0": True, "v7.0.5": True, "v7.0.4": True},
                },
            ],
            "revisions": {
                "v7.0.3": False,
                "v7.0.2": False,
                "v7.0.1": False,
                "v7.0.0": False,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": False,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "log_unification": {
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.2.0": True,
                    },
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.2.0": True,
                    },
                },
            ],
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": False,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "management_port": {
            "type": "integer",
            "revisions": {
                "v6.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "downstream_access": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.2.0": True,
                    },
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.2.0": True,
                    },
                },
            ],
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": False,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "status": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
            ],
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "fabric_workers": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "fixed_key": {
            "type": "string",
            "revisions": {
                "v6.2.0": False,
                "v6.0.11": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.0.5": True,
            },
        },
        "trusted_list": {
            "elements": "dict",
            "type": "list",
            "children": {
                "authorization_type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "serial",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "certificate",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v7.2.0": True,
                            },
                        },
                    ],
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": True,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "name": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": True,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "certificate": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": True,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "ha_members": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "downstream_authorization": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                    ],
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "action": {
                    "type": "string",
                    "options": [
                        {
                            "value": "accept",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "deny",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                    ],
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "serial": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
            },
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "upstream": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": False,
                "v7.0.0": False,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": False,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "fabric_connector": {
            "elements": "dict",
            "type": "list",
            "children": {
                "serial": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.2.0": True,
                    },
                },
                "accprofile": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.2.0": True,
                    },
                },
                "configuration_write_access": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.2.0": True,
                            },
                        },
                    ],
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.2.0": True,
                    },
                },
            },
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": False,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "authorization_request_type": {
            "type": "string",
            "options": [
                {
                    "value": "serial",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v7.2.0": True,
                    },
                },
                {
                    "value": "certificate",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v7.2.0": True,
                    },
                },
            ],
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": True,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "certificate": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": True,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "management_ip": {
            "type": "string",
            "revisions": {
                "v6.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "accept_auth_by_cert": {
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v7.2.0": True,
                    },
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v7.2.0": True,
                    },
                },
            ],
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": True,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "upstream_ip": {
            "type": "string",
            "revisions": {
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "group_password": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
    },
    "revisions": {
        "v7.0.3": True,
        "v7.0.2": True,
        "v7.0.1": True,
        "v7.0.0": True,
        "v7.0.5": True,
        "v7.0.4": True,
        "v6.4.4": True,
        "v6.0.5": True,
        "v6.0.0": True,
        "v6.4.0": True,
        "v6.4.1": True,
        "v6.2.0": True,
        "v7.2.0": True,
        "v6.2.3": True,
        "v6.2.5": True,
        "v6.2.7": True,
        "v6.0.11": True,
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
        "system_csf": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_csf"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_csf"]["options"][attribute_name]["required"] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=False)
    check_legacy_fortiosapi(module)

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if "access_token" in module.params:
            connection.set_option("access_token", module.params["access_token"])

        if "enable_log" in module.params:
            connection.set_option("enable_log", module.params["enable_log"])
        else:
            connection.set_option("enable_log", False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(
            fos, versioned_schema, "system_csf"
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
