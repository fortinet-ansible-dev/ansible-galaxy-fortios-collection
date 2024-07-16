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
module: fortios_web_proxy_global
short_description: Configure Web proxy global settings in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify web_proxy feature and global category.
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

    web_proxy_global:
        description:
            - Configure Web proxy global settings.
        default: null
        type: dict
        suboptions:
            always_learn_client_ip:
                description:
                    - Enable/disable learning the client"s IP address from headers for every request.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            fast_policy_match:
                description:
                    - Enable/disable fast matching algorithm for explicit and transparent proxy policy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            forward_proxy_auth:
                description:
                    - Enable/disable forwarding proxy authentication headers.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            forward_server_affinity_timeout:
                description:
                    - Period of time before the source IP"s traffic is no longer assigned to the forwarding server (6 - 60 min).
                type: int
            ldap_user_cache:
                description:
                    - Enable/disable LDAP user cache for explicit and transparent proxy user.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            learn_client_ip:
                description:
                    - Enable/disable learning the client"s IP address from headers.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            learn_client_ip_from_header:
                description:
                    - Learn client IP address from the specified headers.
                type: list
                elements: str
                choices:
                    - 'true-client-ip'
                    - 'x-real-ip'
                    - 'x-forwarded-for'
            learn_client_ip_srcaddr:
                description:
                    - Source address name (srcaddr or srcaddr6 must be set).
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name.
                        required: true
                        type: str
            learn_client_ip_srcaddr6:
                description:
                    - IPv6 Source address name (srcaddr or srcaddr6 must be set).
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name firewall.addrgrp6.name.
                        required: true
                        type: str
            log_app_id:
                description:
                    - Enable/disable always log application type in traffic log.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            log_forward_server:
                description:
                    - Enable/disable forward server name logging in forward traffic log.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            log_policy_pending:
                description:
                    - Enable/disable logging sessions that are pending on policy matching.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            max_message_length:
                description:
                    - Maximum length of HTTP message, not including body (16 - 256 Kbytes).
                type: int
            max_request_length:
                description:
                    - Maximum length of HTTP request line (2 - 64 Kbytes).
                type: int
            max_waf_body_cache_length:
                description:
                    - Maximum length of HTTP messages processed by Web Application Firewall (WAF) (10 - 1024 Kbytes).
                type: int
            policy_category_deep_inspect:
                description:
                    - Enable/disable deep inspection for application level category policy matching.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            proxy_fqdn:
                description:
                    - Fully Qualified Domain Name (FQDN) that clients connect to  to connect to the explicit web proxy.
                type: str
            proxy_transparent_cert_inspection:
                description:
                    - Enable/disable transparent proxy certificate inspection.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            src_affinity_exempt_addr:
                description:
                    - IPv4 source addresses to exempt proxy affinity.
                type: list
                elements: str
            src_affinity_exempt_addr6:
                description:
                    - IPv6 source addresses to exempt proxy affinity.
                type: list
                elements: str
            ssl_ca_cert:
                description:
                    - SSL CA certificate for SSL interception. Source vpn.certificate.local.name.
                type: str
            ssl_cert:
                description:
                    - SSL certificate for SSL interception. Source vpn.certificate.local.name.
                type: str
            strict_web_check:
                description:
                    - Enable/disable strict web checking to block web sites that send incorrect headers that don"t conform to HTTP 1.1.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            tunnel_non_http:
                description:
                    - Enable/disable allowing non-HTTP traffic. Allowed non-HTTP traffic is tunneled.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            unknown_http_version:
                description:
                    - 'Action to take when an unknown version of HTTP is encountered: reject, allow (tunnel), or proceed with best-effort.'
                type: str
                choices:
                    - 'reject'
                    - 'tunnel'
                    - 'best-effort'
            webproxy_profile:
                description:
                    - Name of the web proxy profile to apply when explicit proxy traffic is allowed by default and traffic is accepted that does not match an
                       explicit proxy policy. Source web-proxy.profile.name.
                type: str
"""

EXAMPLES = """
- name: Configure Web proxy global settings.
  fortinet.fortios.fortios_web_proxy_global:
      vdom: "{{ vdom }}"
      web_proxy_global:
          always_learn_client_ip: "enable"
          fast_policy_match: "enable"
          forward_proxy_auth: "enable"
          forward_server_affinity_timeout: "30"
          ldap_user_cache: "enable"
          learn_client_ip: "enable"
          learn_client_ip_from_header: "true-client-ip"
          learn_client_ip_srcaddr:
              -
                  name: "default_name_11 (source firewall.address.name firewall.addrgrp.name)"
          learn_client_ip_srcaddr6:
              -
                  name: "default_name_13 (source firewall.address6.name firewall.addrgrp6.name)"
          log_app_id: "enable"
          log_forward_server: "enable"
          log_policy_pending: "enable"
          max_message_length: "32"
          max_request_length: "8"
          max_waf_body_cache_length: "32"
          policy_category_deep_inspect: "enable"
          proxy_fqdn: "<your_own_value>"
          proxy_transparent_cert_inspection: "enable"
          src_affinity_exempt_addr: "<your_own_value>"
          src_affinity_exempt_addr6: "<your_own_value>"
          ssl_ca_cert: "<your_own_value> (source vpn.certificate.local.name)"
          ssl_cert: "<your_own_value> (source vpn.certificate.local.name)"
          strict_web_check: "enable"
          tunnel_non_http: "enable"
          unknown_http_version: "reject"
          webproxy_profile: "<your_own_value> (source web-proxy.profile.name)"
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


def filter_web_proxy_global_data(json):
    option_list = [
        "always_learn_client_ip",
        "fast_policy_match",
        "forward_proxy_auth",
        "forward_server_affinity_timeout",
        "ldap_user_cache",
        "learn_client_ip",
        "learn_client_ip_from_header",
        "learn_client_ip_srcaddr",
        "learn_client_ip_srcaddr6",
        "log_app_id",
        "log_forward_server",
        "log_policy_pending",
        "max_message_length",
        "max_request_length",
        "max_waf_body_cache_length",
        "policy_category_deep_inspect",
        "proxy_fqdn",
        "proxy_transparent_cert_inspection",
        "src_affinity_exempt_addr",
        "src_affinity_exempt_addr6",
        "ssl_ca_cert",
        "ssl_cert",
        "strict_web_check",
        "tunnel_non_http",
        "unknown_http_version",
        "webproxy_profile",
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
        ["learn_client_ip_from_header"],
        ["src_affinity_exempt_addr"],
        ["src_affinity_exempt_addr6"],
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


def web_proxy_global(data, fos):
    state = None
    vdom = data["vdom"]
    web_proxy_global_data = data["web_proxy_global"]
    web_proxy_global_data = flatten_multilists_attributes(web_proxy_global_data)
    filtered_data = filter_web_proxy_global_data(web_proxy_global_data)
    converted_data = underscore_to_hyphen(filtered_data)

    return fos.set("web-proxy", "global", data=converted_data, vdom=vdom)


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


def fortios_web_proxy(data, fos):
    fos.do_member_operation("web-proxy", "global")
    if data["web_proxy_global"]:
        resp = web_proxy_global(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("web_proxy_global"))

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
        "ssl_cert": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "ssl_ca_cert": {"v_range": [["v6.2.0", ""]], "type": "string"},
        "fast_policy_match": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ldap_user_cache": {
            "v_range": [["v7.0.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "proxy_fqdn": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "max_request_length": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "max_message_length": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "strict_web_check": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "forward_proxy_auth": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "forward_server_affinity_timeout": {
            "v_range": [["v6.0.0", ""]],
            "type": "integer",
        },
        "max_waf_body_cache_length": {"v_range": [["v6.0.0", ""]], "type": "integer"},
        "webproxy_profile": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "learn_client_ip": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "always_learn_client_ip": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "learn_client_ip_from_header": {
            "v_range": [["v6.0.0", ""]],
            "type": "list",
            "options": [
                {"value": "true-client-ip"},
                {"value": "x-real-ip"},
                {"value": "x-forwarded-for"},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "learn_client_ip_srcaddr": {
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
        "learn_client_ip_srcaddr6": {
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
        "src_affinity_exempt_addr": {
            "v_range": [["v7.0.0", ""]],
            "type": "list",
            "multiple_values": True,
            "elements": "str",
        },
        "src_affinity_exempt_addr6": {
            "v_range": [["v7.0.0", ""]],
            "type": "list",
            "multiple_values": True,
            "elements": "str",
        },
        "policy_category_deep_inspect": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "log_policy_pending": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "log_forward_server": {
            "v_range": [["v7.4.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "log_app_id": {
            "v_range": [["v7.4.2", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "proxy_transparent_cert_inspection": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "tunnel_non_http": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "unknown_http_version": {
            "v_range": [["v6.0.0", "v6.2.7"]],
            "type": "string",
            "options": [
                {"value": "reject"},
                {"value": "tunnel"},
                {"value": "best-effort"},
            ],
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
        "web_proxy_global": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["web_proxy_global"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["web_proxy_global"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "web_proxy_global"
        )

        is_error, has_changed, result, diff = fortios_web_proxy(module.params, fos)

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
