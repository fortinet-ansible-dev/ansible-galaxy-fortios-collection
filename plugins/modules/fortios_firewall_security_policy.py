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
module: fortios_firewall_security_policy
short_description: Configure NGFW IPv4/IPv6 application policies in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and security_policy category.
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

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - present
            - absent
    firewall_security_policy:
        description:
            - Configure NGFW IPv4/IPv6 application policies.
        default: null
        type: dict
        suboptions:
            action:
                description:
                    - Policy action (accept/deny).
                type: str
                choices:
                    - accept
                    - deny
            app_category:
                description:
                    - Application category ID list.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Category IDs.
                        type: int
            app_group:
                description:
                    - Application group names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Application group names. Source application.group.name.
                        type: str
            application:
                description:
                    - Application ID list.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Application IDs.
                        type: int
            application_list:
                description:
                    - Name of an existing Application list. Source application.list.name.
                type: str
            av_profile:
                description:
                    - Name of an existing Antivirus profile. Source antivirus.profile.name.
                type: str
            cifs_profile:
                description:
                    - Name of an existing CIFS profile. Source cifs.profile.name.
                type: str
            comments:
                description:
                    - Comment.
                type: str
            dlp_profile:
                description:
                    - Name of an existing DLP profile. Source dlp.profile.name.
                type: str
            dlp_sensor:
                description:
                    - Name of an existing DLP sensor. Source dlp.sensor.name.
                type: str
            dnsfilter_profile:
                description:
                    - Name of an existing DNS filter profile. Source dnsfilter.profile.name.
                type: str
            dstaddr:
                description:
                    - Destination IPv4 address name and address group names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name firewall.vip.name firewall.vipgrp.name system.external-resource
                              .name.
                        type: str
            dstaddr_negate:
                description:
                    - When enabled dstaddr/dstaddr6 specifies what the destination address must NOT be.
                type: str
                choices:
                    - enable
                    - disable
            dstaddr4:
                description:
                    - Destination IPv4 address name and address group names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name firewall.vip.name firewall.vipgrp.name.
                        type: str
            dstaddr6:
                description:
                    - Destination IPv6 address name and address group names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name firewall.addrgrp6.name firewall.vip6.name firewall.vipgrp6.name system
                              .external-resource.name.
                        type: str
            dstintf:
                description:
                    - Outgoing (egress) interface.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Interface name. Source system.interface.name system.zone.name system.sdwan.zone.name.
                        type: str
            emailfilter_profile:
                description:
                    - Name of an existing email filter profile. Source emailfilter.profile.name.
                type: str
            enforce_default_app_port:
                description:
                    - Enable/disable default application port enforcement for allowed applications.
                type: str
                choices:
                    - enable
                    - disable
            file_filter_profile:
                description:
                    - Name of an existing file-filter profile. Source file-filter.profile.name.
                type: str
            fsso_groups:
                description:
                    - Names of FSSO groups.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Names of FSSO groups. Source user.adgrp.name.
                        type: str
            global_label:
                description:
                    - Label for the policy that appears when the GUI is in Global View mode.
                type: str
            groups:
                description:
                    - Names of user groups that can authenticate with this policy.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - User group name. Source user.group.name.
                        type: str
            icap_profile:
                description:
                    - Name of an existing ICAP profile. Source icap.profile.name.
                type: str
            internet_service:
                description:
                    - Enable/disable use of Internet Services for this policy. If enabled, destination address and service are not used.
                type: str
                choices:
                    - enable
                    - disable
            internet_service_custom:
                description:
                    - Custom Internet Service name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Custom Internet Service name. Source firewall.internet-service-custom.name.
                        type: str
            internet_service_custom_group:
                description:
                    - Custom Internet Service group name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Custom Internet Service group name. Source firewall.internet-service-custom-group.name.
                        type: str
            internet_service_group:
                description:
                    - Internet Service group name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Internet Service group name. Source firewall.internet-service-group.name.
                        type: str
            internet_service_id:
                description:
                    - Internet Service ID.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Internet Service ID. Source firewall.internet-service.id.
                        type: int
            internet_service_name:
                description:
                    - Internet Service name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Internet Service name. Source firewall.internet-service-name.name.
                        type: str
            internet_service_negate:
                description:
                    - When enabled internet-service specifies what the service must NOT be.
                type: str
                choices:
                    - enable
                    - disable
            internet_service_src:
                description:
                    - Enable/disable use of Internet Services in source for this policy. If enabled, source address is not used.
                type: str
                choices:
                    - enable
                    - disable
            internet_service_src_custom:
                description:
                    - Custom Internet Service source name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Custom Internet Service name. Source firewall.internet-service-custom.name.
                        type: str
            internet_service_src_custom_group:
                description:
                    - Custom Internet Service source group name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Custom Internet Service group name. Source firewall.internet-service-custom-group.name.
                        type: str
            internet_service_src_group:
                description:
                    - Internet Service source group name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Internet Service group name. Source firewall.internet-service-group.name.
                        type: str
            internet_service_src_id:
                description:
                    - Internet Service source ID.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Internet Service ID. Source firewall.internet-service.id.
                        type: int
            internet_service_src_name:
                description:
                    - Internet Service source name.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Internet Service name. Source firewall.internet-service-name.name.
                        type: str
            internet_service_src_negate:
                description:
                    - When enabled internet-service-src specifies what the service must NOT be.
                type: str
                choices:
                    - enable
                    - disable
            ips_sensor:
                description:
                    - Name of an existing IPS sensor. Source ips.sensor.name.
                type: str
            learning_mode:
                description:
                    - Enable to allow everything, but log all of the meaningful data for security information gathering. A learning report will be generated.
                type: str
                choices:
                    - enable
                    - disable
            logtraffic:
                description:
                    - Enable or disable logging. Log all sessions or security profile sessions.
                type: str
                choices:
                    - all
                    - utm
                    - disable
            logtraffic_start:
                description:
                    - Record logs when a session starts.
                type: str
                choices:
                    - enable
                    - disable
            mms_profile:
                description:
                    - Name of an existing MMS profile. Source firewall.mms-profile.name.
                type: str
            name:
                description:
                    - Policy name.
                type: str
            nat46:
                description:
                    - Enable/disable NAT46.
                type: str
                choices:
                    - enable
                    - disable
            nat64:
                description:
                    - Enable/disable NAT64.
                type: str
                choices:
                    - enable
                    - disable
            policyid:
                description:
                    - Policy ID.
                required: true
                type: int
            profile_group:
                description:
                    - Name of profile group. Source firewall.profile-group.name.
                type: str
            profile_protocol_options:
                description:
                    - Name of an existing Protocol options profile. Source firewall.profile-protocol-options.name.
                type: str
            profile_type:
                description:
                    - Determine whether the firewall policy allows security profile groups or single profiles only.
                type: str
                choices:
                    - single
                    - group
            schedule:
                description:
                    - Schedule name. Source firewall.schedule.onetime.name firewall.schedule.recurring.name firewall.schedule.group.name.
                type: str
            sctp_filter_profile:
                description:
                    - Name of an existing SCTP filter profile. Source sctp-filter.profile.name.
                type: str
            send_deny_packet:
                description:
                    - Enable to send a reply when a session is denied or blocked by a firewall policy.
                type: str
                choices:
                    - disable
                    - enable
            service:
                description:
                    - Service and service group names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Service name. Source firewall.service.custom.name firewall.service.group.name.
                        type: str
            service_negate:
                description:
                    - When enabled service specifies what the service must NOT be.
                type: str
                choices:
                    - enable
                    - disable
            srcaddr:
                description:
                    - Source IPv4 address name and address group names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name system.external-resource.name.
                        type: str
            srcaddr_negate:
                description:
                    - When enabled srcaddr/srcaddr6 specifies what the source address must NOT be.
                type: str
                choices:
                    - enable
                    - disable
            srcaddr4:
                description:
                    - Source IPv4 address name and address group names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name.
                        type: str
            srcaddr6:
                description:
                    - Source IPv6 address name and address group names.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name firewall.addrgrp6.name system.external-resource.name.
                        type: str
            srcintf:
                description:
                    - Incoming (ingress) interface.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Interface name. Source system.interface.name system.zone.name system.sdwan.zone.name.
                        type: str
            ssh_filter_profile:
                description:
                    - Name of an existing SSH filter profile. Source ssh-filter.profile.name.
                type: str
            ssl_ssh_profile:
                description:
                    - Name of an existing SSL SSH profile. Source firewall.ssl-ssh-profile.name.
                type: str
            status:
                description:
                    - Enable or disable this policy.
                type: str
                choices:
                    - enable
                    - disable
            url_category:
                description:
                    - URL categories or groups.
                type: list
                elements: str
            users:
                description:
                    - Names of individual users that can authenticate with this policy.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - User name. Source user.local.name.
                        type: str
            utm_status:
                description:
                    - Enable security profiles.
                type: str
                choices:
                    - enable
                    - disable
            uuid:
                description:
                    - Universally Unique Identifier (UUID; automatically assigned but can be manually reset).
                type: str
            uuid_idx:
                description:
                    - uuid-idx
                type: int
            videofilter_profile:
                description:
                    - Name of an existing VideoFilter profile. Source videofilter.profile.name.
                type: str
            voip_profile:
                description:
                    - Name of an existing VoIP profile. Source voip.profile.name.
                type: str
            webfilter_profile:
                description:
                    - Name of an existing Web filter profile. Source webfilter.profile.name.
                type: str
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
  - name: Configure NGFW IPv4/IPv6 application policies.
    fortios_firewall_security_policy:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_security_policy:
        action: "accept"
        app_category:
         -
            id:  "5"
        app_group:
         -
            name: "default_name_7 (source application.group.name)"
        application:
         -
            id:  "9"
        application_list: "<your_own_value> (source application.list.name)"
        av_profile: "<your_own_value> (source antivirus.profile.name)"
        cifs_profile: "<your_own_value> (source cifs.profile.name)"
        comments: "<your_own_value>"
        dlp_profile: "<your_own_value> (source dlp.profile.name)"
        dlp_sensor: "<your_own_value> (source dlp.sensor.name)"
        dnsfilter_profile: "<your_own_value> (source dnsfilter.profile.name)"
        dstaddr:
         -
            name: "default_name_18 (source firewall.address.name firewall.addrgrp.name firewall.vip.name firewall.vipgrp.name system.external-resource.name)"
        dstaddr_negate: "enable"
        dstaddr4:
         -
            name: "default_name_21 (source firewall.address.name firewall.addrgrp.name firewall.vip.name firewall.vipgrp.name)"
        dstaddr6:
         -
            name: "default_name_23 (source firewall.address6.name firewall.addrgrp6.name firewall.vip6.name firewall.vipgrp6.name system.external-resource
              .name)"
        dstintf:
         -
            name: "default_name_25 (source system.interface.name system.zone.name system.sdwan.zone.name)"
        emailfilter_profile: "<your_own_value> (source emailfilter.profile.name)"
        enforce_default_app_port: "enable"
        file_filter_profile: "<your_own_value> (source file-filter.profile.name)"
        fsso_groups:
         -
            name: "default_name_30 (source user.adgrp.name)"
        global_label: "<your_own_value>"
        groups:
         -
            name: "default_name_33 (source user.group.name)"
        icap_profile: "<your_own_value> (source icap.profile.name)"
        internet_service: "enable"
        internet_service_custom:
         -
            name: "default_name_37 (source firewall.internet-service-custom.name)"
        internet_service_custom_group:
         -
            name: "default_name_39 (source firewall.internet-service-custom-group.name)"
        internet_service_group:
         -
            name: "default_name_41 (source firewall.internet-service-group.name)"
        internet_service_id:
         -
            id:  "43 (source firewall.internet-service.id)"
        internet_service_name:
         -
            name: "default_name_45 (source firewall.internet-service-name.name)"
        internet_service_negate: "enable"
        internet_service_src: "enable"
        internet_service_src_custom:
         -
            name: "default_name_49 (source firewall.internet-service-custom.name)"
        internet_service_src_custom_group:
         -
            name: "default_name_51 (source firewall.internet-service-custom-group.name)"
        internet_service_src_group:
         -
            name: "default_name_53 (source firewall.internet-service-group.name)"
        internet_service_src_id:
         -
            id:  "55 (source firewall.internet-service.id)"
        internet_service_src_name:
         -
            name: "default_name_57 (source firewall.internet-service-name.name)"
        internet_service_src_negate: "enable"
        ips_sensor: "<your_own_value> (source ips.sensor.name)"
        learning_mode: "enable"
        logtraffic: "all"
        logtraffic_start: "enable"
        mms_profile: "<your_own_value> (source firewall.mms-profile.name)"
        name: "default_name_64"
        nat46: "enable"
        nat64: "enable"
        policyid: "67"
        profile_group: "<your_own_value> (source firewall.profile-group.name)"
        profile_protocol_options: "<your_own_value> (source firewall.profile-protocol-options.name)"
        profile_type: "single"
        schedule: "<your_own_value> (source firewall.schedule.onetime.name firewall.schedule.recurring.name firewall.schedule.group.name)"
        sctp_filter_profile: "<your_own_value> (source sctp-filter.profile.name)"
        send_deny_packet: "disable"
        service:
         -
            name: "default_name_75 (source firewall.service.custom.name firewall.service.group.name)"
        service_negate: "enable"
        srcaddr:
         -
            name: "default_name_78 (source firewall.address.name firewall.addrgrp.name system.external-resource.name)"
        srcaddr_negate: "enable"
        srcaddr4:
         -
            name: "default_name_81 (source firewall.address.name firewall.addrgrp.name)"
        srcaddr6:
         -
            name: "default_name_83 (source firewall.address6.name firewall.addrgrp6.name system.external-resource.name)"
        srcintf:
         -
            name: "default_name_85 (source system.interface.name system.zone.name system.sdwan.zone.name)"
        ssh_filter_profile: "<your_own_value> (source ssh-filter.profile.name)"
        ssl_ssh_profile: "<your_own_value> (source firewall.ssl-ssh-profile.name)"
        status: "enable"
        url_category: "<your_own_value>"
        users:
         -
            name: "default_name_91 (source user.local.name)"
        utm_status: "enable"
        uuid: "<your_own_value>"
        uuid_idx: "94"
        videofilter_profile: "<your_own_value> (source videofilter.profile.name)"
        voip_profile: "<your_own_value> (source voip.profile.name)"
        webfilter_profile: "<your_own_value> (source webfilter.profile.name)"

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
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.secret_field import (
    is_secret_field,
)


def filter_firewall_security_policy_data(json):
    option_list = [
        "action",
        "app_category",
        "app_group",
        "application",
        "application_list",
        "av_profile",
        "cifs_profile",
        "comments",
        "dlp_profile",
        "dlp_sensor",
        "dnsfilter_profile",
        "dstaddr",
        "dstaddr_negate",
        "dstaddr4",
        "dstaddr6",
        "dstintf",
        "emailfilter_profile",
        "enforce_default_app_port",
        "file_filter_profile",
        "fsso_groups",
        "global_label",
        "groups",
        "icap_profile",
        "internet_service",
        "internet_service_custom",
        "internet_service_custom_group",
        "internet_service_group",
        "internet_service_id",
        "internet_service_name",
        "internet_service_negate",
        "internet_service_src",
        "internet_service_src_custom",
        "internet_service_src_custom_group",
        "internet_service_src_group",
        "internet_service_src_id",
        "internet_service_src_name",
        "internet_service_src_negate",
        "ips_sensor",
        "learning_mode",
        "logtraffic",
        "logtraffic_start",
        "mms_profile",
        "name",
        "nat46",
        "nat64",
        "policyid",
        "profile_group",
        "profile_protocol_options",
        "profile_type",
        "schedule",
        "sctp_filter_profile",
        "send_deny_packet",
        "service",
        "service_negate",
        "srcaddr",
        "srcaddr_negate",
        "srcaddr4",
        "srcaddr6",
        "srcintf",
        "ssh_filter_profile",
        "ssl_ssh_profile",
        "status",
        "url_category",
        "users",
        "utm_status",
        "uuid",
        "uuid_idx",
        "videofilter_profile",
        "voip_profile",
        "webfilter_profile",
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
        ["url_category"],
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


def firewall_security_policy(data, fos, check_mode=False):

    vdom = data["vdom"]

    state = data["state"]

    firewall_security_policy_data = data["firewall_security_policy"]
    firewall_security_policy_data = flatten_multilists_attributes(
        firewall_security_policy_data
    )
    filtered_data = underscore_to_hyphen(
        filter_firewall_security_policy_data(firewall_security_policy_data)
    )

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("firewall", "security-policy", filtered_data, vdom=vdom)
        current_data = fos.get("firewall", "security-policy", vdom=vdom, mkey=mkey)
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
                return (
                    False,
                    not is_same,
                    filtered_data,
                    {"before": current_data["results"][0], "after": filtered_data},
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
        return fos.set("firewall", "security-policy", data=filtered_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "firewall", "security-policy", mkey=filtered_data["policyid"], vdom=vdom
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

    fos.do_member_operation("firewall", "security-policy")
    if data["firewall_security_policy"]:
        resp = firewall_security_policy(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("firewall_security_policy")
        )
    if check_mode:
        return resp
    return (
        not is_successful_status(resp),
        is_successful_status(resp)
        and (resp["revision_changed"] if "revision_changed" in resp else True),
        resp,
        {},
    )


versioned_schema = {
    "elements": "dict",
    "type": "list",
    "children": {
        "internet_service_src": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
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
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "icap_profile": {
            "type": "string",
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "enforce_default_app_port": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
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
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "ssh_filter_profile": {
            "type": "string",
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "internet_service_src_negate": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
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
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "srcaddr_negate": {
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
                        "v6.4.0": True,
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
                "v6.4.0": True,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
            },
        },
        "application_list": {
            "type": "string",
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "url_category": {
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
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "cifs_profile": {
            "type": "string",
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "service_negate": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
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
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "send_deny_packet": {
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
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
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
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
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
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "av_profile": {
            "type": "string",
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "mms_profile": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "learning_mode": {
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
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
            },
        },
        "internet_service_negate": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
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
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "internet_service_custom": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                }
            },
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "dstaddr": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                }
            },
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
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
            },
        },
        "uuid": {
            "type": "string",
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "service": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                }
            },
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "dlp_sensor": {
            "type": "string",
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
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "ssl_ssh_profile": {
            "type": "string",
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "internet_service_src_custom": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                }
            },
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "comments": {
            "type": "string",
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "application": {
            "elements": "dict",
            "type": "list",
            "children": {
                "id": {
                    "type": "integer",
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
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                }
            },
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "nat46": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.2.0": True,
                        "v7.0.2": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                    },
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.2.0": True,
                        "v7.0.2": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                    },
                },
            ],
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": False,
                "v7.0.0": False,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
            },
        },
        "dnsfilter_profile": {
            "type": "string",
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "profile_group": {
            "type": "string",
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "logtraffic": {
            "type": "string",
            "options": [
                {
                    "value": "all",
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
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                },
                {
                    "value": "utm",
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
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
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
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "nat64": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.2.0": True,
                        "v7.0.2": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                    },
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.2.0": True,
                        "v7.0.2": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                    },
                },
            ],
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": False,
                "v7.0.0": False,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
            },
        },
        "global_label": {
            "type": "string",
            "revisions": {"v6.2.0": False, "v6.2.3": True},
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
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
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "users": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                }
            },
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "profile_type": {
            "type": "string",
            "options": [
                {
                    "value": "single",
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
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                },
                {
                    "value": "group",
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
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
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
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "schedule": {
            "type": "string",
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "dstaddr4": {
            "elements": "dict",
            "type": "list",
            "children": {
                "name": {
                    "type": "string",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                }
            },
            "revisions": {
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "dstaddr6": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                }
            },
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "utm_status": {
            "type": "string",
            "options": [
                {"value": "enable", "revisions": {"v6.2.3": True}},
                {"value": "disable", "revisions": {"v6.2.3": True}},
            ],
            "revisions": {"v6.2.0": False, "v6.2.3": True},
        },
        "app_category": {
            "elements": "dict",
            "type": "list",
            "children": {
                "id": {
                    "type": "integer",
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
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                }
            },
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "videofilter_profile": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
            },
        },
        "srcaddr": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                }
            },
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
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
            },
        },
        "emailfilter_profile": {
            "type": "string",
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "policyid": {
            "type": "integer",
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "srcintf": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                }
            },
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "voip_profile": {
            "type": "string",
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "dlp_profile": {
            "type": "string",
            "revisions": {
                "v7.0.3": False,
                "v7.0.2": False,
                "v7.0.1": False,
                "v7.0.0": False,
                "v7.0.5": False,
                "v7.0.4": False,
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
            },
        },
        "internet_service_custom_group": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                }
            },
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "srcaddr6": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                }
            },
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "groups": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                }
            },
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "fsso_groups": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                }
            },
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "file_filter_profile": {
            "type": "string",
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
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
            },
        },
        "webfilter_profile": {
            "type": "string",
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "logtraffic_start": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                },
            ],
            "revisions": {
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
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
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "sctp_filter_profile": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": False,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
            },
        },
        "uuid_idx": {"type": "integer", "revisions": {"v6.2.0": False, "v6.2.3": True}},
        "internet_service_id": {
            "elements": "dict",
            "type": "list",
            "children": {
                "id": {
                    "type": "integer",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                }
            },
            "revisions": {
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "dstaddr_negate": {
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
                        "v6.4.0": True,
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
                "v6.4.0": True,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
            },
        },
        "ips_sensor": {
            "type": "string",
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "internet_service_src_name": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                }
            },
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
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
            },
        },
        "dstintf": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                }
            },
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "internet_service_name": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                }
            },
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
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
            },
        },
        "internet_service_src_id": {
            "elements": "dict",
            "type": "list",
            "children": {
                "id": {
                    "type": "integer",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                }
            },
            "revisions": {
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "internet_service_group": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                }
            },
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "internet_service_src_group": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                }
            },
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
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
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "srcaddr4": {
            "elements": "dict",
            "type": "list",
            "children": {
                "name": {
                    "type": "string",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                }
            },
            "revisions": {
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "internet_service_src_custom_group": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                }
            },
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "app_group": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                }
            },
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "profile_protocol_options": {
            "type": "string",
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
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
            },
        },
        "internet_service": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
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
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
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
        "v6.4.0": True,
        "v6.4.1": True,
        "v6.2.0": True,
        "v7.2.0": True,
        "v6.2.3": True,
        "v6.2.5": True,
        "v6.2.7": True,
    },
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
        "firewall_security_policy": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["firewall_security_policy"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_security_policy"]["options"][attribute_name][
                "required"
            ] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)
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
            fos, versioned_schema, "firewall_security_policy"
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
