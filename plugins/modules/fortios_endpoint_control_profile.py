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
module: fortios_endpoint_control_profile
short_description: Configure FortiClient endpoint control profiles in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify endpoint_control feature and profile category.
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
    endpoint_control_profile:
        description:
            - Configure FortiClient endpoint control profiles.
        default: null
        type: dict
        suboptions:
            description:
                description:
                    - Description.
                type: str
            device_groups:
                description:
                    - Device groups.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Device group object from available options. Source user.device-group.name user.device-category.name.
                        type: str
            forticlient_android_settings:
                description:
                    - FortiClient settings for Android platform.
                type: dict
                suboptions:
                    disable_wf_when_protected:
                        description:
                            - Enable/disable FortiClient web category filtering when protected by FortiGate.
                        type: str
                        choices:
                            - enable
                            - disable
                    forticlient_advanced_vpn:
                        description:
                            - Enable/disable advanced FortiClient VPN configuration.
                        type: str
                        choices:
                            - enable
                            - disable
                    forticlient_advanced_vpn_buffer:
                        description:
                            - Advanced FortiClient VPN configuration.
                        type: str
                    forticlient_vpn_provisioning:
                        description:
                            - Enable/disable FortiClient VPN provisioning.
                        type: str
                        choices:
                            - enable
                            - disable
                    forticlient_vpn_settings:
                        description:
                            - FortiClient VPN settings.
                        type: list
                        elements: dict
                        suboptions:
                            auth_method:
                                description:
                                    - Authentication method.
                                type: str
                                choices:
                                    - psk
                                    - certificate
                            name:
                                description:
                                    - VPN name.
                                type: str
                            preshared_key:
                                description:
                                    - Pre-shared secret for PSK authentication.
                                type: str
                            remote_gw:
                                description:
                                    - IP address or FQDN of the remote VPN gateway.
                                type: str
                            sslvpn_access_port:
                                description:
                                    - SSL VPN access port (1 - 65535).
                                type: int
                            sslvpn_require_certificate:
                                description:
                                    - Enable/disable requiring SSL VPN client certificate.
                                type: str
                                choices:
                                    - enable
                                    - disable
                            type:
                                description:
                                    - VPN type (IPsec or SSL VPN).
                                type: str
                                choices:
                                    - ipsec
                                    - ssl
                    forticlient_wf:
                        description:
                            - Enable/disable FortiClient web filtering.
                        type: str
                        choices:
                            - enable
                            - disable
                    forticlient_wf_profile:
                        description:
                            - The FortiClient web filter profile to apply. Source webfilter.profile.name.
                        type: str
            forticlient_ios_settings:
                description:
                    - FortiClient settings for iOS platform.
                type: dict
                suboptions:
                    client_vpn_provisioning:
                        description:
                            - FortiClient VPN provisioning.
                        type: str
                        choices:
                            - enable
                            - disable
                    client_vpn_settings:
                        description:
                            - FortiClient VPN settings.
                        type: list
                        elements: dict
                        suboptions:
                            auth_method:
                                description:
                                    - Authentication method.
                                type: str
                                choices:
                                    - psk
                                    - certificate
                            name:
                                description:
                                    - VPN name.
                                type: str
                            preshared_key:
                                description:
                                    - Pre-shared secret for PSK authentication.
                                type: str
                            remote_gw:
                                description:
                                    - IP address or FQDN of the remote VPN gateway.
                                type: str
                            sslvpn_access_port:
                                description:
                                    - SSL VPN access port (1 - 65535).
                                type: int
                            sslvpn_require_certificate:
                                description:
                                    - Enable/disable requiring SSL VPN client certificate.
                                type: str
                                choices:
                                    - enable
                                    - disable
                            type:
                                description:
                                    - VPN type (IPsec or SSL VPN).
                                type: str
                                choices:
                                    - ipsec
                                    - ssl
                            vpn_configuration_content:
                                description:
                                    - Content of VPN configuration.
                                type: str
                            vpn_configuration_name:
                                description:
                                    - Name of VPN configuration.
                                type: str
                    configuration_content:
                        description:
                            - Content of configuration profile.
                        type: str
                    configuration_name:
                        description:
                            - Name of configuration profile.
                        type: str
                    disable_wf_when_protected:
                        description:
                            - Enable/disable FortiClient web category filtering when protected by FortiGate.
                        type: str
                        choices:
                            - enable
                            - disable
                    distribute_configuration_profile:
                        description:
                            - Enable/disable configuration profile (.mobileconfig file) distribution.
                        type: str
                        choices:
                            - enable
                            - disable
                    forticlient_wf:
                        description:
                            - Enable/disable FortiClient web filtering.
                        type: str
                        choices:
                            - enable
                            - disable
                    forticlient_wf_profile:
                        description:
                            - The FortiClient web filter profile to apply. Source webfilter.profile.name.
                        type: str
            forticlient_winmac_settings:
                description:
                    - FortiClient settings for Windows/Mac platform.
                type: dict
                suboptions:
                    av_realtime_protection:
                        description:
                            - Enable/disable FortiClient AntiVirus real-time protection.
                        type: str
                        choices:
                            - enable
                            - disable
                    av_signature_up_to_date:
                        description:
                            - Enable/disable FortiClient AV signature updates.
                        type: str
                        choices:
                            - enable
                            - disable
                    forticlient_application_firewall:
                        description:
                            - Enable/disable the FortiClient application firewall.
                        type: str
                        choices:
                            - enable
                            - disable
                    forticlient_application_firewall_list:
                        description:
                            - FortiClient application firewall rule list. Source application.list.name.
                        type: str
                    forticlient_av:
                        description:
                            - Enable/disable FortiClient AntiVirus scanning.
                        type: str
                        choices:
                            - enable
                            - disable
                    forticlient_ems_compliance:
                        description:
                            - Enable/disable FortiClient Enterprise Management Server (EMS) compliance.
                        type: str
                        choices:
                            - enable
                            - disable
                    forticlient_ems_compliance_action:
                        description:
                            - FortiClient EMS compliance action.
                        type: str
                        choices:
                            - block
                            - warning
                    forticlient_ems_entries:
                        description:
                            - FortiClient EMS entries.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - FortiClient EMS name. Source endpoint-control.forticlient-ems.name.
                                type: str
                    forticlient_linux_ver:
                        description:
                            - Minimum FortiClient Linux version.
                        type: str
                    forticlient_log_upload:
                        description:
                            - Enable/disable uploading FortiClient logs.
                        type: str
                        choices:
                            - enable
                            - disable
                    forticlient_log_upload_level:
                        description:
                            - Select the FortiClient logs to upload.
                        type: str
                        choices:
                            - traffic
                            - vulnerability
                            - event
                    forticlient_log_upload_server:
                        description:
                            - IP address or FQDN of the server to which to upload FortiClient logs.
                        type: str
                    forticlient_mac_ver:
                        description:
                            - Minimum FortiClient Mac OS version.
                        type: str
                    forticlient_minimum_software_version:
                        description:
                            - Enable/disable requiring clients to run FortiClient with a minimum software version number.
                        type: str
                        choices:
                            - enable
                            - disable
                    forticlient_operating_system:
                        description:
                            - FortiClient operating system.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - Operating system entry ID.
                                type: int
                            os_name:
                                description:
                                    - 'Customize operating system name or Mac OS format:x.x.x'
                                type: str
                            os_type:
                                description:
                                    - Operating system type.
                                type: str
                                choices:
                                    - custom
                                    - mac-os
                                    - win-7
                                    - win-80
                                    - win-81
                                    - win-10
                                    - win-2000
                                    - win-home-svr
                                    - win-svr-10
                                    - win-svr-2003
                                    - win-svr-2003-r2
                                    - win-svr-2008
                                    - win-svr-2008-r2
                                    - win-svr-2012
                                    - win-svr-2012-r2
                                    - win-sto-svr-2003
                                    - win-vista
                                    - win-xp
                                    - ubuntu-linux
                                    - centos-linux
                                    - redhat-linux
                                    - fedora-linux
                    forticlient_own_file:
                        description:
                            - Checking the path and filename of the FortiClient application.
                        type: list
                        elements: dict
                        suboptions:
                            file:
                                description:
                                    - File path and name.
                                type: str
                            id:
                                description:
                                    - File ID.
                                type: int
                    forticlient_registration_compliance_action:
                        description:
                            - FortiClient registration compliance action.
                        type: str
                        choices:
                            - block
                            - warning
                    forticlient_registry_entry:
                        description:
                            - FortiClient registry entry.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - Registry entry ID.
                                type: int
                            registry_entry:
                                description:
                                    - Registry entry.
                                type: str
                    forticlient_running_app:
                        description:
                            - Use FortiClient to verify if the listed applications are running on the client.
                        type: list
                        elements: dict
                        suboptions:
                            app_name:
                                description:
                                    - Application name.
                                type: str
                            app_sha256_signature:
                                description:
                                    - App"s SHA256 signature.
                                type: str
                            app_sha256_signature2:
                                description:
                                    - App"s SHA256 Signature.
                                type: str
                            app_sha256_signature3:
                                description:
                                    - App"s SHA256 Signature.
                                type: str
                            app_sha256_signature4:
                                description:
                                    - App"s SHA256 Signature.
                                type: str
                            application_check_rule:
                                description:
                                    - Application check rule.
                                type: str
                                choices:
                                    - present
                                    - absent
                            id:
                                description:
                                    - Application ID.
                                type: int
                            process_name:
                                description:
                                    - Process name.
                                type: str
                            process_name2:
                                description:
                                    - Process name.
                                type: str
                            process_name3:
                                description:
                                    - Process name.
                                type: str
                            process_name4:
                                description:
                                    - Process name.
                                type: str
                    forticlient_security_posture:
                        description:
                            - Enable/disable FortiClient security posture check options.
                        type: str
                        choices:
                            - enable
                            - disable
                    forticlient_security_posture_compliance_action:
                        description:
                            - FortiClient security posture compliance action.
                        type: str
                        choices:
                            - block
                            - warning
                    forticlient_system_compliance:
                        description:
                            - Enable/disable enforcement of FortiClient system compliance.
                        type: str
                        choices:
                            - enable
                            - disable
                    forticlient_system_compliance_action:
                        description:
                            - Block or warn clients not compliant with FortiClient requirements.
                        type: str
                        choices:
                            - block
                            - warning
                    forticlient_vuln_scan:
                        description:
                            - Enable/disable FortiClient vulnerability scanning.
                        type: str
                        choices:
                            - enable
                            - disable
                    forticlient_vuln_scan_compliance_action:
                        description:
                            - FortiClient vulnerability compliance action.
                        type: str
                        choices:
                            - block
                            - warning
                    forticlient_vuln_scan_enforce:
                        description:
                            - Configure the level of the vulnerability found that causes a FortiClient vulnerability compliance action.
                        type: str
                        choices:
                            - critical
                            - high
                            - medium
                            - low
                            - info
                    forticlient_vuln_scan_enforce_grace:
                        description:
                            - FortiClient vulnerability scan enforcement grace period (0 - 30 days).
                        type: int
                    forticlient_vuln_scan_exempt:
                        description:
                            - Enable/disable compliance exemption for vulnerabilities that cannot be patched automatically.
                        type: str
                        choices:
                            - enable
                            - disable
                    forticlient_wf:
                        description:
                            - Enable/disable FortiClient web filtering.
                        type: str
                        choices:
                            - enable
                            - disable
                    forticlient_wf_profile:
                        description:
                            - The FortiClient web filter profile to apply. Source webfilter.profile.name.
                        type: str
                    forticlient_win_ver:
                        description:
                            - Minimum FortiClient Windows version.
                        type: str
                    os_av_software_installed:
                        description:
                            - Enable/disable checking for OS recognized AntiVirus software.
                        type: str
                        choices:
                            - enable
                            - disable
                    sandbox_address:
                        description:
                            - FortiSandbox address.
                        type: str
                    sandbox_analysis:
                        description:
                            - Enable/disable sending files to FortiSandbox for analysis.
                        type: str
                        choices:
                            - enable
                            - disable
            on_net_addr:
                description:
                    - Addresses for on-net detection.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address object from available options. Source firewall.address.name firewall.addrgrp.name.
                        type: str
            profile_name:
                description:
                    - Profile name.
                type: str
            replacemsg_override_group:
                description:
                    - Select an endpoint control replacement message override group from available options. Source system.replacemsg-group.name.
                type: str
            src_addr:
                description:
                    - Source addresses.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Address object from available options. Source firewall.address.name firewall.addrgrp.name.
                        type: str
            user_groups:
                description:
                    - User groups.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - User group name. Source user.group.name.
                        type: str
            users:
                description:
                    - Users.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - User name. Source user.local.name.
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
  - name: Configure FortiClient endpoint control profiles.
    fortios_endpoint_control_profile:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      endpoint_control_profile:
        description: "<your_own_value>"
        device_groups:
         -
            name: "default_name_5 (source user.device-group.name user.device-category.name)"
        forticlient_android_settings:
            disable_wf_when_protected: "enable"
            forticlient_advanced_vpn: "enable"
            forticlient_advanced_vpn_buffer: "<your_own_value>"
            forticlient_vpn_provisioning: "enable"
            forticlient_vpn_settings:
             -
                auth_method: "psk"
                name: "default_name_13"
                preshared_key: "<your_own_value>"
                remote_gw: "<your_own_value>"
                sslvpn_access_port: "16"
                sslvpn_require_certificate: "enable"
                type: "ipsec"
            forticlient_wf: "enable"
            forticlient_wf_profile: "<your_own_value> (source webfilter.profile.name)"
        forticlient_ios_settings:
            client_vpn_provisioning: "enable"
            client_vpn_settings:
             -
                auth_method: "psk"
                name: "default_name_25"
                preshared_key: "<your_own_value>"
                remote_gw: "<your_own_value>"
                sslvpn_access_port: "28"
                sslvpn_require_certificate: "enable"
                type: "ipsec"
                vpn_configuration_content: "<your_own_value>"
                vpn_configuration_name: "<your_own_value>"
            configuration_content: "<your_own_value>"
            configuration_name: "<your_own_value>"
            disable_wf_when_protected: "enable"
            distribute_configuration_profile: "enable"
            forticlient_wf: "enable"
            forticlient_wf_profile: "<your_own_value> (source webfilter.profile.name)"
        forticlient_winmac_settings:
            av_realtime_protection: "enable"
            av_signature_up_to_date: "enable"
            forticlient_application_firewall: "enable"
            forticlient_application_firewall_list: "<your_own_value> (source application.list.name)"
            forticlient_av: "enable"
            forticlient_ems_compliance: "enable"
            forticlient_ems_compliance_action: "block"
            forticlient_ems_entries:
             -
                name: "default_name_48 (source endpoint-control.forticlient-ems.name)"
            forticlient_linux_ver: "<your_own_value>"
            forticlient_log_upload: "enable"
            forticlient_log_upload_level: "traffic"
            forticlient_log_upload_server: "<your_own_value>"
            forticlient_mac_ver: "<your_own_value>"
            forticlient_minimum_software_version: "enable"
            forticlient_operating_system:
             -
                id:  "56"
                os_name: "<your_own_value>"
                os_type: "custom"
            forticlient_own_file:
             -
                file: "<your_own_value>"
                id:  "61"
            forticlient_registration_compliance_action: "block"
            forticlient_registry_entry:
             -
                id:  "64"
                registry_entry: "<your_own_value>"
            forticlient_running_app:
             -
                app_name: "<your_own_value>"
                app_sha256_signature: "<your_own_value>"
                app_sha256_signature2: "<your_own_value>"
                app_sha256_signature3: "<your_own_value>"
                app_sha256_signature4: "<your_own_value>"
                application_check_rule: "present"
                id:  "73"
                process_name: "<your_own_value>"
                process_name2: "<your_own_value>"
                process_name3: "<your_own_value>"
                process_name4: "<your_own_value>"
            forticlient_security_posture: "enable"
            forticlient_security_posture_compliance_action: "block"
            forticlient_system_compliance: "enable"
            forticlient_system_compliance_action: "block"
            forticlient_vuln_scan: "enable"
            forticlient_vuln_scan_compliance_action: "block"
            forticlient_vuln_scan_enforce: "critical"
            forticlient_vuln_scan_enforce_grace: "85"
            forticlient_vuln_scan_exempt: "enable"
            forticlient_wf: "enable"
            forticlient_wf_profile: "<your_own_value> (source webfilter.profile.name)"
            forticlient_win_ver: "<your_own_value>"
            os_av_software_installed: "enable"
            sandbox_address: "<your_own_value>"
            sandbox_analysis: "enable"
        on_net_addr:
         -
            name: "default_name_94 (source firewall.address.name firewall.addrgrp.name)"
        profile_name: "<your_own_value>"
        replacemsg_override_group: "<your_own_value> (source system.replacemsg-group.name)"
        src_addr:
         -
            name: "default_name_98 (source firewall.address.name firewall.addrgrp.name)"
        user_groups:
         -
            name: "default_name_100 (source user.group.name)"
        users:
         -
            name: "default_name_102 (source user.local.name)"

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


def filter_endpoint_control_profile_data(json):
    option_list = [
        "description",
        "device_groups",
        "forticlient_android_settings",
        "forticlient_ios_settings",
        "forticlient_winmac_settings",
        "on_net_addr",
        "profile_name",
        "replacemsg_override_group",
        "src_addr",
        "user_groups",
        "users",
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


def endpoint_control_profile(data, fos, check_mode=False):

    vdom = data["vdom"]

    state = data["state"]

    endpoint_control_profile_data = data["endpoint_control_profile"]
    filtered_data = underscore_to_hyphen(
        filter_endpoint_control_profile_data(endpoint_control_profile_data)
    )

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("endpoint-control", "profile", filtered_data, vdom=vdom)
        current_data = fos.get("endpoint-control", "profile", vdom=vdom, mkey=mkey)
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
        return fos.set("endpoint-control", "profile", data=filtered_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "endpoint-control", "profile", mkey=filtered_data["profile-name"], vdom=vdom
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


def fortios_endpoint_control(data, fos, check_mode):

    fos.do_member_operation("endpoint-control", "profile")
    if data["endpoint_control_profile"]:
        resp = endpoint_control_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("endpoint_control_profile")
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
        "forticlient_ios_settings": {
            "type": "dict",
            "children": {
                "forticlient_wf": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "client_vpn_settings": {
                    "elements": "dict",
                    "type": "list",
                    "children": {
                        "vpn_configuration_content": {
                            "type": "string",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "vpn_configuration_name": {
                            "type": "string",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "sslvpn_access_port": {
                            "type": "integer",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "sslvpn_require_certificate": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                            ],
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "preshared_key": {
                            "type": "string",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "remote_gw": {
                            "type": "string",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "type": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "ipsec",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "ssl",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                            ],
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "auth_method": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "psk",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "certificate",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                            ],
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "name": {
                            "type": "string",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    },
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "configuration_name": {
                    "type": "string",
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "client_vpn_provisioning": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "distribute_configuration_profile": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "disable_wf_when_protected": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_wf_profile": {
                    "type": "string",
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "configuration_content": {
                    "type": "string",
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
            },
            "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
        },
        "forticlient_android_settings": {
            "type": "dict",
            "children": {
                "forticlient_wf": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_vpn_provisioning": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_advanced_vpn_buffer": {
                    "type": "string",
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "disable_wf_when_protected": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_advanced_vpn": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_vpn_settings": {
                    "elements": "dict",
                    "type": "list",
                    "children": {
                        "name": {
                            "type": "string",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "sslvpn_access_port": {
                            "type": "integer",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "sslvpn_require_certificate": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                            ],
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "preshared_key": {
                            "type": "string",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "remote_gw": {
                            "type": "string",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "type": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "ipsec",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "ssl",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                            ],
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "auth_method": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "psk",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "certificate",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                            ],
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    },
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_wf_profile": {
                    "type": "string",
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
            },
            "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
        },
        "on_net_addr": {
            "elements": "dict",
            "type": "list",
            "children": {
                "name": {
                    "type": "string",
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                }
            },
            "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
        },
        "description": {
            "type": "string",
            "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
        },
        "user_groups": {
            "elements": "dict",
            "type": "list",
            "children": {
                "name": {
                    "type": "string",
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                }
            },
            "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
        },
        "profile_name": {
            "type": "string",
            "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
        },
        "forticlient_winmac_settings": {
            "type": "dict",
            "children": {
                "forticlient_wf": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_vuln_scan_compliance_action": {
                    "type": "string",
                    "options": [
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "warning",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_vuln_scan": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_application_firewall": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_own_file": {
                    "elements": "dict",
                    "type": "list",
                    "children": {
                        "id": {
                            "type": "integer",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "file": {
                            "type": "string",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    },
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_security_posture_compliance_action": {
                    "type": "string",
                    "options": [
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "warning",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "sandbox_address": {
                    "type": "string",
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_log_upload": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_log_upload_level": {
                    "type": "string",
                    "options": [
                        {
                            "value": "traffic",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "vulnerability",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "event",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_vuln_scan_exempt": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_vuln_scan_enforce": {
                    "type": "string",
                    "options": [
                        {
                            "value": "critical",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "high",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "medium",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "low",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "info",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "av_realtime_protection": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_minimum_software_version": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_mac_ver": {
                    "type": "string",
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_application_firewall_list": {
                    "type": "string",
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "sandbox_analysis": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_vuln_scan_enforce_grace": {
                    "type": "integer",
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_security_posture": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_registration_compliance_action": {
                    "type": "string",
                    "options": [
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "warning",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_system_compliance_action": {
                    "type": "string",
                    "options": [
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "warning",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_system_compliance": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_running_app": {
                    "elements": "dict",
                    "type": "list",
                    "children": {
                        "process_name3": {
                            "type": "string",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "app_name": {
                            "type": "string",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "app_sha256_signature3": {
                            "type": "string",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "app_sha256_signature2": {
                            "type": "string",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "process_name2": {
                            "type": "string",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "process_name": {
                            "type": "string",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "process_name4": {
                            "type": "string",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "app_sha256_signature": {
                            "type": "string",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "app_sha256_signature4": {
                            "type": "string",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "application_check_rule": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "present",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "absent",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                            ],
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "id": {
                            "type": "integer",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    },
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_operating_system": {
                    "elements": "dict",
                    "type": "list",
                    "children": {
                        "os_type": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "custom",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "mac-os",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "win-7",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "win-80",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "win-81",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "win-10",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "win-2000",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "win-home-svr",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "win-svr-10",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "win-svr-2003",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "win-svr-2003-r2",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "win-svr-2008",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "win-svr-2008-r2",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "win-svr-2012",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "win-svr-2012-r2",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "win-sto-svr-2003",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "win-vista",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "win-xp",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "ubuntu-linux",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "centos-linux",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "redhat-linux",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                                {
                                    "value": "fedora-linux",
                                    "revisions": {
                                        "v6.0.11": True,
                                        "v6.0.0": True,
                                        "v6.0.5": True,
                                    },
                                },
                            ],
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "os_name": {
                            "type": "string",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "id": {
                            "type": "integer",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    },
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_log_upload_server": {
                    "type": "string",
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "av_signature_up_to_date": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_registry_entry": {
                    "elements": "dict",
                    "type": "list",
                    "children": {
                        "registry_entry": {
                            "type": "string",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        "id": {
                            "type": "integer",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    },
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_wf_profile": {
                    "type": "string",
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_ems_entries": {
                    "elements": "dict",
                    "type": "list",
                    "children": {
                        "name": {
                            "type": "string",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        }
                    },
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_ems_compliance": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_linux_ver": {
                    "type": "string",
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "os_av_software_installed": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_av": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_win_ver": {
                    "type": "string",
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "forticlient_ems_compliance_action": {
                    "type": "string",
                    "options": [
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "warning",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
            },
            "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
        },
        "device_groups": {
            "elements": "dict",
            "type": "list",
            "children": {
                "name": {
                    "type": "string",
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                }
            },
            "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
        },
        "src_addr": {
            "elements": "dict",
            "type": "list",
            "children": {
                "name": {
                    "type": "string",
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                }
            },
            "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
        },
        "replacemsg_override_group": {
            "type": "string",
            "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
        },
        "users": {
            "elements": "dict",
            "type": "list",
            "children": {
                "name": {
                    "type": "string",
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                }
            },
            "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
        },
    },
    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "profile-name"
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
        "endpoint_control_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["endpoint_control_profile"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["endpoint_control_profile"]["options"][attribute_name][
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
            fos, versioned_schema, "endpoint_control_profile"
        )

        is_error, has_changed, result, diff = fortios_endpoint_control(
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
