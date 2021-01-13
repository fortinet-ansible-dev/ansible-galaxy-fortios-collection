#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
# Copyright 2019-2020 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fortios_system_accprofile
short_description: Configure access profiles for system administrators in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and accprofile category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.0
version_added: "2.8"
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
    - ansible>=2.9.0
options:
    access_token:
        description:
            - Token-based authentication.
              Generated from GUI of Fortigate.
        type: str
        required: false
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root

    state:
        description:
            - Indicates whether to create or remove the object.
              This attribute was present already in previous version in a deeper level.
              It has been moved out to this outer level.
        type: str
        required: false
        choices:
            - present
            - absent
        version_added: 2.9
    system_accprofile:
        description:
            - Configure access profiles for system administrators.
        default: null
        type: dict
        suboptions:
            state:
                description:
                    - B(Deprecated)
                    - Starting with Ansible 2.9 we recommend using the top-level 'state' parameter.
                    - HORIZONTALLINE
                    - Indicates whether to create or remove the object.
                type: str
                required: false
                choices:
                    - present
                    - absent
            admintimeout:
                description:
                    - Administrator timeout for this access profile (0 - 480 min).
                type: int
            admintimeout_override:
                description:
                    - Enable/disable overriding the global administrator idle timeout.
                type: str
                choices:
                    - enable
                    - disable
            authgrp:
                description:
                    - Administrator access to Users and Devices.
                type: str
                choices:
                    - none
                    - read
                    - read_write
            comments:
                description:
                    - Comment.
                type: str
            ftviewgrp:
                description:
                    - FortiView.
                type: str
                choices:
                    - none
                    - read
                    - read_write
            fwgrp:
                description:
                    - Administrator access to the Firewall configuration.
                type: str
                choices:
                    - none
                    - read
                    - read_write
                    - custom
            fwgrp_permission:
                description:
                    - Custom firewall permission.
                type: dict
                suboptions:
                    address:
                        description:
                            - Address Configuration.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
                    policy:
                        description:
                            - Policy Configuration.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
                    schedule:
                        description:
                            - Schedule Configuration.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
                    service:
                        description:
                            - Service Configuration.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
            loggrp:
                description:
                    - Administrator access to Logging and Reporting including viewing log messages.
                type: str
                choices:
                    - none
                    - read
                    - read_write
                    - custom
            loggrp_permission:
                description:
                    - Custom Log & Report permission.
                type: dict
                suboptions:
                    config:
                        description:
                            - Log & Report configuration.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
                    data_access:
                        description:
                            - Log & Report Data Access.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
                    report_access:
                        description:
                            - Log & Report Report Access.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
                    threat_weight:
                        description:
                            - Log & Report Threat Weight.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
            name:
                description:
                    - Profile name.
                required: true
                type: str
            netgrp:
                description:
                    - Network Configuration.
                type: str
                choices:
                    - none
                    - read
                    - read_write
                    - custom
            netgrp_permission:
                description:
                    - Custom network permission.
                type: dict
                suboptions:
                    cfg:
                        description:
                            - Network Configuration.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
                    packet_capture:
                        description:
                            - Packet Capture Configuration.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
                    route_cfg:
                        description:
                            - Router Configuration.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
            scope:
                description:
                    - 'Scope of admin access: global or specific VDOM(s).'
                type: str
                choices:
                    - vdom
                    - global
            secfabgrp:
                description:
                    - Security Fabric.
                type: str
                choices:
                    - none
                    - read
                    - read_write
            sysgrp:
                description:
                    - System Configuration.
                type: str
                choices:
                    - none
                    - read
                    - read_write
                    - custom
            sysgrp_permission:
                description:
                    - Custom system permission.
                type: dict
                suboptions:
                    admin:
                        description:
                            - Administrator Users.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
                    cfg:
                        description:
                            - System Configuration.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
                    mnt:
                        description:
                            - Maintenance.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
                    upd:
                        description:
                            - FortiGuard Updates.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
            system_diagnostics:
                description:
                    - Enable/disable permission to run system diagnostic commands.
                type: str
                choices:
                    - enable
                    - disable
            utmgrp:
                description:
                    - Administrator access to Security Profiles.
                type: str
                choices:
                    - none
                    - read
                    - read_write
                    - custom
            utmgrp_permission:
                description:
                    - Custom Security Profile permissions.
                type: dict
                suboptions:
                    antivirus:
                        description:
                            - Antivirus profiles and settings.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
                    application_control:
                        description:
                            - Application Control profiles and settings.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
                    data_loss_prevention:
                        description:
                            - DLP profiles and settings.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
                    dnsfilter:
                        description:
                            - DNS Filter profiles and settings.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
                    emailfilter:
                        description:
                            - AntiSpam filter and settings.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
                    endpoint_control:
                        description:
                            - FortiClient Profiles.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
                    file_filter:
                        description:
                            - File-filter profiles and settings.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
                    icap:
                        description:
                            - ICAP profiles and settings.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
                    ips:
                        description:
                            - IPS profiles and settings.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
                    mmsgtp:
                        description:
                            - UTM permission.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
                    spamfilter:
                        description:
                            - AntiSpam filter and settings.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
                    voip:
                        description:
                            - VoIP profiles and settings.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
                    waf:
                        description:
                            - Web Application Firewall profiles and settings.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
                    webfilter:
                        description:
                            - Web Filter profiles and settings.
                        type: str
                        choices:
                            - none
                            - read
                            - read_write
            vpngrp:
                description:
                    - Administrator access to IPsec, SSL, PPTP, and L2TP VPN.
                type: str
                choices:
                    - none
                    - read
                    - read_write
            wanoptgrp:
                description:
                    - Administrator access to WAN Opt & Cache.
                type: str
                choices:
                    - none
                    - read
                    - read_write
            wifi:
                description:
                    - Administrator access to the WiFi controller and Switch controller.
                type: str
                choices:
                    - none
                    - read
                    - read_write
'''

EXAMPLES = '''
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
  - name: Configure access profiles for system administrators.
    fortios_system_accprofile:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      system_accprofile:
        admintimeout: "3"
        admintimeout_override: "enable"
        authgrp: "none"
        comments: "<your_own_value>"
        ftviewgrp: "none"
        fwgrp: "none"
        fwgrp_permission:
            address: "none"
            policy: "none"
            schedule: "none"
            service: "none"
        loggrp: "none"
        loggrp_permission:
            config: "none"
            data_access: "none"
            report_access: "none"
            threat_weight: "none"
        name: "default_name_20"
        netgrp: "none"
        netgrp_permission:
            cfg: "none"
            packet_capture: "none"
            route_cfg: "none"
        scope: "vdom"
        secfabgrp: "none"
        sysgrp: "none"
        sysgrp_permission:
            admin: "none"
            cfg: "none"
            mnt: "none"
            upd: "none"
        system_diagnostics: "enable"
        utmgrp: "none"
        utmgrp_permission:
            antivirus: "none"
            application_control: "none"
            data_loss_prevention: "none"
            dnsfilter: "none"
            emailfilter: "none"
            endpoint_control: "none"
            file_filter: "none"
            icap: "none"
            ips: "none"
            mmsgtp: "none"
            spamfilter: "none"
            voip: "none"
            waf: "none"
            webfilter: "none"
        vpngrp: "none"
        wanoptgrp: "none"
        wifi: "none"

'''

RETURN = '''
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

'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import FortiOSHandler
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import check_legacy_fortiosapi
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import schema_to_module_spec
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import check_schema_versioning
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import FAIL_SOCKET_MSG


def filter_system_accprofile_data(json):
    option_list = ['admintimeout', 'admintimeout_override', 'authgrp',
                   'comments', 'ftviewgrp', 'fwgrp',
                   'fwgrp_permission', 'loggrp', 'loggrp_permission',
                   'name', 'netgrp', 'netgrp_permission',
                   'scope', 'secfabgrp', 'sysgrp',
                   'sysgrp_permission', 'system_diagnostics', 'utmgrp',
                   'utmgrp_permission', 'vpngrp', 'wanoptgrp',
                   'wifi']
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
            new_data[k.replace('_', '-')] = underscore_to_hyphen(v)
        data = new_data

    return data


def system_accprofile(data, fos):
    vdom = data['vdom']

    if 'state' in data and data['state']:
        state = data['state']
    elif 'state' in data['system_accprofile'] and data['system_accprofile']['state']:
        state = data['system_accprofile']['state']
    else:
        state = True
        fos._module.warn("state was not provided. Assuming 'present'.")

    system_accprofile_data = data['system_accprofile']
    filtered_data = underscore_to_hyphen(filter_system_accprofile_data(system_accprofile_data))

    if state == "present" or state == True:
        return fos.set('system',
                       'accprofile',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('system',
                          'accprofile',
                          mkey=filtered_data['name'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_system(data, fos):

    if data['system_accprofile']:
        resp = system_accprofile(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_accprofile'))

    return not is_successful_status(resp), \
        resp['status'] == "success" and \
        (resp['revision_changed'] if 'revision_changed' in resp else True), \
        resp


versioned_schema = {
    "type": "list",
    "children": {
        "ftviewgrp": {
            "type": "string",
            "options": [
                {
                    "value": "none",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "read",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "read-write",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "admintimeout": {
            "type": "integer",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "admintimeout_override": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "loggrp": {
            "type": "string",
            "options": [
                {
                    "value": "none",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "read",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "read-write",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "custom",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "netgrp_permission": {
            "type": "dict",
            "children": {
                "cfg": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "packet_capture": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "route_cfg": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            },
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "sysgrp_permission": {
            "type": "dict",
            "children": {
                "admin": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "cfg": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "upd": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "mnt": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            },
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "loggrp_permission": {
            "type": "dict",
            "children": {
                "data_access": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "config": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "report_access": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "threat_weight": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            },
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "utmgrp": {
            "type": "string",
            "options": [
                {
                    "value": "none",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "read",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "read-write",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "custom",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "fwgrp": {
            "type": "string",
            "options": [
                {
                    "value": "none",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "read",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "read-write",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "custom",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "comments": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "scope": {
            "type": "string",
            "options": [
                {
                    "value": "vdom",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "global",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "secfabgrp": {
            "type": "string",
            "options": [
                {
                    "value": "none",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "read",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "read-write",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "vpngrp": {
            "type": "string",
            "options": [
                {
                    "value": "none",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "read",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "read-write",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "sysgrp": {
            "type": "string",
            "options": [
                {
                    "value": "none",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "read",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "read-write",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "custom",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "fwgrp_permission": {
            "type": "dict",
            "children": {
                "policy": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "schedule": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "service": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "address": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            },
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "system_diagnostics": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "name": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "utmgrp_permission": {
            "type": "dict",
            "children": {
                "emailfilter": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "waf": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "dnsfilter": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "file_filter": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "antivirus": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "icap": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "ips": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "spamfilter": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.0.0": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.0.0": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.2.0": False,
                        "v6.0.0": True,
                        "v6.2.3": False,
                        "v6.4.0": False,
                        "v6.4.1": False
                    }
                },
                "endpoint_control": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "webfilter": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "application_control": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "mmsgtp": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "voip": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "data_loss_prevention": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "read-write",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.0.0": True,
                                "v6.2.3": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            },
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "wifi": {
            "type": "string",
            "options": [
                {
                    "value": "none",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "read",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "read-write",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "netgrp": {
            "type": "string",
            "options": [
                {
                    "value": "none",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "read",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "read-write",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "custom",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "wanoptgrp": {
            "type": "string",
            "options": [
                {
                    "value": "none",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "read",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "read-write",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "authgrp": {
            "type": "string",
            "options": [
                {
                    "value": "none",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "read",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "read-write",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        }
    },
    "revisions": {
        "v6.2.0": True,
        "v6.0.0": True,
        "v6.2.3": True,
        "v6.4.0": True,
        "v6.4.1": True
    }
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = 'name'
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "state": {"required": False, "type": "str",
                  "choices": ["present", "absent"]},
        "system_accprofile": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "state": {"required": False, "type": "str",
                          "choices": ["present", "absent"]}
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["system_accprofile"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_accprofile"]['options'][attribute_name]['required'] = True

    check_legacy_fortiosapi()
    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if 'access_token' in module.params:
            connection.set_option('access_token', module.params['access_token'])

        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(fos, versioned_schema, "system_accprofile")

        is_error, has_changed, result = fortios_system(module.params, fos)

    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result['matched'] is False:
        module.warn("Ansible has detected version mismatch between FortOS system and galaxy, see more details by specifying option -vvv")

    if not is_error:
        if versions_check_result and versions_check_result['matched'] is False:
            module.exit_json(changed=has_changed, version_check_warning=versions_check_result, meta=result)
        else:
            module.exit_json(changed=has_changed, meta=result)
    else:
        if versions_check_result and versions_check_result['matched'] is False:
            module.fail_json(msg="Error in repo", version_check_warning=versions_check_result, meta=result)
        else:
            module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
