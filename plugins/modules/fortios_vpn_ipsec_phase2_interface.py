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
module: fortios_vpn_ipsec_phase2_interface
short_description: Configure VPN autokey tunnel in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify vpn_ipsec feature and phase2_interface category.
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
    vpn_ipsec_phase2_interface:
        description:
            - Configure VPN autokey tunnel.
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
            add_route:
                description:
                    - Enable/disable automatic route addition.
                type: str
                choices:
                    - phase1
                    - enable
                    - disable
            auto_discovery_forwarder:
                description:
                    - Enable/disable forwarding short-cut messages.
                type: str
                choices:
                    - phase1
                    - enable
                    - disable
            auto_discovery_sender:
                description:
                    - Enable/disable sending short-cut messages.
                type: str
                choices:
                    - phase1
                    - enable
                    - disable
            auto_negotiate:
                description:
                    - Enable/disable IPsec SA auto-negotiation.
                type: str
                choices:
                    - enable
                    - disable
            comments:
                description:
                    - Comment.
                type: str
            dhcp_ipsec:
                description:
                    - Enable/disable DHCP-IPsec.
                type: str
                choices:
                    - enable
                    - disable
            dhgrp:
                description:
                    - Phase2 DH group.
                type: list
                choices:
                    - 1
                    - 2
                    - 5
                    - 14
                    - 15
                    - 16
                    - 17
                    - 18
                    - 19
                    - 20
                    - 21
                    - 27
                    - 28
                    - 29
                    - 30
                    - 31
                    - 32
            dst_addr_type:
                description:
                    - Remote proxy ID type.
                type: str
                choices:
                    - subnet
                    - range
                    - ip
                    - name
                    - subnet6
                    - range6
                    - ip6
                    - name6
            dst_end_ip:
                description:
                    - Remote proxy ID IPv4 end.
                type: str
            dst_end_ip6:
                description:
                    - Remote proxy ID IPv6 end.
                type: str
            dst_name:
                description:
                    - Remote proxy ID name. Source firewall.address.name firewall.addrgrp.name.
                type: str
            dst_name6:
                description:
                    - Remote proxy ID name. Source firewall.address6.name firewall.addrgrp6.name.
                type: str
            dst_port:
                description:
                    - Quick mode destination port (1 - 65535 or 0 for all).
                type: int
            dst_start_ip:
                description:
                    - Remote proxy ID IPv4 start.
                type: str
            dst_start_ip6:
                description:
                    - Remote proxy ID IPv6 start.
                type: str
            dst_subnet:
                description:
                    - Remote proxy ID IPv4 subnet.
                type: str
            dst_subnet6:
                description:
                    - Remote proxy ID IPv6 subnet.
                type: str
            encapsulation:
                description:
                    - ESP encapsulation mode.
                type: str
                choices:
                    - tunnel_mode
                    - transport_mode
            ipv4_df:
                description:
                    - Enable/disable setting and resetting of IPv4 "Don"t Fragment" bit.
                type: str
                choices:
                    - enable
                    - disable
            keepalive:
                description:
                    - Enable/disable keep alive.
                type: str
                choices:
                    - enable
                    - disable
            keylife_type:
                description:
                    - Keylife type.
                type: str
                choices:
                    - seconds
                    - kbs
                    - both
            keylifekbs:
                description:
                    - Phase2 key life in number of bytes of traffic (5120 - 4294967295).
                type: int
            keylifeseconds:
                description:
                    - Phase2 key life in time in seconds (120 - 172800).
                type: int
            l2tp:
                description:
                    - Enable/disable L2TP over IPsec.
                type: str
                choices:
                    - enable
                    - disable
            name:
                description:
                    - IPsec tunnel name.
                required: true
                type: str
            pfs:
                description:
                    - Enable/disable PFS feature.
                type: str
                choices:
                    - enable
                    - disable
            phase1name:
                description:
                    - Phase 1 determines the options required for phase 2. Source vpn.ipsec.phase1-interface.name.
                type: str
            proposal:
                description:
                    - Phase2 proposal.
                type: list
                choices:
                    - null_md5
                    - null_sha1
                    - null_sha256
                    - null_sha384
                    - null_sha512
                    - des_null
                    - des_md5
                    - des_sha1
                    - des_sha256
                    - des_sha384
                    - des_sha512
                    - 3des_null
                    - 3des_md5
                    - 3des_sha1
                    - 3des_sha256
                    - 3des_sha384
                    - 3des_sha512
                    - aes128_null
                    - aes128_md5
                    - aes128_sha1
                    - aes128_sha256
                    - aes128_sha384
                    - aes128_sha512
                    - aes128gcm
                    - aes192_null
                    - aes192_md5
                    - aes192_sha1
                    - aes192_sha256
                    - aes192_sha384
                    - aes192_sha512
                    - aes256_null
                    - aes256_md5
                    - aes256_sha1
                    - aes256_sha256
                    - aes256_sha384
                    - aes256_sha512
                    - aes256gcm
                    - chacha20poly1305
                    - aria128_null
                    - aria128_md5
                    - aria128_sha1
                    - aria128_sha256
                    - aria128_sha384
                    - aria128_sha512
                    - aria192_null
                    - aria192_md5
                    - aria192_sha1
                    - aria192_sha256
                    - aria192_sha384
                    - aria192_sha512
                    - aria256_null
                    - aria256_md5
                    - aria256_sha1
                    - aria256_sha256
                    - aria256_sha384
                    - aria256_sha512
                    - seed_null
                    - seed_md5
                    - seed_sha1
                    - seed_sha256
                    - seed_sha384
                    - seed_sha512
            protocol:
                description:
                    - Quick mode protocol selector (1 - 255 or 0 for all).
                type: int
            replay:
                description:
                    - Enable/disable replay detection.
                type: str
                choices:
                    - enable
                    - disable
            route_overlap:
                description:
                    - Action for overlapping routes.
                type: str
                choices:
                    - use_old
                    - use_new
                    - allow
            single_source:
                description:
                    - Enable/disable single source IP restriction.
                type: str
                choices:
                    - enable
                    - disable
            src_addr_type:
                description:
                    - Local proxy ID type.
                type: str
                choices:
                    - subnet
                    - range
                    - ip
                    - name
                    - subnet6
                    - range6
                    - ip6
                    - name6
            src_end_ip:
                description:
                    - Local proxy ID end.
                type: str
            src_end_ip6:
                description:
                    - Local proxy ID IPv6 end.
                type: str
            src_name:
                description:
                    - Local proxy ID name. Source firewall.address.name firewall.addrgrp.name.
                type: str
            src_name6:
                description:
                    - Local proxy ID name. Source firewall.address6.name firewall.addrgrp6.name.
                type: str
            src_port:
                description:
                    - Quick mode source port (1 - 65535 or 0 for all).
                type: int
            src_start_ip:
                description:
                    - Local proxy ID start.
                type: str
            src_start_ip6:
                description:
                    - Local proxy ID IPv6 start.
                type: str
            src_subnet:
                description:
                    - Local proxy ID subnet.
                type: str
            src_subnet6:
                description:
                    - Local proxy ID IPv6 subnet.
                type: str
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
  - name: Configure VPN autokey tunnel.
    fortios_vpn_ipsec_phase2_interface:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      vpn_ipsec_phase2_interface:
        add_route: "phase1"
        auto_discovery_forwarder: "phase1"
        auto_discovery_sender: "phase1"
        auto_negotiate: "enable"
        comments: "<your_own_value>"
        dhcp_ipsec: "enable"
        dhgrp: "1"
        dst_addr_type: "subnet"
        dst_end_ip: "<your_own_value>"
        dst_end_ip6: "<your_own_value>"
        dst_name: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
        dst_name6: "<your_own_value> (source firewall.address6.name firewall.addrgrp6.name)"
        dst_port: "15"
        dst_start_ip: "<your_own_value>"
        dst_start_ip6: "<your_own_value>"
        dst_subnet: "<your_own_value>"
        dst_subnet6: "<your_own_value>"
        encapsulation: "tunnel_mode"
        ipv4_df: "enable"
        keepalive: "enable"
        keylife_type: "seconds"
        keylifekbs: "24"
        keylifeseconds: "25"
        l2tp: "enable"
        name: "default_name_27"
        pfs: "enable"
        phase1name: "<your_own_value> (source vpn.ipsec.phase1-interface.name)"
        proposal: "null_md5"
        protocol: "31"
        replay: "enable"
        route_overlap: "use_old"
        single_source: "enable"
        src_addr_type: "subnet"
        src_end_ip: "<your_own_value>"
        src_end_ip6: "<your_own_value>"
        src_name: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
        src_name6: "<your_own_value> (source firewall.address6.name firewall.addrgrp6.name)"
        src_port: "40"
        src_start_ip: "<your_own_value>"
        src_start_ip6: "<your_own_value>"
        src_subnet: "<your_own_value>"
        src_subnet6: "<your_own_value>"

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


def filter_vpn_ipsec_phase2_interface_data(json):
    option_list = ['add_route', 'auto_discovery_forwarder', 'auto_discovery_sender',
                   'auto_negotiate', 'comments', 'dhcp_ipsec',
                   'dhgrp', 'dst_addr_type', 'dst_end_ip',
                   'dst_end_ip6', 'dst_name', 'dst_name6',
                   'dst_port', 'dst_start_ip', 'dst_start_ip6',
                   'dst_subnet', 'dst_subnet6', 'encapsulation',
                   'ipv4_df', 'keepalive', 'keylife_type',
                   'keylifekbs', 'keylifeseconds', 'l2tp',
                   'name', 'pfs', 'phase1name',
                   'proposal', 'protocol', 'replay',
                   'route_overlap', 'single_source', 'src_addr_type',
                   'src_end_ip', 'src_end_ip6', 'src_name',
                   'src_name6', 'src_port', 'src_start_ip',
                   'src_start_ip6', 'src_subnet', 'src_subnet6']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def flatten_multilists_attributes(data):
    multilist_attrs = [[u'dhgrp'], [u'proposal']]

    for attr in multilist_attrs:
        try:
            path = "data['" + "']['".join(elem for elem in attr) + "']"
            current_val = eval(path)
            flattened_val = ' '.join(elem for elem in current_val)
            exec(path + '= flattened_val')
        except BaseException:
            pass

    return data


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


def vpn_ipsec_phase2_interface(data, fos):
    vdom = data['vdom']

    if 'state' in data and data['state']:
        state = data['state']
    elif 'state' in data['vpn_ipsec_phase2_interface'] and data['vpn_ipsec_phase2_interface']['state']:
        state = data['vpn_ipsec_phase2_interface']['state']
    else:
        state = True
        fos._module.warn("state was not provided. Assuming 'present'.")

    vpn_ipsec_phase2_interface_data = data['vpn_ipsec_phase2_interface']
    vpn_ipsec_phase2_interface_data = flatten_multilists_attributes(vpn_ipsec_phase2_interface_data)
    filtered_data = underscore_to_hyphen(filter_vpn_ipsec_phase2_interface_data(vpn_ipsec_phase2_interface_data))

    if state == "present" or state == True:
        return fos.set('vpn.ipsec',
                       'phase2-interface',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('vpn.ipsec',
                          'phase2-interface',
                          mkey=filtered_data['name'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_vpn_ipsec(data, fos):

    if data['vpn_ipsec_phase2_interface']:
        resp = vpn_ipsec_phase2_interface(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('vpn_ipsec_phase2_interface'))

    return not is_successful_status(resp), \
        resp['status'] == "success" and \
        (resp['revision_changed'] if 'revision_changed' in resp else True), \
        resp


versioned_schema = {
    "type": "list",
    "children": {
        "protocol": {
            "type": "integer",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "add_route": {
            "type": "string",
            "options": [
                {
                    "value": "phase1",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
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
        "dst_name": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "keylifekbs": {
            "type": "integer",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "replay": {
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
        "keepalive": {
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
        "ipv4_df": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
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
        "auto_discovery_sender": {
            "type": "string",
            "options": [
                {
                    "value": "phase1",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
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
        "src_port": {
            "type": "integer",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "dst_subnet": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "dhgrp": {
            "multiple_values": True,
            "type": "list",
            "options": [
                {
                    "value": "1",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "2",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "5",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "14",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "15",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "16",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "17",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "18",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "19",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "20",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "21",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "27",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "28",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "29",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "30",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "31",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "32",
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
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "src_end_ip": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "keylifeseconds": {
            "type": "integer",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "single_source": {
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
        "auto_negotiate": {
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
        "l2tp": {
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
        "dst_name6": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "phase1name": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "proposal": {
            "multiple_values": True,
            "type": "list",
            "options": [
                {
                    "value": "null-md5",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "null-sha1",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "null-sha256",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "null-sha384",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "null-sha512",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "des-null",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "des-md5",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "des-sha1",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "des-sha256",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "des-sha384",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "des-sha512",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "3des-null",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "3des-md5",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "3des-sha1",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "3des-sha256",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "3des-sha384",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "3des-sha512",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aes128-null",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aes128-md5",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aes128-sha1",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aes128-sha256",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aes128-sha384",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aes128-sha512",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aes128gcm",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aes192-null",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aes192-md5",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aes192-sha1",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aes192-sha256",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aes192-sha384",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aes192-sha512",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aes256-null",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aes256-md5",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aes256-sha1",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aes256-sha256",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aes256-sha384",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aes256-sha512",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aes256gcm",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "chacha20poly1305",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aria128-null",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aria128-md5",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aria128-sha1",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aria128-sha256",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aria128-sha384",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aria128-sha512",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aria192-null",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aria192-md5",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aria192-sha1",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aria192-sha256",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aria192-sha384",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aria192-sha512",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aria256-null",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aria256-md5",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aria256-sha1",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aria256-sha256",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aria256-sha384",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "aria256-sha512",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "seed-null",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "seed-md5",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "seed-sha1",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "seed-sha256",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "seed-sha384",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "seed-sha512",
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
        "src_addr_type": {
            "type": "string",
            "options": [
                {
                    "value": "subnet",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "range",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "ip",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "name",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "subnet6",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "range6",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "ip6",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "name6",
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
        "dst_port": {
            "type": "integer",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "dhcp_ipsec": {
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
        "dst_subnet6": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "src_name6": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "src_name": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "src_end_ip6": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "pfs": {
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
        "dst_end_ip": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "src_start_ip6": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "encapsulation": {
            "type": "string",
            "options": [
                {
                    "value": "tunnel-mode",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "transport-mode",
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
        "src_subnet6": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "dst_start_ip": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
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
        "keylife_type": {
            "type": "string",
            "options": [
                {
                    "value": "seconds",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "kbs",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "both",
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
        "auto_discovery_forwarder": {
            "type": "string",
            "options": [
                {
                    "value": "phase1",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
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
        "src_start_ip": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "dst_addr_type": {
            "type": "string",
            "options": [
                {
                    "value": "subnet",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "range",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "ip",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "name",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "subnet6",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "range6",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "ip6",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "name6",
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
        "dst_end_ip6": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "src_subnet": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "route_overlap": {
            "type": "string",
            "options": [
                {
                    "value": "use-old",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "use-new",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "allow",
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
        "dst_start_ip6": {
            "type": "string",
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
        "vpn_ipsec_phase2_interface": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "state": {"required": False, "type": "str",
                          "choices": ["present", "absent"]}
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["vpn_ipsec_phase2_interface"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["vpn_ipsec_phase2_interface"]['options'][attribute_name]['required'] = True

    check_legacy_fortiosapi()
    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if 'access_token' in module.params:
            connection.set_option('access_token', module.params['access_token'])

        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(fos, versioned_schema, "vpn_ipsec_phase2_interface")

        is_error, has_changed, result = fortios_vpn_ipsec(module.params, fos)

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
