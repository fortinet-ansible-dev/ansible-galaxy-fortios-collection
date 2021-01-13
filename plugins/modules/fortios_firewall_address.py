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
module: fortios_firewall_address
short_description: Configure IPv4 addresses in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and address category.
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
    firewall_address:
        description:
            - Configure IPv4 addresses.
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
            allow_routing:
                description:
                    - Enable/disable use of this address in the static route configuration.
                type: str
                choices:
                    - enable
                    - disable
            associated_interface:
                description:
                    - Network interface associated with address. Source system.interface.name system.zone.name.
                type: str
            cache_ttl:
                description:
                    - Defines the minimal TTL of individual IP addresses in FQDN cache measured in seconds.
                type: int
            clearpass_spt:
                description:
                    - SPT (System Posture Token) value.
                type: str
                choices:
                    - unknown
                    - healthy
                    - quarantine
                    - checkup
                    - transient
                    - infected
            color:
                description:
                    - Color of icon on the GUI.
                type: int
            comment:
                description:
                    - Comment.
                type: str
            country:
                description:
                    - IP addresses associated to a specific country.
                type: str
            end_ip:
                description:
                    - Final IP address (inclusive) in the range for the address.
                type: str
            end_mac:
                description:
                    - Last MAC address in the range.
                type: str
            epg_name:
                description:
                    - Endpoint group name.
                type: str
            filter:
                description:
                    - Match criteria filter.
                type: str
            fqdn:
                description:
                    - Fully Qualified Domain Name address.
                type: str
            fsso_group:
                description:
                    - FSSO group(s).
                type: list
                suboptions:
                    name:
                        description:
                            - FSSO group name. Source user.adgrp.name.
                        required: true
                        type: str
            interface:
                description:
                    - Name of interface whose IP address is to be used. Source system.interface.name.
                type: str
            list:
                description:
                    - IP address list.
                type: list
                suboptions:
                    ip:
                        description:
                            - IP.
                        required: true
                        type: str
                    net_id:
                        description:
                            - Network ID.
                        type: str
                    obj_id:
                        description:
                            - Object ID.
                        type: str
            name:
                description:
                    - Address name.
                required: true
                type: str
            obj_id:
                description:
                    - Object ID for NSX.
                type: int
            organization:
                description:
                    - 'Organization domain name (Syntax: organization/domain).'
                type: str
            policy_group:
                description:
                    - Policy group name.
                type: str
            sdn:
                description:
                    - SDN. Source system.sdn-connector.name.
                type: str
                choices:
                    - aci
                    - aws
                    - azure
                    - nsx
                    - nuage
            sdn_addr_type:
                description:
                    - Type of addresses to collect.
                type: str
                choices:
                    - private
                    - public
                    - all
            sdn_tag:
                description:
                    - SDN Tag.
                type: str
            start_ip:
                description:
                    - First IP address (inclusive) in the range for the address.
                type: str
            start_mac:
                description:
                    - First MAC address in the range.
                type: str
            sub_type:
                description:
                    - Sub-type of address.
                type: str
                choices:
                    - sdn
                    - clearpass_spt
                    - fsso
                    - ems_tag
            subnet:
                description:
                    - IP address and subnet mask of address.
                type: str
            subnet_name:
                description:
                    - Subnet name.
                type: str
            tagging:
                description:
                    - Config object tagging.
                type: list
                suboptions:
                    category:
                        description:
                            - Tag category. Source system.object-tagging.category.
                        type: str
                    name:
                        description:
                            - Tagging entry name.
                        required: true
                        type: str
                    tags:
                        description:
                            - Tags.
                        type: list
                        suboptions:
                            name:
                                description:
                                    - Tag name. Source system.object-tagging.tags.name.
                                required: true
                                type: str
            tenant:
                description:
                    - Tenant.
                type: str
            type:
                description:
                    - Type of address.
                type: str
                choices:
                    - ipmask
                    - iprange
                    - fqdn
                    - geography
                    - wildcard
                    - wildcard_fqdn
                    - dynamic
                    - interface_subnet
                    - mac
            uuid:
                description:
                    - Universally Unique Identifier (UUID; automatically assigned but can be manually reset).
                type: str
            visibility:
                description:
                    - Enable/disable address visibility in the GUI.
                type: str
                choices:
                    - enable
                    - disable
            wildcard:
                description:
                    - IP address and wildcard netmask.
                type: str
            wildcard_fqdn:
                description:
                    - Fully Qualified Domain Name with wildcard characters.
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
  - name: Configure IPv4 addresses.
    fortios_firewall_address:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_address:
        allow_routing: "enable"
        associated_interface: "<your_own_value> (source system.interface.name system.zone.name)"
        cache_ttl: "5"
        clearpass_spt: "unknown"
        color: "7"
        comment: "Comment."
        country: "<your_own_value>"
        end_ip: "<your_own_value>"
        end_mac: "<your_own_value>"
        epg_name: "<your_own_value>"
        filter: "<your_own_value>"
        fqdn: "<your_own_value>"
        fsso_group:
         -
            name: "default_name_16 (source user.adgrp.name)"
        interface: "<your_own_value> (source system.interface.name)"
        list:
         -
            ip: "<your_own_value>"
            net_id: "<your_own_value>"
            obj_id: "<your_own_value>"
        name: "default_name_22"
        obj_id: "23"
        organization: "<your_own_value>"
        policy_group: "<your_own_value>"
        sdn: "aci"
        sdn_addr_type: "private"
        sdn_tag: "<your_own_value>"
        start_ip: "<your_own_value>"
        start_mac: "<your_own_value>"
        sub_type: "sdn"
        subnet: "<your_own_value>"
        subnet_name: "<your_own_value>"
        tagging:
         -
            category: "<your_own_value> (source system.object-tagging.category)"
            name: "default_name_36"
            tags:
             -
                name: "default_name_38 (source system.object-tagging.tags.name)"
        tenant: "<your_own_value>"
        type: "ipmask"
        uuid: "<your_own_value>"
        visibility: "enable"
        wildcard: "<your_own_value>"
        wildcard_fqdn: "<your_own_value>"

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


def filter_firewall_address_data(json):
    option_list = ['allow_routing', 'associated_interface', 'cache_ttl',
                   'clearpass_spt', 'color', 'comment',
                   'country', 'end_ip', 'end_mac',
                   'epg_name', 'filter', 'fqdn',
                   'fsso_group', 'interface', 'list',
                   'name', 'obj_id', 'organization',
                   'policy_group', 'sdn', 'sdn_addr_type',
                   'sdn_tag', 'start_ip', 'start_mac',
                   'sub_type', 'subnet', 'subnet_name',
                   'tagging', 'tenant', 'type',
                   'uuid', 'visibility', 'wildcard',
                   'wildcard_fqdn']
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


def firewall_address(data, fos):
    vdom = data['vdom']

    if 'state' in data and data['state']:
        state = data['state']
    elif 'state' in data['firewall_address'] and data['firewall_address']['state']:
        state = data['firewall_address']['state']
    else:
        state = True
        fos._module.warn("state was not provided. Assuming 'present'.")

    firewall_address_data = data['firewall_address']
    filtered_data = underscore_to_hyphen(filter_firewall_address_data(firewall_address_data))

    if state == "present" or state == True:
        return fos.set('firewall',
                       'address',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('firewall',
                          'address',
                          mkey=filtered_data['name'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_firewall(data, fos):

    if data['firewall_address']:
        resp = firewall_address(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('firewall_address'))

    return not is_successful_status(resp), \
        resp['status'] == "success" and \
        (resp['revision_changed'] if 'revision_changed' in resp else True), \
        resp


versioned_schema = {
    "type": "list",
    "children": {
        "comment": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "allow_routing": {
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
        "color": {
            "type": "integer",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "list": {
            "type": "list",
            "children": {
                "ip": {
                    "type": "string",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "net_id": {
                    "type": "string",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.4.0": False,
                        "v6.4.1": False
                    }
                },
                "obj_id": {
                    "type": "string",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.4.0": False,
                        "v6.4.1": False
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
        "sdn_tag": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "fqdn": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "interface": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "sdn": {
            "type": "string",
            "options": [
                {
                    "value": "aci",
                    "revisions": {
                        "v6.0.0": True
                    }
                },
                {
                    "value": "aws",
                    "revisions": {
                        "v6.0.0": True
                    }
                },
                {
                    "value": "azure",
                    "revisions": {
                        "v6.0.0": True
                    }
                },
                {
                    "value": "nsx",
                    "revisions": {
                        "v6.0.0": True
                    }
                },
                {
                    "value": "nuage",
                    "revisions": {
                        "v6.0.0": True
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
        "epg_name": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "subnet": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "sdn_addr_type": {
            "type": "string",
            "options": [
                {
                    "value": "private",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "public",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "all",
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
        "policy_group": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "end_ip": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "subnet_name": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "tenant": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "clearpass_spt": {
            "type": "string",
            "options": [
                {
                    "value": "unknown",
                    "revisions": {
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "healthy",
                    "revisions": {
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "quarantine",
                    "revisions": {
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "checkup",
                    "revisions": {
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "transient",
                    "revisions": {
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "infected",
                    "revisions": {
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "type": {
            "type": "string",
            "options": [
                {
                    "value": "ipmask",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "iprange",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "fqdn",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "geography",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "wildcard",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "wildcard-fqdn",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": False,
                        "v6.4.0": False,
                        "v6.4.1": False
                    }
                },
                {
                    "value": "dynamic",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "interface-subnet",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "mac",
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
        "associated_interface": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "start_mac": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "visibility": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.2.0": True,
                        "v6.0.0": True,
                        "v6.2.3": True
                    }
                }
            ],
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": False,
                "v6.4.1": False
            }
        },
        "organization": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "start_ip": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "cache_ttl": {
            "type": "integer",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "sub_type": {
            "type": "string",
            "options": [
                {
                    "value": "sdn",
                    "revisions": {
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "clearpass-spt",
                    "revisions": {
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "fsso",
                    "revisions": {
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "ems-tag",
                    "revisions": {
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "tagging": {
            "type": "list",
            "children": {
                "category": {
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
                "tags": {
                    "type": "list",
                    "children": {
                        "name": {
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
            },
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "uuid": {
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
        "obj_id": {
            "type": "integer",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "country": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "end_mac": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "wildcard_fqdn": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "filter": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "wildcard": {
            "type": "string",
            "revisions": {
                "v6.2.0": True,
                "v6.0.0": True,
                "v6.2.3": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "fsso_group": {
            "type": "list",
            "children": {
                "name": {
                    "type": "string",
                    "revisions": {
                        "v6.2.3": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            },
            "revisions": {
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
        "firewall_address": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "state": {"required": False, "type": "str",
                          "choices": ["present", "absent"]}
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["firewall_address"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_address"]['options'][attribute_name]['required'] = True

    check_legacy_fortiosapi()
    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if 'access_token' in module.params:
            connection.set_option('access_token', module.params['access_token'])

        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(fos, versioned_schema, "firewall_address")

        is_error, has_changed, result = fortios_firewall(module.params, fos)

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
