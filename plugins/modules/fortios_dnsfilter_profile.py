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
module: fortios_dnsfilter_profile
short_description: Configure DNS domain filter profiles in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify dnsfilter feature and profile category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.0
version_added: "2.10"
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

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - present
            - absent
    dnsfilter_profile:
        description:
            - Configure DNS domain filter profiles.
        default: null
        type: dict
        suboptions:
            block_action:
                description:
                    - Action to take for blocked domains.
                type: str
                choices:
                    - block
                    - redirect
            block_botnet:
                description:
                    - Enable/disable blocking botnet C&C DNS lookups.
                type: str
                choices:
                    - disable
                    - enable
            comment:
                description:
                    - Comment.
                type: str
            dns_translation:
                description:
                    - DNS translation settings.
                type: list
                suboptions:
                    addr_type:
                        description:
                            - DNS translation type (IPv4 or IPv6).
                        type: str
                        choices:
                            - ipv4
                            - ipv6
                    dst:
                        description:
                            - IPv4 address or subnet on the external network to substitute for the resolved address in DNS query replies. Can be single IP
                               address or subnet on the external network, but number of addresses must equal number of mapped IP addresses in src.
                        type: str
                    dst6:
                        description:
                            - IPv6 address or subnet on the external network to substitute for the resolved address in DNS query replies. Can be single IP
                               address or subnet on the external network, but number of addresses must equal number of mapped IP addresses in src6.
                        type: str
                    id:
                        description:
                            - ID.
                        required: true
                        type: int
                    netmask:
                        description:
                            - If src and dst are subnets rather than single IP addresses, enter the netmask for both src and dst.
                        type: str
                    prefix:
                        description:
                            - If src6 and dst6 are subnets rather than single IP addresses, enter the prefix for both src6 and dst6 (1 - 128).
                        type: int
                    src:
                        description:
                            - IPv4 address or subnet on the internal network to compare with the resolved address in DNS query replies. If the resolved
                               address matches, the resolved address is substituted with dst.
                        type: str
                    src6:
                        description:
                            - IPv6 address or subnet on the internal network to compare with the resolved address in DNS query replies. If the resolved
                               address matches, the resolved address is substituted with dst6.
                        type: str
                    status:
                        description:
                            - Enable/disable this DNS translation entry.
                        type: str
                        choices:
                            - enable
                            - disable
            domain_filter:
                description:
                    - Domain filter settings.
                type: dict
                suboptions:
                    domain_filter_table:
                        description:
                            - DNS domain filter table ID. Source dnsfilter.domain-filter.id.
                        type: int
            external_ip_blocklist:
                description:
                    - One or more external IP block lists.
                type: list
                suboptions:
                    name:
                        description:
                            - External domain block list name. Source system.external-resource.name.
                        required: true
                        type: str
            ftgd_dns:
                description:
                    - FortiGuard DNS Filter settings.
                type: dict
                suboptions:
                    filters:
                        description:
                            - FortiGuard DNS domain filters.
                        type: list
                        suboptions:
                            action:
                                description:
                                    - Action to take for DNS requests matching the category.
                                type: str
                                choices:
                                    - block
                                    - monitor
                            category:
                                description:
                                    - Category number.
                                type: int
                            id:
                                description:
                                    - ID number.
                                required: true
                                type: int
                            log:
                                description:
                                    - Enable/disable DNS filter logging for this DNS profile.
                                type: str
                                choices:
                                    - enable
                                    - disable
                    options:
                        description:
                            - FortiGuard DNS filter options.
                        type: str
                        choices:
                            - error-allow
                            - ftgd-disable
            log_all_domain:
                description:
                    - Enable/disable logging of all domains visited (detailed DNS logging).
                type: str
                choices:
                    - enable
                    - disable
            name:
                description:
                    - Profile name.
                required: true
                type: str
            redirect_portal:
                description:
                    - IP address of the SDNS redirect portal.
                type: str
            redirect_portal6:
                description:
                    - IPv6 address of the SDNS redirect portal.
                type: str
            safe_search:
                description:
                    - Enable/disable Google, Bing, and YouTube safe search.
                type: str
                choices:
                    - disable
                    - enable
            sdns_domain_log:
                description:
                    - Enable/disable domain filtering and botnet domain logging.
                type: str
                choices:
                    - enable
                    - disable
            sdns_ftgd_err_log:
                description:
                    - Enable/disable FortiGuard SDNS rating error logging.
                type: str
                choices:
                    - enable
                    - disable
            youtube_restrict:
                description:
                    - Set safe search for YouTube restriction level.
                type: str
                choices:
                    - strict
                    - moderate
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
  - name: Configure DNS domain filter profiles.
    fortios_dnsfilter_profile:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      dnsfilter_profile:
        block_action: "block"
        block_botnet: "disable"
        comment: "Comment."
        dns_translation:
         -
            addr_type: "ipv4"
            dst: "<your_own_value>"
            dst6: "<your_own_value>"
            id:  "10"
            netmask: "<your_own_value>"
            prefix: "12"
            src: "<your_own_value>"
            src6: "<your_own_value>"
            status: "enable"
        domain_filter:
            domain_filter_table: "17 (source dnsfilter.domain-filter.id)"
        external_ip_blocklist:
         -
            name: "default_name_19 (source system.external-resource.name)"
        ftgd_dns:
            filters:
             -
                action: "block"
                category: "23"
                id:  "24"
                log: "enable"
            options: "error-allow"
        log_all_domain: "enable"
        name: "default_name_28"
        redirect_portal: "<your_own_value>"
        redirect_portal6: "<your_own_value>"
        safe_search: "disable"
        sdns_domain_log: "enable"
        sdns_ftgd_err_log: "enable"
        youtube_restrict: "strict"

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
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import is_same_comparison
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import serialize


def filter_dnsfilter_profile_data(json):
    option_list = ['block_action', 'block_botnet', 'comment',
                   'dns_translation', 'domain_filter', 'external_ip_blocklist',
                   'ftgd_dns', 'log_all_domain', 'name',
                   'redirect_portal', 'redirect_portal6', 'safe_search',
                   'sdns_domain_log', 'sdns_ftgd_err_log', 'youtube_restrict']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def flatten_single_path(data, path, index):
    if not data or index == len(path) or path[index] not in data or not data[path[index]]:
        return

    if index == len(path) - 1:
        data[path[index]] = ' '.join(str(elem) for elem in data[path[index]])
    elif isinstance(data[path[index]], list):
        for value in data[path[index]]:
            flatten_single_path(value, path, index + 1)
    else:
        flatten_single_path(data[path[index]], path, index + 1)


def flatten_multilists_attributes(data):
    multilist_attrs = [[u'ftgd_dns', u'options']]

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
            new_data[k.replace('_', '-')] = underscore_to_hyphen(v)
        data = new_data

    return data


def dnsfilter_profile(data, fos, check_mode=False):

    vdom = data['vdom']

    state = data['state']

    dnsfilter_profile_data = data['dnsfilter_profile']
    dnsfilter_profile_data = flatten_multilists_attributes(dnsfilter_profile_data)
    filtered_data = underscore_to_hyphen(filter_dnsfilter_profile_data(dnsfilter_profile_data))

    # check_mode starts from here
    if check_mode:
        mkey = fos.get_mkey('system', 'interface', filtered_data, vdom=vdom)
        current_data = fos.get('system', 'interface', vdom=vdom, mkey=mkey)
        is_existed = current_data and current_data.get('http_status') == 200 \
            and isinstance(current_data.get('results'), list) \
            and len(current_data['results']) > 0

        # 2. if it exists and the state is 'present' then compare current settings with desired
        if state == 'present' or state is True:
            if mkey is None:
                return False, True, filtered_data

            # if mkey exists then compare each other
            # record exits and they're matched or not
            if is_existed:
                is_same = is_same_comparison(
                    serialize(current_data['results'][0]), serialize(filtered_data))
                return False, not is_same, filtered_data

            # record does not exist
            return False, True, filtered_data

        if state == 'absent':
            if mkey is None:
                return False, False, filtered_data

            if is_existed:
                return False, True, filtered_data
            return False, False, filtered_data

        return True, False, {'reason: ': 'Must provide state parameter'}

    if state == "present" or state is True:
        return fos.set('dnsfilter',
                       'profile',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('dnsfilter',
                          'profile',
                          mkey=filtered_data['name'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_dnsfilter(data, fos, check_mode):

    if data['dnsfilter_profile']:
        resp = dnsfilter_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('dnsfilter_profile'))
    if check_mode:
        return resp
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
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "external_ip_blocklist": {
            "type": "list",
            "children": {
                "name": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                }
            },
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "domain_filter": {
            "type": "dict",
            "children": {
                "domain_filter_table": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                }
            },
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "name": {
            "type": "string",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "youtube_restrict": {
            "type": "string",
            "options": [
                {
                    "value": "strict",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "moderate",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                }
            ],
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "log_all_domain": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                }
            ],
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "safe_search": {
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                }
            ],
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "redirect_portal6": {
            "type": "string",
            "revisions": {
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True
            }
        },
        "block_botnet": {
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                }
            ],
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "sdns_ftgd_err_log": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                }
            ],
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "block_action": {
            "type": "string",
            "options": [
                {
                    "value": "block",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "redirect",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                }
            ],
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "redirect_portal": {
            "type": "string",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "ftgd_dns": {
            "type": "dict",
            "children": {
                "options": {
                    "multiple_values": True,
                    "type": "list",
                    "options": [
                        {
                            "value": "error-allow",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "ftgd-disable",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "filters": {
                    "type": "list",
                    "children": {
                        "category": {
                            "type": "integer",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        "action": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "block",
                                    "revisions": {
                                        "v6.0.0": True,
                                        "v7.0.0": True,
                                        "v6.0.5": True,
                                        "v6.4.4": True,
                                        "v6.4.0": True,
                                        "v6.4.1": True,
                                        "v6.2.0": True,
                                        "v6.2.3": True,
                                        "v6.2.5": True,
                                        "v6.2.7": True,
                                        "v6.0.11": True
                                    }
                                },
                                {
                                    "value": "monitor",
                                    "revisions": {
                                        "v6.0.0": True,
                                        "v7.0.0": True,
                                        "v6.0.5": True,
                                        "v6.4.4": True,
                                        "v6.4.0": True,
                                        "v6.4.1": True,
                                        "v6.2.0": True,
                                        "v6.2.3": True,
                                        "v6.2.5": True,
                                        "v6.2.7": True,
                                        "v6.0.11": True
                                    }
                                }
                            ],
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        "id": {
                            "type": "integer",
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        "log": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v6.0.0": True,
                                        "v7.0.0": True,
                                        "v6.0.5": True,
                                        "v6.4.4": True,
                                        "v6.4.0": True,
                                        "v6.4.1": True,
                                        "v6.2.0": True,
                                        "v6.2.3": True,
                                        "v6.2.5": True,
                                        "v6.2.7": True,
                                        "v6.0.11": True
                                    }
                                },
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v6.0.0": True,
                                        "v7.0.0": True,
                                        "v6.0.5": True,
                                        "v6.4.4": True,
                                        "v6.4.0": True,
                                        "v6.4.1": True,
                                        "v6.2.0": True,
                                        "v6.2.3": True,
                                        "v6.2.5": True,
                                        "v6.2.7": True,
                                        "v6.0.11": True
                                    }
                                }
                            ],
                            "revisions": {
                                "v6.0.0": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        }
                    },
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                }
            },
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "dns_translation": {
            "type": "list",
            "children": {
                "status": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "src": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "dst6": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "dst": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "prefix": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "id": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "netmask": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "src6": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "addr_type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "ipv4",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "ipv6",
                            "revisions": {
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                }
            },
            "revisions": {
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True
            }
        },
        "sdns_domain_log": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                }
            ],
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        }
    },
    "revisions": {
        "v6.0.0": True,
        "v7.0.0": True,
        "v6.0.5": True,
        "v6.4.4": True,
        "v6.4.0": True,
        "v6.4.1": True,
        "v6.2.0": True,
        "v6.2.3": True,
        "v6.2.5": True,
        "v6.2.7": True,
        "v6.0.11": True
    }
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = 'name'
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "enable_log": {"required": False, "type": bool},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "state": {"required": True, "type": "str",
                  "choices": ["present", "absent"]},
        "dnsfilter_profile": {
            "required": False, "type": "dict", "default": None,
            "options": {
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["dnsfilter_profile"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["dnsfilter_profile"]['options'][attribute_name]['required'] = True

    check_legacy_fortiosapi()
    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=True)

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if 'access_token' in module.params:
            connection.set_option('access_token', module.params['access_token'])

        if 'enable_log' in module.params:
            connection.set_option('enable_log', module.params['enable_log'])
        else:
            connection.set_option('enable_log', False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(fos, versioned_schema, "dnsfilter_profile")

        is_error, has_changed, result = fortios_dnsfilter(module.params, fos, module.check_mode)

    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result['matched'] is False:
        module.warn("Ansible has detected version mismatch between FortOS system and your playbook, see more details by specifying option -vvv")

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
