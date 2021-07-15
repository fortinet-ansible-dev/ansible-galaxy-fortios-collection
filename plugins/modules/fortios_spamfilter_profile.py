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
module: fortios_spamfilter_profile
short_description: Configure AntiSpam profiles in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify spamfilter feature and profile category.
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
    spamfilter_profile:
        description:
            - Configure AntiSpam profiles.
        default: null
        type: dict
        suboptions:
            comment:
                description:
                    - Comment.
                type: str
            external:
                description:
                    - Enable/disable external Email inspection.
                type: str
                choices:
                    - enable
                    - disable
            flow_based:
                description:
                    - Enable/disable flow-based spam filtering.
                type: str
                choices:
                    - enable
                    - disable
            gmail:
                description:
                    - Gmail.
                type: dict
                suboptions:
                    log:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - enable
                            - disable
            imap:
                description:
                    - IMAP.
                type: dict
                suboptions:
                    action:
                        description:
                            - Action for spam email.
                        type: str
                        choices:
                            - pass
                            - tag
                    log:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - enable
                            - disable
                    tag_msg:
                        description:
                            - Subject text or header added to spam email.
                        type: str
                    tag_type:
                        description:
                            - Tag subject or header for spam email.
                        type: list
                        choices:
                            - subject
                            - header
                            - spaminfo
            mapi:
                description:
                    - MAPI.
                type: dict
                suboptions:
                    action:
                        description:
                            - Action for spam email.
                        type: str
                        choices:
                            - pass
                            - discard
                    log:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - enable
                            - disable
            msn_hotmail:
                description:
                    - MSN Hotmail.
                type: dict
                suboptions:
                    log:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - enable
                            - disable
            name:
                description:
                    - Profile name.
                required: true
                type: str
            options:
                description:
                    - Options.
                type: list
                choices:
                    - bannedword
                    - spambwl
                    - spamfsip
                    - spamfssubmit
                    - spamfschksum
                    - spamfsurl
                    - spamhelodns
                    - spamraddrdns
                    - spamrbl
                    - spamhdrcheck
                    - spamfsphish
            pop3:
                description:
                    - POP3.
                type: dict
                suboptions:
                    action:
                        description:
                            - Action for spam email.
                        type: str
                        choices:
                            - pass
                            - tag
                    log:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - enable
                            - disable
                    tag_msg:
                        description:
                            - Subject text or header added to spam email.
                        type: str
                    tag_type:
                        description:
                            - Tag subject or header for spam email.
                        type: list
                        choices:
                            - subject
                            - header
                            - spaminfo
            replacemsg_group:
                description:
                    - Replacement message group. Source system.replacemsg-group.name.
                type: str
            smtp:
                description:
                    - SMTP.
                type: dict
                suboptions:
                    action:
                        description:
                            - Action for spam email.
                        type: str
                        choices:
                            - pass
                            - tag
                            - discard
                    hdrip:
                        description:
                            - Enable/disable SMTP email header IP checks for spamfsip, spamrbl and spambwl filters.
                        type: str
                        choices:
                            - disable
                            - enable
                    local_override:
                        description:
                            - Enable/disable local filter to override SMTP remote check result.
                        type: str
                        choices:
                            - disable
                            - enable
                    log:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - enable
                            - disable
                    tag_msg:
                        description:
                            - Subject text or header added to spam email.
                        type: str
                    tag_type:
                        description:
                            - Tag subject or header for spam email.
                        type: list
                        choices:
                            - subject
                            - header
                            - spaminfo
            spam_bwl_table:
                description:
                    - Anti-spam black/white list table ID. Source spamfilter.bwl.id.
                type: int
            spam_bword_table:
                description:
                    - Anti-spam banned word table ID. Source spamfilter.bword.id.
                type: int
            spam_bword_threshold:
                description:
                    - Spam banned word threshold.
                type: int
            spam_filtering:
                description:
                    - Enable/disable spam filtering.
                type: str
                choices:
                    - enable
                    - disable
            spam_iptrust_table:
                description:
                    - Anti-spam IP trust table ID. Source spamfilter.iptrust.id.
                type: int
            spam_log:
                description:
                    - Enable/disable spam logging for email filtering.
                type: str
                choices:
                    - disable
                    - enable
            spam_log_fortiguard_response:
                description:
                    - Enable/disable logging FortiGuard spam response.
                type: str
                choices:
                    - disable
                    - enable
            spam_mheader_table:
                description:
                    - Anti-spam MIME header table ID. Source spamfilter.mheader.id.
                type: int
            spam_rbl_table:
                description:
                    - Anti-spam DNSBL table ID. Source spamfilter.dnsbl.id.
                type: int
            yahoo_mail:
                description:
                    - Yahoo! Mail.
                type: dict
                suboptions:
                    log:
                        description:
                            - Enable/disable logging.
                        type: str
                        choices:
                            - enable
                            - disable
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
  - name: Configure AntiSpam profiles.
    fortios_spamfilter_profile:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      spamfilter_profile:
        comment: "Comment."
        external: "enable"
        flow_based: "enable"
        gmail:
            log: "enable"
        imap:
            action: "pass"
            log: "enable"
            tag_msg: "<your_own_value>"
            tag_type: "subject"
        mapi:
            action: "pass"
            log: "enable"
        msn_hotmail:
            log: "enable"
        name: "default_name_18"
        options: "bannedword"
        pop3:
            action: "pass"
            log: "enable"
            tag_msg: "<your_own_value>"
            tag_type: "subject"
        replacemsg_group: "<your_own_value> (source system.replacemsg-group.name)"
        smtp:
            action: "pass"
            hdrip: "disable"
            local_override: "disable"
            log: "enable"
            tag_msg: "<your_own_value>"
            tag_type: "subject"
        spam_bwl_table: "33 (source spamfilter.bwl.id)"
        spam_bword_table: "34 (source spamfilter.bword.id)"
        spam_bword_threshold: "35"
        spam_filtering: "enable"
        spam_iptrust_table: "37 (source spamfilter.iptrust.id)"
        spam_log: "disable"
        spam_log_fortiguard_response: "disable"
        spam_mheader_table: "40 (source spamfilter.mheader.id)"
        spam_rbl_table: "41 (source spamfilter.dnsbl.id)"
        yahoo_mail:
            log: "enable"

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


def filter_spamfilter_profile_data(json):
    option_list = ['comment', 'external', 'flow_based',
                   'gmail', 'imap', 'mapi',
                   'msn_hotmail', 'name', 'options',
                   'pop3', 'replacemsg_group', 'smtp',
                   'spam_bwl_table', 'spam_bword_table', 'spam_bword_threshold',
                   'spam_filtering', 'spam_iptrust_table', 'spam_log',
                   'spam_log_fortiguard_response', 'spam_mheader_table', 'spam_rbl_table',
                   'yahoo_mail']
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
    multilist_attrs = [[u'options'], [u'imap', u'tag_type'], [u'pop3', u'tag_type'], [u'smtp', u'tag_type']]

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


def spamfilter_profile(data, fos, check_mode=False):

    vdom = data['vdom']

    state = data['state']

    spamfilter_profile_data = data['spamfilter_profile']
    spamfilter_profile_data = flatten_multilists_attributes(spamfilter_profile_data)
    filtered_data = underscore_to_hyphen(filter_spamfilter_profile_data(spamfilter_profile_data))

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
        return fos.set('spamfilter',
                       'profile',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('spamfilter',
                          'profile',
                          mkey=filtered_data['name'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_spamfilter(data, fos, check_mode):

    if data['spamfilter_profile']:
        resp = spamfilter_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('spamfilter_profile'))
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
                "v6.0.11": True,
                "v6.0.0": True,
                "v6.0.5": True
            }
        },
        "spam_bword_threshold": {
            "type": "integer",
            "revisions": {
                "v6.0.11": True,
                "v6.0.0": True,
                "v6.0.5": True
            }
        },
        "spam_iptrust_table": {
            "type": "integer",
            "revisions": {
                "v6.0.11": True,
                "v6.0.0": True,
                "v6.0.5": True
            }
        },
        "spam_log_fortiguard_response": {
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                }
            ],
            "revisions": {
                "v6.0.11": True,
                "v6.0.0": True,
                "v6.0.5": True
            }
        },
        "smtp": {
            "type": "dict",
            "children": {
                "local_override": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                },
                "hdrip": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                },
                "log": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                },
                "action": {
                    "type": "string",
                    "options": [
                        {
                            "value": "pass",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "tag",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "discard",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                },
                "tag_msg": {
                    "type": "string",
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                },
                "tag_type": {
                    "type": "list",
                    "options": [
                        {
                            "value": "subject",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "header",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "spaminfo",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                }
            },
            "revisions": {
                "v6.0.11": True,
                "v6.0.0": True,
                "v6.0.5": True
            }
        },
        "replacemsg_group": {
            "type": "string",
            "revisions": {
                "v6.0.11": True,
                "v6.0.0": True,
                "v6.0.5": True
            }
        },
        "gmail": {
            "type": "dict",
            "children": {
                "log": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                }
            },
            "revisions": {
                "v6.0.11": True,
                "v6.0.0": True,
                "v6.0.5": True
            }
        },
        "spam_mheader_table": {
            "type": "integer",
            "revisions": {
                "v6.0.11": True,
                "v6.0.0": True,
                "v6.0.5": True
            }
        },
        "spam_rbl_table": {
            "type": "integer",
            "revisions": {
                "v6.0.11": True,
                "v6.0.0": True,
                "v6.0.5": True
            }
        },
        "mapi": {
            "type": "dict",
            "children": {
                "action": {
                    "type": "string",
                    "options": [
                        {
                            "value": "pass",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "discard",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                },
                "log": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                }
            },
            "revisions": {
                "v6.0.11": True,
                "v6.0.0": True,
                "v6.0.5": True
            }
        },
        "spam_bword_table": {
            "type": "integer",
            "revisions": {
                "v6.0.11": True,
                "v6.0.0": True,
                "v6.0.5": True
            }
        },
        "yahoo_mail": {
            "type": "dict",
            "children": {
                "log": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                }
            },
            "revisions": {
                "v6.0.11": True,
                "v6.0.0": True,
                "v6.0.5": True
            }
        },
        "msn_hotmail": {
            "type": "dict",
            "children": {
                "log": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                }
            },
            "revisions": {
                "v6.0.11": True,
                "v6.0.0": True,
                "v6.0.5": True
            }
        },
        "flow_based": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                }
            ],
            "revisions": {
                "v6.0.11": True,
                "v6.0.0": True,
                "v6.0.5": True
            }
        },
        "pop3": {
            "type": "dict",
            "children": {
                "action": {
                    "type": "string",
                    "options": [
                        {
                            "value": "pass",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "tag",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                },
                "tag_msg": {
                    "type": "string",
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                },
                "log": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                },
                "tag_type": {
                    "type": "list",
                    "options": [
                        {
                            "value": "subject",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "header",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "spaminfo",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                }
            },
            "revisions": {
                "v6.0.11": True,
                "v6.0.0": True,
                "v6.0.5": True
            }
        },
        "external": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                }
            ],
            "revisions": {
                "v6.0.11": True,
                "v6.0.0": True,
                "v6.0.5": True
            }
        },
        "imap": {
            "type": "dict",
            "children": {
                "action": {
                    "type": "string",
                    "options": [
                        {
                            "value": "pass",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "tag",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                },
                "tag_msg": {
                    "type": "string",
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                },
                "log": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                },
                "tag_type": {
                    "type": "list",
                    "options": [
                        {
                            "value": "subject",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "header",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "spaminfo",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                }
            },
            "revisions": {
                "v6.0.11": True,
                "v6.0.0": True,
                "v6.0.5": True
            }
        },
        "spam_log": {
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                }
            ],
            "revisions": {
                "v6.0.11": True,
                "v6.0.0": True,
                "v6.0.5": True
            }
        },
        "name": {
            "type": "string",
            "revisions": {
                "v6.0.11": True,
                "v6.0.0": True,
                "v6.0.5": True
            }
        },
        "spam_filtering": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                }
            ],
            "revisions": {
                "v6.0.11": True,
                "v6.0.0": True,
                "v6.0.5": True
            }
        },
        "options": {
            "type": "list",
            "options": [
                {
                    "value": "bannedword",
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                },
                {
                    "value": "spambwl",
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                },
                {
                    "value": "spamfsip",
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                },
                {
                    "value": "spamfssubmit",
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                },
                {
                    "value": "spamfschksum",
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                },
                {
                    "value": "spamfsurl",
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                },
                {
                    "value": "spamhelodns",
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                },
                {
                    "value": "spamraddrdns",
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                },
                {
                    "value": "spamrbl",
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                },
                {
                    "value": "spamhdrcheck",
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                },
                {
                    "value": "spamfsphish",
                    "revisions": {
                        "v6.0.11": True,
                        "v6.0.0": True,
                        "v6.0.5": True
                    }
                }
            ],
            "revisions": {
                "v6.0.11": True,
                "v6.0.0": True,
                "v6.0.5": True
            }
        },
        "spam_bwl_table": {
            "type": "integer",
            "revisions": {
                "v6.0.11": True,
                "v6.0.0": True,
                "v6.0.5": True
            }
        }
    },
    "revisions": {
        "v6.0.11": True,
        "v6.0.0": True,
        "v6.0.5": True
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
        "spamfilter_profile": {
            "required": False, "type": "dict", "default": None,
            "options": {
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["spamfilter_profile"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["spamfilter_profile"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "spamfilter_profile")

        is_error, has_changed, result = fortios_spamfilter(module.params, fos, module.check_mode)

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
