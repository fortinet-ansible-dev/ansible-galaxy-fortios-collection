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
module: fortios_emailfilter_profile
short_description: Configure AntiSpam profiles in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify emailfilter feature and profile category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.2.0
version_added: "2.9"
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
        type: str
        required: true
        choices:
            - present
            - absent
    emailfilter_profile:
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
            file_filter:
                description:
                    - File filter.
                type: dict
                suboptions:
                    entries:
                        description:
                            - File filter entries.
                        type: list
                        suboptions:
                            action:
                                description:
                                    - Action taken for matched file.
                                type: str
                                choices:
                                    - log
                                    - block
                            comment:
                                description:
                                    - Comment.
                                type: str
                            encryption:
                                description:
                                    - Match encrypted files or not.
                                type: str
                                choices:
                                    - yes
                                    - any
                            file_type:
                                description:
                                    - Select file type.
                                type: list
                                suboptions:
                                    name:
                                        description:
                                            - File type name. Source antivirus.filetype.name.
                                        required: true
                                        type: str
                            filter:
                                description:
                                    - Add a file filter.
                                required: true
                                type: str
                            protocol:
                                description:
                                    - Protocols to apply with.
                                type: str
                                choices:
                                    - smtp
                                    - imap
                                    - pop3
                    log:
                        description:
                            - Enable/disable file filter logging.
                        type: str
                        choices:
                            - enable
                            - disable
                    scan_archive_contents:
                        description:
                            - Enable/disable file filter archive contents scan.
                        type: str
                        choices:
                            - enable
                            - disable
                    status:
                        description:
                            - Enable/disable file filter.
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
                        type: str
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
                type: str
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
                        type: str
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
                        type: str
                        choices:
                            - subject
                            - header
                            - spaminfo
            spam_bwl_table:
                description:
                    - Anti-spam black/white list table ID. Source emailfilter.bwl.id.
                type: int
            spam_bword_table:
                description:
                    - Anti-spam banned word table ID. Source emailfilter.bword.id.
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
                    - Anti-spam IP trust table ID. Source emailfilter.iptrust.id.
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
                    - Anti-spam MIME header table ID. Source emailfilter.mheader.id.
                type: int
            spam_rbl_table:
                description:
                    - Anti-spam DNSBL table ID. Source emailfilter.dnsbl.id.
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
    fortios_emailfilter_profile:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      emailfilter_profile:
        comment: "Comment."
        external: "enable"
        file_filter:
            entries:
             -
                action: "log"
                comment: "Comment."
                encryption: "yes"
                file_type:
                 -
                    name: "default_name_11 (source antivirus.filetype.name)"
                filter: "<your_own_value>"
                protocol: "smtp"
            log: "enable"
            scan_archive_contents: "enable"
            status: "enable"
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
        name: "default_name_29"
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
        spam_bwl_table: "44 (source emailfilter.bwl.id)"
        spam_bword_table: "45 (source emailfilter.bword.id)"
        spam_bword_threshold: "46"
        spam_filtering: "enable"
        spam_iptrust_table: "48 (source emailfilter.iptrust.id)"
        spam_log: "disable"
        spam_log_fortiguard_response: "disable"
        spam_mheader_table: "51 (source emailfilter.mheader.id)"
        spam_rbl_table: "52 (source emailfilter.dnsbl.id)"
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
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import FAIL_SOCKET_MSG


def filter_emailfilter_profile_data(json):
    option_list = ['comment', 'external', 'file_filter',
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


def emailfilter_profile(data, fos):
    vdom = data['vdom']
    state = data['state']
    emailfilter_profile_data = data['emailfilter_profile']
    filtered_data = underscore_to_hyphen(filter_emailfilter_profile_data(emailfilter_profile_data))

    if state == "present":
        return fos.set('emailfilter',
                       'profile',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('emailfilter',
                          'profile',
                          mkey=filtered_data['name'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_emailfilter(data, fos):

    if data['emailfilter_profile']:
        resp = emailfilter_profile(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('emailfilter_profile'))

    return not is_successful_status(resp), \
        resp['status'] == "success" and \
        (resp['revision_changed'] if 'revision_changed' in resp else True), \
        resp


def main():
    mkeyname = 'name'
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "state": {"required": True, "type": "str",
                  "choices": ["present", "absent"]},
        "emailfilter_profile": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "comment": {"required": False, "type": "str"},
                "external": {"required": False, "type": "str",
                             "choices": ["enable",
                                         "disable"]},
                "file_filter": {"required": False, "type": "dict",
                                "options": {
                                    "entries": {"required": False, "type": "list",
                                                "options": {
                                                    "action": {"required": False, "type": "str",
                                                               "choices": ["log",
                                                                           "block"]},
                                                    "comment": {"required": False, "type": "str"},
                                                    "encryption": {"required": False, "type": "str",
                                                                   "choices": ["yes",
                                                                               "any"]},
                                                    "file_type": {"required": False, "type": "list",
                                                                  "options": {
                                                                      "name": {"required": True, "type": "str"}
                                                                  }},
                                                    "filter": {"required": True, "type": "str"},
                                                    "protocol": {"required": False, "type": "str",
                                                                 "choices": ["smtp",
                                                                             "imap",
                                                                             "pop3"]}
                                                }},
                                    "log": {"required": False, "type": "str",
                                            "choices": ["enable",
                                                        "disable"]},
                                    "scan_archive_contents": {"required": False, "type": "str",
                                                              "choices": ["enable",
                                                                          "disable"]},
                                    "status": {"required": False, "type": "str",
                                               "choices": ["enable",
                                                           "disable"]}
                                }},
                "gmail": {"required": False, "type": "dict",
                          "options": {
                              "log": {"required": False, "type": "str",
                                      "choices": ["enable",
                                                  "disable"]}
                          }},
                "imap": {"required": False, "type": "dict",
                         "options": {
                             "action": {"required": False, "type": "str",
                                        "choices": ["pass",
                                                    "tag"]},
                             "log": {"required": False, "type": "str",
                                     "choices": ["enable",
                                                 "disable"]},
                             "tag_msg": {"required": False, "type": "str"},
                             "tag_type": {"required": False, "type": "str",
                                          "choices": ["subject",
                                                      "header",
                                                      "spaminfo"]}
                         }},
                "mapi": {"required": False, "type": "dict",
                         "options": {
                             "action": {"required": False, "type": "str",
                                        "choices": ["pass",
                                                    "discard"]},
                             "log": {"required": False, "type": "str",
                                     "choices": ["enable",
                                                 "disable"]}
                         }},
                "msn_hotmail": {"required": False, "type": "dict",
                                "options": {
                                    "log": {"required": False, "type": "str",
                                            "choices": ["enable",
                                                        "disable"]}
                                }},
                "name": {"required": True, "type": "str"},
                "options": {"required": False, "type": "str",
                            "choices": ["bannedword",
                                        "spambwl",
                                        "spamfsip",
                                        "spamfssubmit",
                                        "spamfschksum",
                                        "spamfsurl",
                                        "spamhelodns",
                                        "spamraddrdns",
                                        "spamrbl",
                                        "spamhdrcheck",
                                        "spamfsphish"]},
                "pop3": {"required": False, "type": "dict",
                         "options": {
                             "action": {"required": False, "type": "str",
                                        "choices": ["pass",
                                                    "tag"]},
                             "log": {"required": False, "type": "str",
                                     "choices": ["enable",
                                                 "disable"]},
                             "tag_msg": {"required": False, "type": "str"},
                             "tag_type": {"required": False, "type": "str",
                                          "choices": ["subject",
                                                      "header",
                                                      "spaminfo"]}
                         }},
                "replacemsg_group": {"required": False, "type": "str"},
                "smtp": {"required": False, "type": "dict",
                         "options": {
                             "action": {"required": False, "type": "str",
                                        "choices": ["pass",
                                                    "tag",
                                                    "discard"]},
                             "hdrip": {"required": False, "type": "str",
                                       "choices": ["disable",
                                                   "enable"]},
                             "local_override": {"required": False, "type": "str",
                                                "choices": ["disable",
                                                            "enable"]},
                             "log": {"required": False, "type": "str",
                                     "choices": ["enable",
                                                 "disable"]},
                             "tag_msg": {"required": False, "type": "str"},
                             "tag_type": {"required": False, "type": "str",
                                          "choices": ["subject",
                                                      "header",
                                                      "spaminfo"]}
                         }},
                "spam_bwl_table": {"required": False, "type": "int"},
                "spam_bword_table": {"required": False, "type": "int"},
                "spam_bword_threshold": {"required": False, "type": "int"},
                "spam_filtering": {"required": False, "type": "str",
                                   "choices": ["enable",
                                               "disable"]},
                "spam_iptrust_table": {"required": False, "type": "int"},
                "spam_log": {"required": False, "type": "str",
                             "choices": ["disable",
                                         "enable"]},
                "spam_log_fortiguard_response": {"required": False, "type": "str",
                                                 "choices": ["disable",
                                                             "enable"]},
                "spam_mheader_table": {"required": False, "type": "int"},
                "spam_rbl_table": {"required": False, "type": "int"},
                "yahoo_mail": {"required": False, "type": "dict",
                               "options": {
                                   "log": {"required": False, "type": "str",
                                           "choices": ["enable",
                                                       "disable"]}
                               }}

            }
        }
    }

    check_legacy_fortiosapi()
    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if 'access_token' in module.params:
            connection.set_option('access_token', module.params['access_token'])

        fos = FortiOSHandler(connection, module, mkeyname)

        is_error, has_changed, result = fortios_emailfilter(module.params, fos)
        versions_check_result = connection.get_system_version()
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
