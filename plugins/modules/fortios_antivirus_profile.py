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
module: fortios_antivirus_profile
short_description: Configure AntiVirus profiles in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify antivirus feature and profile category.
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
    antivirus_profile:
        description:
            - Configure AntiVirus profiles.
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
            analytics_bl_filetype:
                description:
                    - Only submit files matching this DLP file-pattern to FortiSandbox. Source dlp.filepattern.id.
                type: int
            analytics_db:
                description:
                    - Enable/disable using the FortiSandbox signature database to supplement the AV signature databases.
                type: str
                choices:
                    - disable
                    - enable
            analytics_max_upload:
                description:
                    - Maximum size of files that can be uploaded to FortiSandbox (1 - 395 MBytes).
                type: int
            analytics_wl_filetype:
                description:
                    - Do not submit files matching this DLP file-pattern to FortiSandbox. Source dlp.filepattern.id.
                type: int
            av_block_log:
                description:
                    - Enable/disable logging for AntiVirus file blocking.
                type: str
                choices:
                    - enable
                    - disable
            av_virus_log:
                description:
                    - Enable/disable AntiVirus logging.
                type: str
                choices:
                    - enable
                    - disable
            comment:
                description:
                    - Comment.
                type: str
            content_disarm:
                description:
                    - AV Content Disarm and Reconstruction settings.
                type: dict
                suboptions:
                    cover_page:
                        description:
                            - Enable/disable inserting a cover page into the disarmed document.
                        type: str
                        choices:
                            - disable
                            - enable
                    detect_only:
                        description:
                            - Enable/disable only detect disarmable files, do not alter content.
                        type: str
                        choices:
                            - disable
                            - enable
                    office_embed:
                        description:
                            - Enable/disable stripping of embedded objects in Microsoft Office documents.
                        type: str
                        choices:
                            - disable
                            - enable
                    office_hylink:
                        description:
                            - Enable/disable stripping of hyperlinks in Microsoft Office documents.
                        type: str
                        choices:
                            - disable
                            - enable
                    office_linked:
                        description:
                            - Enable/disable stripping of linked objects in Microsoft Office documents.
                        type: str
                        choices:
                            - disable
                            - enable
                    office_macro:
                        description:
                            - Enable/disable stripping of macros in Microsoft Office documents.
                        type: str
                        choices:
                            - disable
                            - enable
                    original_file_destination:
                        description:
                            - Destination to send original file if active content is removed.
                        type: str
                        choices:
                            - fortisandbox
                            - quarantine
                            - discard
                    pdf_act_form:
                        description:
                            - Enable/disable stripping of actions that submit data to other targets in PDF documents.
                        type: str
                        choices:
                            - disable
                            - enable
                    pdf_act_gotor:
                        description:
                            - Enable/disable stripping of links to other PDFs in PDF documents.
                        type: str
                        choices:
                            - disable
                            - enable
                    pdf_act_java:
                        description:
                            - Enable/disable stripping of actions that execute JavaScript code in PDF documents.
                        type: str
                        choices:
                            - disable
                            - enable
                    pdf_act_launch:
                        description:
                            - Enable/disable stripping of links to external applications in PDF documents.
                        type: str
                        choices:
                            - disable
                            - enable
                    pdf_act_movie:
                        description:
                            - Enable/disable stripping of embedded movies in PDF documents.
                        type: str
                        choices:
                            - disable
                            - enable
                    pdf_act_sound:
                        description:
                            - Enable/disable stripping of embedded sound files in PDF documents.
                        type: str
                        choices:
                            - disable
                            - enable
                    pdf_embedfile:
                        description:
                            - Enable/disable stripping of embedded files in PDF documents.
                        type: str
                        choices:
                            - disable
                            - enable
                    pdf_hyperlink:
                        description:
                            - Enable/disable stripping of hyperlinks from PDF documents.
                        type: str
                        choices:
                            - disable
                            - enable
                    pdf_javacode:
                        description:
                            - Enable/disable stripping of JavaScript code in PDF documents.
                        type: str
                        choices:
                            - disable
                            - enable
            extended_log:
                description:
                    - Enable/disable extended logging for antivirus.
                type: str
                choices:
                    - enable
                    - disable
            ftgd_analytics:
                description:
                    - Settings to control which files are uploaded to FortiSandbox.
                type: str
                choices:
                    - disable
                    - suspicious
                    - everything
            ftp:
                description:
                    - Configure FTP AntiVirus options.
                type: dict
                suboptions:
                    archive_block:
                        description:
                            - Select the archive types to block.
                        type: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - fileslimit
                            - timeout
                            - unhandled
                    archive_log:
                        description:
                            - Select the archive types to log.
                        type: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - fileslimit
                            - timeout
                            - unhandled
                    emulator:
                        description:
                            - Enable/disable the virus emulator.
                        type: str
                        choices:
                            - enable
                            - disable
                    options:
                        description:
                            - Enable/disable FTP AntiVirus scanning, monitoring, and quarantine.
                        type: str
                        choices:
                            - scan
                            - avmonitor
                            - quarantine
                    outbreak_prevention:
                        description:
                            - Enable FortiGuard Virus Outbreak Prevention service.
                        type: str
                        choices:
                            - disabled
                            - files
                            - full-archive
            http:
                description:
                    - Configure HTTP AntiVirus options.
                type: dict
                suboptions:
                    archive_block:
                        description:
                            - Select the archive types to block.
                        type: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - fileslimit
                            - timeout
                            - unhandled
                    archive_log:
                        description:
                            - Select the archive types to log.
                        type: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - fileslimit
                            - timeout
                            - unhandled
                    content_disarm:
                        description:
                            - Enable Content Disarm and Reconstruction for this protocol.
                        type: str
                        choices:
                            - disable
                            - enable
                    emulator:
                        description:
                            - Enable/disable the virus emulator.
                        type: str
                        choices:
                            - enable
                            - disable
                    options:
                        description:
                            - Enable/disable HTTP AntiVirus scanning, monitoring, and quarantine.
                        type: str
                        choices:
                            - scan
                            - avmonitor
                            - quarantine
                    outbreak_prevention:
                        description:
                            - Enable FortiGuard Virus Outbreak Prevention service.
                        type: str
                        choices:
                            - disabled
                            - files
                            - full-archive
            imap:
                description:
                    - Configure IMAP AntiVirus options.
                type: dict
                suboptions:
                    archive_block:
                        description:
                            - Select the archive types to block.
                        type: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - fileslimit
                            - timeout
                            - unhandled
                    archive_log:
                        description:
                            - Select the archive types to log.
                        type: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - fileslimit
                            - timeout
                            - unhandled
                    content_disarm:
                        description:
                            - Enable Content Disarm and Reconstruction for this protocol.
                        type: str
                        choices:
                            - disable
                            - enable
                    emulator:
                        description:
                            - Enable/disable the virus emulator.
                        type: str
                        choices:
                            - enable
                            - disable
                    executables:
                        description:
                            - Treat Windows executable files as viruses for the purpose of blocking or monitoring.
                        type: str
                        choices:
                            - default
                            - virus
                    options:
                        description:
                            - Enable/disable IMAP AntiVirus scanning, monitoring, and quarantine.
                        type: str
                        choices:
                            - scan
                            - avmonitor
                            - quarantine
                    outbreak_prevention:
                        description:
                            - Enable FortiGuard Virus Outbreak Prevention service.
                        type: str
                        choices:
                            - disabled
                            - files
                            - full-archive
            inspection_mode:
                description:
                    - Inspection mode.
                type: str
                choices:
                    - proxy
                    - flow-based
            mapi:
                description:
                    - Configure MAPI AntiVirus options.
                type: dict
                suboptions:
                    archive_block:
                        description:
                            - Select the archive types to block.
                        type: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - fileslimit
                            - timeout
                            - unhandled
                    archive_log:
                        description:
                            - Select the archive types to log.
                        type: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - fileslimit
                            - timeout
                            - unhandled
                    emulator:
                        description:
                            - Enable/disable the virus emulator.
                        type: str
                        choices:
                            - enable
                            - disable
                    executables:
                        description:
                            - Treat Windows executable files as viruses for the purpose of blocking or monitoring.
                        type: str
                        choices:
                            - default
                            - virus
                    options:
                        description:
                            - Enable/disable MAPI AntiVirus scanning, monitoring, and quarantine.
                        type: str
                        choices:
                            - scan
                            - avmonitor
                            - quarantine
                    outbreak_prevention:
                        description:
                            - Enable FortiGuard Virus Outbreak Prevention service.
                        type: str
                        choices:
                            - disabled
                            - files
                            - full-archive
            mobile_malware_db:
                description:
                    - Enable/disable using the mobile malware signature database.
                type: str
                choices:
                    - disable
                    - enable
            nac_quar:
                description:
                    - Configure AntiVirus quarantine settings.
                type: dict
                suboptions:
                    expiry:
                        description:
                            - Duration of quarantine.
                        type: str
                    infected:
                        description:
                            - Enable/Disable quarantining infected hosts to the banned user list.
                        type: str
                        choices:
                            - none
                            - quar-src-ip
                    log:
                        description:
                            - Enable/disable AntiVirus quarantine logging.
                        type: str
                        choices:
                            - enable
                            - disable
            name:
                description:
                    - Profile name.
                required: true
                type: str
            nntp:
                description:
                    - Configure NNTP AntiVirus options.
                type: dict
                suboptions:
                    archive_block:
                        description:
                            - Select the archive types to block.
                        type: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - fileslimit
                            - timeout
                            - unhandled
                    archive_log:
                        description:
                            - Select the archive types to log.
                        type: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - fileslimit
                            - timeout
                            - unhandled
                    emulator:
                        description:
                            - Enable/disable the virus emulator.
                        type: str
                        choices:
                            - enable
                            - disable
                    options:
                        description:
                            - Enable/disable NNTP AntiVirus scanning, monitoring, and quarantine.
                        type: str
                        choices:
                            - scan
                            - avmonitor
                            - quarantine
                    outbreak_prevention:
                        description:
                            - Enable FortiGuard Virus Outbreak Prevention service.
                        type: str
                        choices:
                            - disabled
                            - files
                            - full-archive
            pop3:
                description:
                    - Configure POP3 AntiVirus options.
                type: dict
                suboptions:
                    archive_block:
                        description:
                            - Select the archive types to block.
                        type: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - fileslimit
                            - timeout
                            - unhandled
                    archive_log:
                        description:
                            - Select the archive types to log.
                        type: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - fileslimit
                            - timeout
                            - unhandled
                    content_disarm:
                        description:
                            - Enable Content Disarm and Reconstruction for this protocol.
                        type: str
                        choices:
                            - disable
                            - enable
                    emulator:
                        description:
                            - Enable/disable the virus emulator.
                        type: str
                        choices:
                            - enable
                            - disable
                    executables:
                        description:
                            - Treat Windows executable files as viruses for the purpose of blocking or monitoring.
                        type: str
                        choices:
                            - default
                            - virus
                    options:
                        description:
                            - Enable/disable POP3 AntiVirus scanning, monitoring, and quarantine.
                        type: str
                        choices:
                            - scan
                            - avmonitor
                            - quarantine
                    outbreak_prevention:
                        description:
                            - Enable FortiGuard Virus Outbreak Prevention service.
                        type: str
                        choices:
                            - disabled
                            - files
                            - full-archive
            replacemsg_group:
                description:
                    - Replacement message group customized for this profile. Source system.replacemsg-group.name.
                type: str
            scan_mode:
                description:
                    - Choose between full scan mode and quick scan mode.
                type: str
                choices:
                    - quick
                    - full
            smb:
                description:
                    - Configure SMB AntiVirus options.
                type: dict
                suboptions:
                    archive_block:
                        description:
                            - Select the archive types to block.
                        type: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - fileslimit
                            - timeout
                            - unhandled
                    archive_log:
                        description:
                            - Select the archive types to log.
                        type: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - fileslimit
                            - timeout
                            - unhandled
                    emulator:
                        description:
                            - Enable/disable the virus emulator.
                        type: str
                        choices:
                            - enable
                            - disable
                    options:
                        description:
                            - Enable/disable SMB AntiVirus scanning, monitoring, and quarantine.
                        type: str
                        choices:
                            - scan
                            - avmonitor
                            - quarantine
                    outbreak_prevention:
                        description:
                            - Enable FortiGuard Virus Outbreak Prevention service.
                        type: str
                        choices:
                            - disabled
                            - files
                            - full-archive
            smtp:
                description:
                    - Configure SMTP AntiVirus options.
                type: dict
                suboptions:
                    archive_block:
                        description:
                            - Select the archive types to block.
                        type: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - fileslimit
                            - timeout
                            - unhandled
                    archive_log:
                        description:
                            - Select the archive types to log.
                        type: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - fileslimit
                            - timeout
                            - unhandled
                    content_disarm:
                        description:
                            - Enable Content Disarm and Reconstruction for this protocol.
                        type: str
                        choices:
                            - disable
                            - enable
                    emulator:
                        description:
                            - Enable/disable the virus emulator.
                        type: str
                        choices:
                            - enable
                            - disable
                    executables:
                        description:
                            - Treat Windows executable files as viruses for the purpose of blocking or monitoring.
                        type: str
                        choices:
                            - default
                            - virus
                    options:
                        description:
                            - Enable/disable SMTP AntiVirus scanning, monitoring, and quarantine.
                        type: str
                        choices:
                            - scan
                            - avmonitor
                            - quarantine
                    outbreak_prevention:
                        description:
                            - Enable FortiGuard Virus Outbreak Prevention service.
                        type: str
                        choices:
                            - disabled
                            - files
                            - full-archive
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
  - name: Configure AntiVirus profiles.
    fortios_antivirus_profile:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      antivirus_profile:
        analytics_bl_filetype: "3 (source dlp.filepattern.id)"
        analytics_db: "disable"
        analytics_max_upload: "5"
        analytics_wl_filetype: "6 (source dlp.filepattern.id)"
        av_block_log: "enable"
        av_virus_log: "enable"
        comment: "Comment."
        content_disarm:
            cover_page: "disable"
            detect_only: "disable"
            office_embed: "disable"
            office_hylink: "disable"
            office_linked: "disable"
            office_macro: "disable"
            original_file_destination: "fortisandbox"
            pdf_act_form: "disable"
            pdf_act_gotor: "disable"
            pdf_act_java: "disable"
            pdf_act_launch: "disable"
            pdf_act_movie: "disable"
            pdf_act_sound: "disable"
            pdf_embedfile: "disable"
            pdf_hyperlink: "disable"
            pdf_javacode: "disable"
        extended_log: "enable"
        ftgd_analytics: "disable"
        ftp:
            archive_block: "encrypted"
            archive_log: "encrypted"
            emulator: "enable"
            options: "scan"
            outbreak_prevention: "disabled"
        http:
            archive_block: "encrypted"
            archive_log: "encrypted"
            content_disarm: "disable"
            emulator: "enable"
            options: "scan"
            outbreak_prevention: "disabled"
        imap:
            archive_block: "encrypted"
            archive_log: "encrypted"
            content_disarm: "disable"
            emulator: "enable"
            executables: "default"
            options: "scan"
            outbreak_prevention: "disabled"
        inspection_mode: "proxy"
        mapi:
            archive_block: "encrypted"
            archive_log: "encrypted"
            emulator: "enable"
            executables: "default"
            options: "scan"
            outbreak_prevention: "disabled"
        mobile_malware_db: "disable"
        nac_quar:
            expiry: "<your_own_value>"
            infected: "none"
            log: "enable"
        name: "default_name_63"
        nntp:
            archive_block: "encrypted"
            archive_log: "encrypted"
            emulator: "enable"
            options: "scan"
            outbreak_prevention: "disabled"
        pop3:
            archive_block: "encrypted"
            archive_log: "encrypted"
            content_disarm: "disable"
            emulator: "enable"
            executables: "default"
            options: "scan"
            outbreak_prevention: "disabled"
        replacemsg_group: "<your_own_value> (source system.replacemsg-group.name)"
        scan_mode: "quick"
        smb:
            archive_block: "encrypted"
            archive_log: "encrypted"
            emulator: "enable"
            options: "scan"
            outbreak_prevention: "disabled"
        smtp:
            archive_block: "encrypted"
            archive_log: "encrypted"
            content_disarm: "disable"
            emulator: "enable"
            executables: "default"
            options: "scan"
            outbreak_prevention: "disabled"

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


def filter_antivirus_profile_data(json):
    option_list = ['analytics_bl_filetype', 'analytics_db', 'analytics_max_upload',
                   'analytics_wl_filetype', 'av_block_log', 'av_virus_log',
                   'comment', 'content_disarm', 'extended_log',
                   'ftgd_analytics', 'ftp', 'http',
                   'imap', 'inspection_mode', 'mapi',
                   'mobile_malware_db', 'nac_quar', 'name',
                   'nntp', 'pop3', 'replacemsg_group',
                   'scan_mode', 'smb', 'smtp']
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


def antivirus_profile(data, fos):
    vdom = data['vdom']
    if 'state' in data and data['state']:
        state = data['state']
    elif 'state' in data['antivirus_profile'] and data['antivirus_profile']['state']:
        state = data['antivirus_profile']['state']
    else:
        state = True
    antivirus_profile_data = data['antivirus_profile']
    filtered_data = underscore_to_hyphen(filter_antivirus_profile_data(antivirus_profile_data))

    if state == "present":
        return fos.set('antivirus',
                       'profile',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('antivirus',
                          'profile',
                          mkey=filtered_data['name'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_antivirus(data, fos):

    if data['antivirus_profile']:
        resp = antivirus_profile(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('antivirus_profile'))

    return not is_successful_status(resp), \
        resp['status'] == "success" and \
        (resp['revision_changed'] if 'revision_changed' in resp else True), \
        resp


def main():
    mkeyname = 'name'
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "state": {"required": False, "type": "str",
                  "choices": ["present", "absent"]},
        "antivirus_profile": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "state": {"required": False, "type": "str",
                          "choices": ["present", "absent"]},
                "analytics_bl_filetype": {"required": False, "type": "int"},
                "analytics_db": {"required": False, "type": "str",
                                 "choices": ["disable",
                                             "enable"]},
                "analytics_max_upload": {"required": False, "type": "int"},
                "analytics_wl_filetype": {"required": False, "type": "int"},
                "av_block_log": {"required": False, "type": "str",
                                 "choices": ["enable",
                                             "disable"]},
                "av_virus_log": {"required": False, "type": "str",
                                 "choices": ["enable",
                                             "disable"]},
                "comment": {"required": False, "type": "str"},
                "content_disarm": {"required": False, "type": "dict",
                                   "options": {
                                       "cover_page": {"required": False, "type": "str",
                                                      "choices": ["disable",
                                                                  "enable"]},
                                       "detect_only": {"required": False, "type": "str",
                                                       "choices": ["disable",
                                                                   "enable"]},
                                       "office_embed": {"required": False, "type": "str",
                                                        "choices": ["disable",
                                                                    "enable"]},
                                       "office_hylink": {"required": False, "type": "str",
                                                         "choices": ["disable",
                                                                     "enable"]},
                                       "office_linked": {"required": False, "type": "str",
                                                         "choices": ["disable",
                                                                     "enable"]},
                                       "office_macro": {"required": False, "type": "str",
                                                        "choices": ["disable",
                                                                    "enable"]},
                                       "original_file_destination": {"required": False, "type": "str",
                                                                     "choices": ["fortisandbox",
                                                                                 "quarantine",
                                                                                 "discard"]},
                                       "pdf_act_form": {"required": False, "type": "str",
                                                        "choices": ["disable",
                                                                    "enable"]},
                                       "pdf_act_gotor": {"required": False, "type": "str",
                                                         "choices": ["disable",
                                                                     "enable"]},
                                       "pdf_act_java": {"required": False, "type": "str",
                                                        "choices": ["disable",
                                                                    "enable"]},
                                       "pdf_act_launch": {"required": False, "type": "str",
                                                          "choices": ["disable",
                                                                      "enable"]},
                                       "pdf_act_movie": {"required": False, "type": "str",
                                                         "choices": ["disable",
                                                                     "enable"]},
                                       "pdf_act_sound": {"required": False, "type": "str",
                                                         "choices": ["disable",
                                                                     "enable"]},
                                       "pdf_embedfile": {"required": False, "type": "str",
                                                         "choices": ["disable",
                                                                     "enable"]},
                                       "pdf_hyperlink": {"required": False, "type": "str",
                                                         "choices": ["disable",
                                                                     "enable"]},
                                       "pdf_javacode": {"required": False, "type": "str",
                                                        "choices": ["disable",
                                                                    "enable"]}
                                   }},
                "extended_log": {"required": False, "type": "str",
                                 "choices": ["enable",
                                             "disable"]},
                "ftgd_analytics": {"required": False, "type": "str",
                                   "choices": ["disable",
                                               "suspicious",
                                               "everything"]},
                "ftp": {"required": False, "type": "dict",
                        "options": {
                            "archive_block": {"required": False, "type": "str",
                                              "choices": ["encrypted",
                                                          "corrupted",
                                                          "partiallycorrupted",
                                                          "multipart",
                                                          "nested",
                                                          "mailbomb",
                                                          "fileslimit",
                                                          "timeout",
                                                          "unhandled"]},
                            "archive_log": {"required": False, "type": "str",
                                            "choices": ["encrypted",
                                                        "corrupted",
                                                        "partiallycorrupted",
                                                        "multipart",
                                                        "nested",
                                                        "mailbomb",
                                                        "fileslimit",
                                                        "timeout",
                                                        "unhandled"]},
                            "emulator": {"required": False, "type": "str",
                                         "choices": ["enable",
                                                     "disable"]},
                            "options": {"required": False, "type": "str",
                                        "choices": ["scan",
                                                    "avmonitor",
                                                    "quarantine"]},
                            "outbreak_prevention": {"required": False, "type": "str",
                                                    "choices": ["disabled",
                                                                "files",
                                                                "full-archive"]}
                        }},
                "http": {"required": False, "type": "dict",
                         "options": {
                             "archive_block": {"required": False, "type": "str",
                                               "choices": ["encrypted",
                                                           "corrupted",
                                                           "partiallycorrupted",
                                                           "multipart",
                                                           "nested",
                                                           "mailbomb",
                                                           "fileslimit",
                                                           "timeout",
                                                           "unhandled"]},
                             "archive_log": {"required": False, "type": "str",
                                             "choices": ["encrypted",
                                                         "corrupted",
                                                         "partiallycorrupted",
                                                         "multipart",
                                                         "nested",
                                                         "mailbomb",
                                                         "fileslimit",
                                                         "timeout",
                                                         "unhandled"]},
                             "content_disarm": {"required": False, "type": "str",
                                                "choices": ["disable",
                                                            "enable"]},
                             "emulator": {"required": False, "type": "str",
                                          "choices": ["enable",
                                                      "disable"]},
                             "options": {"required": False, "type": "str",
                                         "choices": ["scan",
                                                     "avmonitor",
                                                     "quarantine"]},
                             "outbreak_prevention": {"required": False, "type": "str",
                                                     "choices": ["disabled",
                                                                 "files",
                                                                 "full-archive"]}
                         }},
                "imap": {"required": False, "type": "dict",
                         "options": {
                             "archive_block": {"required": False, "type": "str",
                                               "choices": ["encrypted",
                                                           "corrupted",
                                                           "partiallycorrupted",
                                                           "multipart",
                                                           "nested",
                                                           "mailbomb",
                                                           "fileslimit",
                                                           "timeout",
                                                           "unhandled"]},
                             "archive_log": {"required": False, "type": "str",
                                             "choices": ["encrypted",
                                                         "corrupted",
                                                         "partiallycorrupted",
                                                         "multipart",
                                                         "nested",
                                                         "mailbomb",
                                                         "fileslimit",
                                                         "timeout",
                                                         "unhandled"]},
                             "content_disarm": {"required": False, "type": "str",
                                                "choices": ["disable",
                                                            "enable"]},
                             "emulator": {"required": False, "type": "str",
                                          "choices": ["enable",
                                                      "disable"]},
                             "executables": {"required": False, "type": "str",
                                             "choices": ["default",
                                                         "virus"]},
                             "options": {"required": False, "type": "str",
                                         "choices": ["scan",
                                                     "avmonitor",
                                                     "quarantine"]},
                             "outbreak_prevention": {"required": False, "type": "str",
                                                     "choices": ["disabled",
                                                                 "files",
                                                                 "full-archive"]}
                         }},
                "inspection_mode": {"required": False, "type": "str",
                                    "choices": ["proxy",
                                                "flow-based"]},
                "mapi": {"required": False, "type": "dict",
                         "options": {
                             "archive_block": {"required": False, "type": "str",
                                               "choices": ["encrypted",
                                                           "corrupted",
                                                           "partiallycorrupted",
                                                           "multipart",
                                                           "nested",
                                                           "mailbomb",
                                                           "fileslimit",
                                                           "timeout",
                                                           "unhandled"]},
                             "archive_log": {"required": False, "type": "str",
                                             "choices": ["encrypted",
                                                         "corrupted",
                                                         "partiallycorrupted",
                                                         "multipart",
                                                         "nested",
                                                         "mailbomb",
                                                         "fileslimit",
                                                         "timeout",
                                                         "unhandled"]},
                             "emulator": {"required": False, "type": "str",
                                          "choices": ["enable",
                                                      "disable"]},
                             "executables": {"required": False, "type": "str",
                                             "choices": ["default",
                                                         "virus"]},
                             "options": {"required": False, "type": "str",
                                         "choices": ["scan",
                                                     "avmonitor",
                                                     "quarantine"]},
                             "outbreak_prevention": {"required": False, "type": "str",
                                                     "choices": ["disabled",
                                                                 "files",
                                                                 "full-archive"]}
                         }},
                "mobile_malware_db": {"required": False, "type": "str",
                                      "choices": ["disable",
                                                  "enable"]},
                "nac_quar": {"required": False, "type": "dict",
                             "options": {
                                 "expiry": {"required": False, "type": "str"},
                                 "infected": {"required": False, "type": "str",
                                              "choices": ["none",
                                                          "quar-src-ip"]},
                                 "log": {"required": False, "type": "str",
                                         "choices": ["enable",
                                                     "disable"]}
                             }},
                "name": {"required": True, "type": "str"},
                "nntp": {"required": False, "type": "dict",
                         "options": {
                             "archive_block": {"required": False, "type": "str",
                                               "choices": ["encrypted",
                                                           "corrupted",
                                                           "partiallycorrupted",
                                                           "multipart",
                                                           "nested",
                                                           "mailbomb",
                                                           "fileslimit",
                                                           "timeout",
                                                           "unhandled"]},
                             "archive_log": {"required": False, "type": "str",
                                             "choices": ["encrypted",
                                                         "corrupted",
                                                         "partiallycorrupted",
                                                         "multipart",
                                                         "nested",
                                                         "mailbomb",
                                                         "fileslimit",
                                                         "timeout",
                                                         "unhandled"]},
                             "emulator": {"required": False, "type": "str",
                                          "choices": ["enable",
                                                      "disable"]},
                             "options": {"required": False, "type": "str",
                                         "choices": ["scan",
                                                     "avmonitor",
                                                     "quarantine"]},
                             "outbreak_prevention": {"required": False, "type": "str",
                                                     "choices": ["disabled",
                                                                 "files",
                                                                 "full-archive"]}
                         }},
                "pop3": {"required": False, "type": "dict",
                         "options": {
                             "archive_block": {"required": False, "type": "str",
                                               "choices": ["encrypted",
                                                           "corrupted",
                                                           "partiallycorrupted",
                                                           "multipart",
                                                           "nested",
                                                           "mailbomb",
                                                           "fileslimit",
                                                           "timeout",
                                                           "unhandled"]},
                             "archive_log": {"required": False, "type": "str",
                                             "choices": ["encrypted",
                                                         "corrupted",
                                                         "partiallycorrupted",
                                                         "multipart",
                                                         "nested",
                                                         "mailbomb",
                                                         "fileslimit",
                                                         "timeout",
                                                         "unhandled"]},
                             "content_disarm": {"required": False, "type": "str",
                                                "choices": ["disable",
                                                            "enable"]},
                             "emulator": {"required": False, "type": "str",
                                          "choices": ["enable",
                                                      "disable"]},
                             "executables": {"required": False, "type": "str",
                                             "choices": ["default",
                                                         "virus"]},
                             "options": {"required": False, "type": "str",
                                         "choices": ["scan",
                                                     "avmonitor",
                                                     "quarantine"]},
                             "outbreak_prevention": {"required": False, "type": "str",
                                                     "choices": ["disabled",
                                                                 "files",
                                                                 "full-archive"]}
                         }},
                "replacemsg_group": {"required": False, "type": "str"},
                "scan_mode": {"required": False, "type": "str",
                              "choices": ["quick",
                                          "full"]},
                "smb": {"required": False, "type": "dict",
                        "options": {
                            "archive_block": {"required": False, "type": "str",
                                              "choices": ["encrypted",
                                                          "corrupted",
                                                          "partiallycorrupted",
                                                          "multipart",
                                                          "nested",
                                                          "mailbomb",
                                                          "fileslimit",
                                                          "timeout",
                                                          "unhandled"]},
                            "archive_log": {"required": False, "type": "str",
                                            "choices": ["encrypted",
                                                        "corrupted",
                                                        "partiallycorrupted",
                                                        "multipart",
                                                        "nested",
                                                        "mailbomb",
                                                        "fileslimit",
                                                        "timeout",
                                                        "unhandled"]},
                            "emulator": {"required": False, "type": "str",
                                         "choices": ["enable",
                                                     "disable"]},
                            "options": {"required": False, "type": "str",
                                        "choices": ["scan",
                                                    "avmonitor",
                                                    "quarantine"]},
                            "outbreak_prevention": {"required": False, "type": "str",
                                                    "choices": ["disabled",
                                                                "files",
                                                                "full-archive"]}
                        }},
                "smtp": {"required": False, "type": "dict",
                         "options": {
                             "archive_block": {"required": False, "type": "str",
                                               "choices": ["encrypted",
                                                           "corrupted",
                                                           "partiallycorrupted",
                                                           "multipart",
                                                           "nested",
                                                           "mailbomb",
                                                           "fileslimit",
                                                           "timeout",
                                                           "unhandled"]},
                             "archive_log": {"required": False, "type": "str",
                                             "choices": ["encrypted",
                                                         "corrupted",
                                                         "partiallycorrupted",
                                                         "multipart",
                                                         "nested",
                                                         "mailbomb",
                                                         "fileslimit",
                                                         "timeout",
                                                         "unhandled"]},
                             "content_disarm": {"required": False, "type": "str",
                                                "choices": ["disable",
                                                            "enable"]},
                             "emulator": {"required": False, "type": "str",
                                          "choices": ["enable",
                                                      "disable"]},
                             "executables": {"required": False, "type": "str",
                                             "choices": ["default",
                                                         "virus"]},
                             "options": {"required": False, "type": "str",
                                         "choices": ["scan",
                                                     "avmonitor",
                                                     "quarantine"]},
                             "outbreak_prevention": {"required": False, "type": "str",
                                                     "choices": ["disabled",
                                                                 "files",
                                                                 "full-archive"]}
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

        is_error, has_changed, result = fortios_antivirus(module.params, fos)
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
