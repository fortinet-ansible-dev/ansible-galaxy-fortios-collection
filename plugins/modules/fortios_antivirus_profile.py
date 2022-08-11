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
module: fortios_antivirus_profile
short_description: Configure AntiVirus profiles in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify antivirus feature and profile category.
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
    antivirus_profile:
        description:
            - Configure AntiVirus profiles.
        default: null
        type: dict
        suboptions:
            analytics_accept_filetype:
                description:
                    - Only submit files matching this DLP file-pattern to FortiSandbox (post-transfer scan only). Source dlp.filepattern.id.
                type: int
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
            analytics_ignore_filetype:
                description:
                    - Do not submit files matching this DLP file-pattern to FortiSandbox (post-transfer scan only). Source dlp.filepattern.id.
                type: int
            analytics_max_upload:
                description:
                    - Maximum size of files that can be uploaded to FortiSandbox.
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
            cifs:
                description:
                    - Configure CIFS AntiVirus options.
                type: dict
                suboptions:
                    archive_block:
                        description:
                            - Select the archive types to block.
                        type: list
                        elements: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - timeout
                            - unhandled
                            - fileslimit
                    archive_log:
                        description:
                            - Select the archive types to log.
                        type: list
                        elements: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - timeout
                            - unhandled
                            - fileslimit
                    av_scan:
                        description:
                            - Enable AntiVirus scan service.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    emulator:
                        description:
                            - Enable/disable the virus emulator.
                        type: str
                        choices:
                            - enable
                            - disable
                    external_blocklist:
                        description:
                            - Enable external-blocklist. Analyzes files including the content of archives.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    fortiai:
                        description:
                            - Enable/disable scanning of files by FortiAI.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    fortindr:
                        description:
                            - Enable scanning of files by FortiNDR.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    fortisandbox:
                        description:
                            - Enable scanning of files by FortiSandbox.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    options:
                        description:
                            - Enable/disable CIFS AntiVirus scanning, monitoring, and quarantine.
                        type: list
                        elements: str
                        choices:
                            - scan
                            - avmonitor
                            - quarantine
                    outbreak_prevention:
                        description:
                            - Enable virus outbreak prevention service.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                            - disabled
                            - files
                            - full-archive
                    quarantine:
                        description:
                            - Enable/disable quarantine for infected files.
                        type: str
                        choices:
                            - disable
                            - enable
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
                    error_action:
                        description:
                            - Action to be taken if CDR engine encounters an unrecoverable error.
                        type: str
                        choices:
                            - block
                            - log-only
                            - ignore
                    office_action:
                        description:
                            - Enable/disable stripping of PowerPoint action events in Microsoft Office documents.
                        type: str
                        choices:
                            - disable
                            - enable
                    office_dde:
                        description:
                            - Enable/disable stripping of Dynamic Data Exchange events in Microsoft Office documents.
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
                            - Enable/disable stripping of PDF document actions that submit data to other targets.
                        type: str
                        choices:
                            - disable
                            - enable
                    pdf_act_gotor:
                        description:
                            - Enable/disable stripping of PDF document actions that access other PDF documents.
                        type: str
                        choices:
                            - disable
                            - enable
                    pdf_act_java:
                        description:
                            - Enable/disable stripping of PDF document actions that execute JavaScript code.
                        type: str
                        choices:
                            - disable
                            - enable
                    pdf_act_launch:
                        description:
                            - Enable/disable stripping of PDF document actions that launch other applications.
                        type: str
                        choices:
                            - disable
                            - enable
                    pdf_act_movie:
                        description:
                            - Enable/disable stripping of PDF document actions that play a movie.
                        type: str
                        choices:
                            - disable
                            - enable
                    pdf_act_sound:
                        description:
                            - Enable/disable stripping of PDF document actions that play a sound.
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
            ems_threat_feed:
                description:
                    - Enable/disable use of EMS threat feed when performing AntiVirus scan. Analyzes files including the content of archives.
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
            external_blocklist:
                description:
                    - One or more external malware block lists.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - External blocklist. Source system.external-resource.name.
                        type: str
            external_blocklist_archive_scan:
                description:
                    - Enable/disable external-blocklist archive scanning.
                type: str
                choices:
                    - disable
                    - enable
            external_blocklist_enable_all:
                description:
                    - Enable/disable all external blocklists.
                type: str
                choices:
                    - disable
                    - enable
            feature_set:
                description:
                    - Flow/proxy feature set.
                type: str
                choices:
                    - flow
                    - proxy
            fortiai_error_action:
                description:
                    - Action to take if FortiAI encounters an error.
                type: str
                choices:
                    - log-only
                    - block
                    - ignore
            fortiai_timeout_action:
                description:
                    - Action to take if FortiAI encounters a scan timeout.
                type: str
                choices:
                    - log-only
                    - block
                    - ignore
            fortindr_error_action:
                description:
                    - Action to take if FortiNDR encounters an error.
                type: str
                choices:
                    - log-only
                    - block
                    - ignore
            fortindr_timeout_action:
                description:
                    - Action to take if FortiNDR encounters a scan timeout.
                type: str
                choices:
                    - log-only
                    - block
                    - ignore
            fortisandbox_error_action:
                description:
                    - Action to take if FortiSandbox inline scan encounters an error.
                type: str
                choices:
                    - log-only
                    - block
                    - ignore
            fortisandbox_max_upload:
                description:
                    - Maximum size of files that can be uploaded to FortiSandbox.
                type: int
            fortisandbox_mode:
                description:
                    - FortiSandbox scan modes.
                type: str
                choices:
                    - inline
                    - analytics-suspicious
                    - analytics-everything
            fortisandbox_timeout_action:
                description:
                    - Action to take if FortiSandbox inline scan encounters a scan timeout.
                type: str
                choices:
                    - log-only
                    - block
                    - ignore
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
                        type: list
                        elements: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - timeout
                            - unhandled
                            - fileslimit
                    archive_log:
                        description:
                            - Select the archive types to log.
                        type: list
                        elements: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - timeout
                            - unhandled
                            - fileslimit
                    av_scan:
                        description:
                            - Enable AntiVirus scan service.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    emulator:
                        description:
                            - Enable/disable the virus emulator.
                        type: str
                        choices:
                            - enable
                            - disable
                    external_blocklist:
                        description:
                            - Enable external-blocklist. Analyzes files including the content of archives.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    fortiai:
                        description:
                            - Enable/disable scanning of files by FortiAI.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    fortindr:
                        description:
                            - Enable scanning of files by FortiNDR.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    fortisandbox:
                        description:
                            - Enable scanning of files by FortiSandbox.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    options:
                        description:
                            - Enable/disable FTP AntiVirus scanning, monitoring, and quarantine.
                        type: list
                        elements: str
                        choices:
                            - scan
                            - avmonitor
                            - quarantine
                    outbreak_prevention:
                        description:
                            - Enable virus outbreak prevention service.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                            - disabled
                            - files
                            - full-archive
                    quarantine:
                        description:
                            - Enable/disable quarantine for infected files.
                        type: str
                        choices:
                            - disable
                            - enable
            http:
                description:
                    - Configure HTTP AntiVirus options.
                type: dict
                suboptions:
                    archive_block:
                        description:
                            - Select the archive types to block.
                        type: list
                        elements: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - timeout
                            - unhandled
                            - fileslimit
                    archive_log:
                        description:
                            - Select the archive types to log.
                        type: list
                        elements: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - timeout
                            - unhandled
                            - fileslimit
                    av_scan:
                        description:
                            - Enable AntiVirus scan service.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    content_disarm:
                        description:
                            - Enable/disable Content Disarm and Reconstruction when performing AntiVirus scan.
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
                    external_blocklist:
                        description:
                            - Enable external-blocklist. Analyzes files including the content of archives.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    fortiai:
                        description:
                            - Enable/disable scanning of files by FortiAI.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    fortindr:
                        description:
                            - Enable scanning of files by FortiNDR.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    fortisandbox:
                        description:
                            - Enable scanning of files by FortiSandbox.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    options:
                        description:
                            - Enable/disable HTTP AntiVirus scanning, monitoring, and quarantine.
                        type: list
                        elements: str
                        choices:
                            - scan
                            - avmonitor
                            - quarantine
                    outbreak_prevention:
                        description:
                            - Enable virus outbreak prevention service.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                            - disabled
                            - files
                            - full-archive
                    quarantine:
                        description:
                            - Enable/disable quarantine for infected files.
                        type: str
                        choices:
                            - disable
                            - enable
            imap:
                description:
                    - Configure IMAP AntiVirus options.
                type: dict
                suboptions:
                    archive_block:
                        description:
                            - Select the archive types to block.
                        type: list
                        elements: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - timeout
                            - unhandled
                            - fileslimit
                    archive_log:
                        description:
                            - Select the archive types to log.
                        type: list
                        elements: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - timeout
                            - unhandled
                            - fileslimit
                    av_scan:
                        description:
                            - Enable AntiVirus scan service.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    content_disarm:
                        description:
                            - Enable/disable Content Disarm and Reconstruction when performing AntiVirus scan.
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
                    external_blocklist:
                        description:
                            - Enable external-blocklist. Analyzes files including the content of archives.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    fortiai:
                        description:
                            - Enable/disable scanning of files by FortiAI.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    fortindr:
                        description:
                            - Enable scanning of files by FortiNDR.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    fortisandbox:
                        description:
                            - Enable scanning of files by FortiSandbox.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    options:
                        description:
                            - Enable/disable IMAP AntiVirus scanning, monitoring, and quarantine.
                        type: list
                        elements: str
                        choices:
                            - scan
                            - avmonitor
                            - quarantine
                    outbreak_prevention:
                        description:
                            - Enable virus outbreak prevention service.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                            - disabled
                            - files
                            - full-archive
                    quarantine:
                        description:
                            - Enable/disable quarantine for infected files.
                        type: str
                        choices:
                            - disable
                            - enable
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
                        type: list
                        elements: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - timeout
                            - unhandled
                            - fileslimit
                    archive_log:
                        description:
                            - Select the archive types to log.
                        type: list
                        elements: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - timeout
                            - unhandled
                            - fileslimit
                    av_scan:
                        description:
                            - Enable AntiVirus scan service.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
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
                    external_blocklist:
                        description:
                            - Enable external-blocklist. Analyzes files including the content of archives.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    fortiai:
                        description:
                            - Enable/disable scanning of files by FortiAI.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    fortindr:
                        description:
                            - Enable scanning of files by FortiNDR.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    fortisandbox:
                        description:
                            - Enable scanning of files by FortiSandbox.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    options:
                        description:
                            - Enable/disable MAPI AntiVirus scanning, monitoring, and quarantine.
                        type: list
                        elements: str
                        choices:
                            - scan
                            - avmonitor
                            - quarantine
                    outbreak_prevention:
                        description:
                            - Enable virus outbreak prevention service.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                            - disabled
                            - files
                            - full-archive
                    quarantine:
                        description:
                            - Enable/disable quarantine for infected files.
                        type: str
                        choices:
                            - disable
                            - enable
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
                        type: list
                        elements: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - timeout
                            - unhandled
                            - fileslimit
                    archive_log:
                        description:
                            - Select the archive types to log.
                        type: list
                        elements: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - timeout
                            - unhandled
                            - fileslimit
                    av_scan:
                        description:
                            - Enable AntiVirus scan service.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    emulator:
                        description:
                            - Enable/disable the virus emulator.
                        type: str
                        choices:
                            - enable
                            - disable
                    external_blocklist:
                        description:
                            - Enable external-blocklist. Analyzes files including the content of archives.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    fortiai:
                        description:
                            - Enable/disable scanning of files by FortiAI.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    fortindr:
                        description:
                            - Enable scanning of files by FortiNDR.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    fortisandbox:
                        description:
                            - Enable scanning of files by FortiSandbox.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    options:
                        description:
                            - Enable/disable NNTP AntiVirus scanning, monitoring, and quarantine.
                        type: list
                        elements: str
                        choices:
                            - scan
                            - avmonitor
                            - quarantine
                    outbreak_prevention:
                        description:
                            - Enable virus outbreak prevention service.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                            - disabled
                            - files
                            - full-archive
                    quarantine:
                        description:
                            - Enable/disable quarantine for infected files.
                        type: str
                        choices:
                            - disable
                            - enable
            outbreak_prevention:
                description:
                    - Configure Virus Outbreak Prevention settings.
                type: dict
                suboptions:
                    external_blocklist:
                        description:
                            - Enable/disable external malware blocklist.
                        type: str
                        choices:
                            - disable
                            - enable
                    ftgd_service:
                        description:
                            - Enable/disable FortiGuard Virus outbreak prevention service.
                        type: str
                        choices:
                            - disable
                            - enable
            outbreak_prevention_archive_scan:
                description:
                    - Enable/disable outbreak-prevention archive scanning.
                type: str
                choices:
                    - disable
                    - enable
            pop3:
                description:
                    - Configure POP3 AntiVirus options.
                type: dict
                suboptions:
                    archive_block:
                        description:
                            - Select the archive types to block.
                        type: list
                        elements: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - timeout
                            - unhandled
                            - fileslimit
                    archive_log:
                        description:
                            - Select the archive types to log.
                        type: list
                        elements: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - timeout
                            - unhandled
                            - fileslimit
                    av_scan:
                        description:
                            - Enable AntiVirus scan service.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    content_disarm:
                        description:
                            - Enable/disable Content Disarm and Reconstruction when performing AntiVirus scan.
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
                    external_blocklist:
                        description:
                            - Enable external-blocklist. Analyzes files including the content of archives.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    fortiai:
                        description:
                            - Enable/disable scanning of files by FortiAI.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    fortindr:
                        description:
                            - Enable scanning of files by FortiNDR.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    fortisandbox:
                        description:
                            - Enable scanning of files by FortiSandbox.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    options:
                        description:
                            - Enable/disable POP3 AntiVirus scanning, monitoring, and quarantine.
                        type: list
                        elements: str
                        choices:
                            - scan
                            - avmonitor
                            - quarantine
                    outbreak_prevention:
                        description:
                            - Enable virus outbreak prevention service.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                            - disabled
                            - files
                            - full-archive
                    quarantine:
                        description:
                            - Enable/disable quarantine for infected files.
                        type: str
                        choices:
                            - disable
                            - enable
            replacemsg_group:
                description:
                    - Replacement message group customized for this profile. Source system.replacemsg-group.name.
                type: str
            scan_mode:
                description:
                    - Configure scan mode .
                type: str
                choices:
                    - default
                    - legacy
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
                        type: list
                        elements: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - timeout
                            - unhandled
                            - fileslimit
                    archive_log:
                        description:
                            - Select the archive types to log.
                        type: list
                        elements: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - timeout
                            - unhandled
                            - fileslimit
                    av_scan:
                        description:
                            - Enable AntiVirus scan service.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    content_disarm:
                        description:
                            - Enable/disable Content Disarm and Reconstruction when performing AntiVirus scan.
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
                    external_blocklist:
                        description:
                            - Enable external-blocklist. Analyzes files including the content of archives.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    fortiai:
                        description:
                            - Enable/disable scanning of files by FortiAI.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    fortindr:
                        description:
                            - Enable scanning of files by FortiNDR.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    fortisandbox:
                        description:
                            - Enable scanning of files by FortiSandbox.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    options:
                        description:
                            - Enable/disable SMTP AntiVirus scanning, monitoring, and quarantine.
                        type: list
                        elements: str
                        choices:
                            - scan
                            - avmonitor
                            - quarantine
                    outbreak_prevention:
                        description:
                            - Enable virus outbreak prevention service.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                            - disabled
                            - files
                            - full-archive
                    quarantine:
                        description:
                            - Enable/disable quarantine for infected files.
                        type: str
                        choices:
                            - disable
                            - enable
            ssh:
                description:
                    - Configure SFTP and SCP AntiVirus options.
                type: dict
                suboptions:
                    archive_block:
                        description:
                            - Select the archive types to block.
                        type: list
                        elements: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - timeout
                            - unhandled
                            - fileslimit
                    archive_log:
                        description:
                            - Select the archive types to log.
                        type: list
                        elements: str
                        choices:
                            - encrypted
                            - corrupted
                            - partiallycorrupted
                            - multipart
                            - nested
                            - mailbomb
                            - timeout
                            - unhandled
                            - fileslimit
                    av_scan:
                        description:
                            - Enable AntiVirus scan service.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    emulator:
                        description:
                            - Enable/disable the virus emulator.
                        type: str
                        choices:
                            - enable
                            - disable
                    external_blocklist:
                        description:
                            - Enable external-blocklist. Analyzes files including the content of archives.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    fortiai:
                        description:
                            - Enable/disable scanning of files by FortiAI.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    fortindr:
                        description:
                            - Enable scanning of files by FortiNDR.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    fortisandbox:
                        description:
                            - Enable scanning of files by FortiSandbox.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                    options:
                        description:
                            - Enable/disable SFTP and SCP AntiVirus scanning, monitoring, and quarantine.
                        type: list
                        elements: str
                        choices:
                            - scan
                            - avmonitor
                            - quarantine
                    outbreak_prevention:
                        description:
                            - Enable virus outbreak prevention service.
                        type: str
                        choices:
                            - disable
                            - block
                            - monitor
                            - disabled
                            - files
                            - full-archive
                    quarantine:
                        description:
                            - Enable/disable quarantine for infected files.
                        type: str
                        choices:
                            - disable
                            - enable
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
  - name: Configure AntiVirus profiles.
    fortios_antivirus_profile:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      antivirus_profile:
        analytics_accept_filetype: "3 (source dlp.filepattern.id)"
        analytics_bl_filetype: "4 (source dlp.filepattern.id)"
        analytics_db: "disable"
        analytics_ignore_filetype: "6 (source dlp.filepattern.id)"
        analytics_max_upload: "7"
        analytics_wl_filetype: "8 (source dlp.filepattern.id)"
        av_block_log: "enable"
        av_virus_log: "enable"
        cifs:
            archive_block: "encrypted"
            archive_log: "encrypted"
            av_scan: "disable"
            emulator: "enable"
            external_blocklist: "disable"
            fortiai: "disable"
            fortindr: "disable"
            fortisandbox: "disable"
            options: "scan"
            outbreak_prevention: "disable"
            quarantine: "disable"
        comment: "Comment."
        content_disarm:
            cover_page: "disable"
            detect_only: "disable"
            error_action: "block"
            office_action: "disable"
            office_dde: "disable"
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
        ems_threat_feed: "disable"
        extended_log: "enable"
        external_blocklist:
         -
            name: "default_name_47 (source system.external-resource.name)"
        external_blocklist_archive_scan: "disable"
        external_blocklist_enable_all: "disable"
        feature_set: "flow"
        fortiai_error_action: "log-only"
        fortiai_timeout_action: "log-only"
        fortindr_error_action: "log-only"
        fortindr_timeout_action: "log-only"
        fortisandbox_error_action: "log-only"
        fortisandbox_max_upload: "56"
        fortisandbox_mode: "inline"
        fortisandbox_timeout_action: "log-only"
        ftgd_analytics: "disable"
        ftp:
            archive_block: "encrypted"
            archive_log: "encrypted"
            av_scan: "disable"
            emulator: "enable"
            external_blocklist: "disable"
            fortiai: "disable"
            fortindr: "disable"
            fortisandbox: "disable"
            options: "scan"
            outbreak_prevention: "disable"
            quarantine: "disable"
        http:
            archive_block: "encrypted"
            archive_log: "encrypted"
            av_scan: "disable"
            content_disarm: "disable"
            emulator: "enable"
            external_blocklist: "disable"
            fortiai: "disable"
            fortindr: "disable"
            fortisandbox: "disable"
            options: "scan"
            outbreak_prevention: "disable"
            quarantine: "disable"
        imap:
            archive_block: "encrypted"
            archive_log: "encrypted"
            av_scan: "disable"
            content_disarm: "disable"
            emulator: "enable"
            executables: "default"
            external_blocklist: "disable"
            fortiai: "disable"
            fortindr: "disable"
            fortisandbox: "disable"
            options: "scan"
            outbreak_prevention: "disable"
            quarantine: "disable"
        inspection_mode: "proxy"
        mapi:
            archive_block: "encrypted"
            archive_log: "encrypted"
            av_scan: "disable"
            emulator: "enable"
            executables: "default"
            external_blocklist: "disable"
            fortiai: "disable"
            fortindr: "disable"
            fortisandbox: "disable"
            options: "scan"
            outbreak_prevention: "disable"
            quarantine: "disable"
        mobile_malware_db: "disable"
        nac_quar:
            expiry: "<your_own_value>"
            infected: "none"
            log: "enable"
        name: "default_name_118"
        nntp:
            archive_block: "encrypted"
            archive_log: "encrypted"
            av_scan: "disable"
            emulator: "enable"
            external_blocklist: "disable"
            fortiai: "disable"
            fortindr: "disable"
            fortisandbox: "disable"
            options: "scan"
            outbreak_prevention: "disable"
            quarantine: "disable"
        outbreak_prevention:
            external_blocklist: "disable"
            ftgd_service: "disable"
        outbreak_prevention_archive_scan: "disable"
        pop3:
            archive_block: "encrypted"
            archive_log: "encrypted"
            av_scan: "disable"
            content_disarm: "disable"
            emulator: "enable"
            executables: "default"
            external_blocklist: "disable"
            fortiai: "disable"
            fortindr: "disable"
            fortisandbox: "disable"
            options: "scan"
            outbreak_prevention: "disable"
            quarantine: "disable"
        replacemsg_group: "<your_own_value> (source system.replacemsg-group.name)"
        scan_mode: "default"
        smb:
            archive_block: "encrypted"
            archive_log: "encrypted"
            emulator: "enable"
            options: "scan"
            outbreak_prevention: "disabled"
        smtp:
            archive_block: "encrypted"
            archive_log: "encrypted"
            av_scan: "disable"
            content_disarm: "disable"
            emulator: "enable"
            executables: "default"
            external_blocklist: "disable"
            fortiai: "disable"
            fortindr: "disable"
            fortisandbox: "disable"
            options: "scan"
            outbreak_prevention: "disable"
            quarantine: "disable"
        ssh:
            archive_block: "encrypted"
            archive_log: "encrypted"
            av_scan: "disable"
            emulator: "enable"
            external_blocklist: "disable"
            fortiai: "disable"
            fortindr: "disable"
            fortisandbox: "disable"
            options: "scan"
            outbreak_prevention: "disable"
            quarantine: "disable"

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
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.secret_field import (
    is_secret_field,
)


def filter_antivirus_profile_data(json):
    option_list = [
        "analytics_accept_filetype",
        "analytics_bl_filetype",
        "analytics_db",
        "analytics_ignore_filetype",
        "analytics_max_upload",
        "analytics_wl_filetype",
        "av_block_log",
        "av_virus_log",
        "cifs",
        "comment",
        "content_disarm",
        "ems_threat_feed",
        "extended_log",
        "external_blocklist",
        "external_blocklist_archive_scan",
        "external_blocklist_enable_all",
        "feature_set",
        "fortiai_error_action",
        "fortiai_timeout_action",
        "fortindr_error_action",
        "fortindr_timeout_action",
        "fortisandbox_error_action",
        "fortisandbox_max_upload",
        "fortisandbox_mode",
        "fortisandbox_timeout_action",
        "ftgd_analytics",
        "ftp",
        "http",
        "imap",
        "inspection_mode",
        "mapi",
        "mobile_malware_db",
        "nac_quar",
        "name",
        "nntp",
        "outbreak_prevention",
        "outbreak_prevention_archive_scan",
        "pop3",
        "replacemsg_group",
        "scan_mode",
        "smb",
        "smtp",
        "ssh",
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
        ["smtp", "archive_block"],
        ["smtp", "archive_log"],
        ["smtp", "options"],
        ["ftp", "archive_block"],
        ["ftp", "archive_log"],
        ["ftp", "options"],
        ["mapi", "archive_block"],
        ["mapi", "archive_log"],
        ["mapi", "options"],
        ["imap", "archive_block"],
        ["imap", "archive_log"],
        ["imap", "options"],
        ["nntp", "archive_block"],
        ["nntp", "archive_log"],
        ["nntp", "options"],
        ["http", "archive_block"],
        ["http", "archive_log"],
        ["http", "options"],
        ["cifs", "archive_block"],
        ["cifs", "archive_log"],
        ["cifs", "options"],
        ["ssh", "archive_block"],
        ["ssh", "archive_log"],
        ["ssh", "options"],
        ["pop3", "archive_block"],
        ["pop3", "archive_log"],
        ["pop3", "options"],
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


def antivirus_profile(data, fos):
    vdom = data["vdom"]

    state = data["state"]

    antivirus_profile_data = data["antivirus_profile"]
    antivirus_profile_data = flatten_multilists_attributes(antivirus_profile_data)
    filtered_data = underscore_to_hyphen(
        filter_antivirus_profile_data(antivirus_profile_data)
    )

    if state == "present" or state is True:
        return fos.set("antivirus", "profile", data=filtered_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("antivirus", "profile", mkey=filtered_data["name"], vdom=vdom)
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


def fortios_antivirus(data, fos):

    fos.do_member_operation("antivirus", "profile")
    if data["antivirus_profile"]:
        resp = antivirus_profile(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("antivirus_profile"))

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
        "comment": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "feature_set": {
            "type": "string",
            "options": [
                {
                    "value": "flow",
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
                },
                {
                    "value": "proxy",
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
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "fortiai_timeout_action": {
            "type": "string",
            "options": [
                {
                    "value": "log-only",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                    },
                },
                {
                    "value": "block",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                    },
                },
                {
                    "value": "ignore",
                    "revisions": {
                        "v7.0.3": True,
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
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "fortiai_error_action": {
            "type": "string",
            "options": [
                {
                    "value": "log-only",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                    },
                },
                {
                    "value": "block",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                    },
                },
                {
                    "value": "ignore",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                    },
                },
            ],
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": False,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": False,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "smtp": {
            "type": "dict",
            "children": {
                "executables": {
                    "type": "string",
                    "options": [
                        {
                            "value": "default",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "virus",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "fortisandbox": {
                    "type": "string",
                    "options": [
                        {"value": "disable", "revisions": {"v7.2.0": True}},
                        {"value": "block", "revisions": {"v7.2.0": True}},
                        {"value": "monitor", "revisions": {"v7.2.0": True}},
                    ],
                    "revisions": {
                        "v7.0.3": False,
                        "v7.0.2": False,
                        "v7.0.1": False,
                        "v7.0.0": False,
                        "v7.0.5": False,
                        "v7.0.4": False,
                        "v6.4.4": False,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "av_scan": {
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
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "block",
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
                            "value": "monitor",
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
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "external_blocklist": {
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
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "block",
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
                            "value": "monitor",
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
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "quarantine": {
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
                                "v7.2.0": True,
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
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "content_disarm": {
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "emulator": {
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "fortindr": {
                    "type": "string",
                    "options": [
                        {"value": "disable", "revisions": {"v7.2.0": True}},
                        {"value": "block", "revisions": {"v7.2.0": True}},
                        {"value": "monitor", "revisions": {"v7.2.0": True}},
                    ],
                    "revisions": {
                        "v7.0.3": False,
                        "v7.0.2": False,
                        "v7.0.1": False,
                        "v7.0.0": False,
                        "v7.0.5": False,
                        "v7.0.4": False,
                        "v6.4.4": False,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "archive_block": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "options": [
                        {
                            "value": "encrypted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "corrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "partiallycorrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "multipart",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "nested",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "mailbomb",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "timeout",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "unhandled",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "fileslimit",
                            "revisions": {
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "archive_log": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "options": [
                        {
                            "value": "encrypted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "corrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "partiallycorrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "multipart",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "nested",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "mailbomb",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "timeout",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "unhandled",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "fileslimit",
                            "revisions": {
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "outbreak_prevention": {
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
                                "v6.4.4": False,
                                "v6.0.5": False,
                                "v6.0.0": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": False,
                                "v7.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": False,
                                "v6.2.7": False,
                                "v6.0.11": False,
                            },
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": False,
                                "v6.0.5": False,
                                "v6.0.0": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": False,
                                "v7.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": False,
                                "v6.2.7": False,
                                "v6.0.11": False,
                            },
                        },
                        {
                            "value": "monitor",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": False,
                                "v6.0.5": False,
                                "v6.0.0": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": False,
                                "v7.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": False,
                                "v6.2.7": False,
                                "v6.0.11": False,
                            },
                        },
                        {
                            "value": "disabled",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "files",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "full-archive",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "options": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "options": [
                        {
                            "value": "scan",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "avmonitor",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "quarantine",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "fortiai": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                        {
                            "value": "monitor",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                    ],
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": False,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": False,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
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
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "analytics_db": {
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
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
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "analytics_ignore_filetype": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": False,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "av_virus_log": {
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
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
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "external_blocklist_archive_scan": {
            "type": "string",
            "options": [
                {"value": "disable", "revisions": {"v7.0.0": True}},
                {"value": "enable", "revisions": {"v7.0.0": True}},
            ],
            "revisions": {
                "v6.0.0": False,
                "v7.0.0": True,
                "v6.0.5": False,
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "fortindr_timeout_action": {
            "type": "string",
            "options": [
                {"value": "log-only", "revisions": {"v7.2.0": True}},
                {"value": "block", "revisions": {"v7.2.0": True}},
                {"value": "ignore", "revisions": {"v7.2.0": True}},
            ],
            "revisions": {
                "v7.0.3": False,
                "v7.0.2": False,
                "v7.0.1": False,
                "v7.0.0": False,
                "v7.0.5": False,
                "v7.0.4": False,
                "v6.4.4": False,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "replacemsg_group": {
            "type": "string",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "outbreak_prevention_archive_scan": {
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
                        "v7.2.0": True,
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
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "analytics_bl_filetype": {
            "type": "integer",
            "revisions": {
                "v6.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "analytics_accept_filetype": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": False,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "ftp": {
            "type": "dict",
            "children": {
                "fortisandbox": {
                    "type": "string",
                    "options": [
                        {"value": "disable", "revisions": {"v7.2.0": True}},
                        {"value": "block", "revisions": {"v7.2.0": True}},
                        {"value": "monitor", "revisions": {"v7.2.0": True}},
                    ],
                    "revisions": {
                        "v7.0.3": False,
                        "v7.0.2": False,
                        "v7.0.1": False,
                        "v7.0.0": False,
                        "v7.0.5": False,
                        "v7.0.4": False,
                        "v6.4.4": False,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "av_scan": {
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
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "block",
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
                            "value": "monitor",
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
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "external_blocklist": {
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
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "block",
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
                            "value": "monitor",
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
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "quarantine": {
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
                                "v7.2.0": True,
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
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "emulator": {
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "fortindr": {
                    "type": "string",
                    "options": [
                        {"value": "disable", "revisions": {"v7.2.0": True}},
                        {"value": "block", "revisions": {"v7.2.0": True}},
                        {"value": "monitor", "revisions": {"v7.2.0": True}},
                    ],
                    "revisions": {
                        "v7.0.3": False,
                        "v7.0.2": False,
                        "v7.0.1": False,
                        "v7.0.0": False,
                        "v7.0.5": False,
                        "v7.0.4": False,
                        "v6.4.4": False,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "archive_block": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "options": [
                        {
                            "value": "encrypted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "corrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "partiallycorrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "multipart",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "nested",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "mailbomb",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "timeout",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "unhandled",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "fileslimit",
                            "revisions": {
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "archive_log": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "options": [
                        {
                            "value": "encrypted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "corrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "partiallycorrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "multipart",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "nested",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "mailbomb",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "timeout",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "unhandled",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "fileslimit",
                            "revisions": {
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "outbreak_prevention": {
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
                                "v6.4.4": False,
                                "v6.0.5": False,
                                "v6.0.0": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": False,
                                "v7.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": False,
                                "v6.2.7": False,
                                "v6.0.11": False,
                            },
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": False,
                                "v6.0.5": False,
                                "v6.0.0": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": False,
                                "v7.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": False,
                                "v6.2.7": False,
                                "v6.0.11": False,
                            },
                        },
                        {
                            "value": "monitor",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": False,
                                "v6.0.5": False,
                                "v6.0.0": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": False,
                                "v7.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": False,
                                "v6.2.7": False,
                                "v6.0.11": False,
                            },
                        },
                        {
                            "value": "disabled",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "files",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "full-archive",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "options": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "options": [
                        {
                            "value": "scan",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "avmonitor",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "quarantine",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "fortiai": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                        {
                            "value": "monitor",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                    ],
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": False,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": False,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
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
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "analytics_max_upload": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "mapi": {
            "type": "dict",
            "children": {
                "executables": {
                    "type": "string",
                    "options": [
                        {
                            "value": "default",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "virus",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "fortisandbox": {
                    "type": "string",
                    "options": [
                        {"value": "disable", "revisions": {"v7.2.0": True}},
                        {"value": "block", "revisions": {"v7.2.0": True}},
                        {"value": "monitor", "revisions": {"v7.2.0": True}},
                    ],
                    "revisions": {
                        "v7.0.3": False,
                        "v7.0.2": False,
                        "v7.0.1": False,
                        "v7.0.0": False,
                        "v7.0.5": False,
                        "v7.0.4": False,
                        "v6.4.4": False,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "av_scan": {
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
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "block",
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
                            "value": "monitor",
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
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "external_blocklist": {
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
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "block",
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
                            "value": "monitor",
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
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "quarantine": {
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
                                "v7.2.0": True,
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
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "emulator": {
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "fortindr": {
                    "type": "string",
                    "options": [
                        {"value": "disable", "revisions": {"v7.2.0": True}},
                        {"value": "block", "revisions": {"v7.2.0": True}},
                        {"value": "monitor", "revisions": {"v7.2.0": True}},
                    ],
                    "revisions": {
                        "v7.0.3": False,
                        "v7.0.2": False,
                        "v7.0.1": False,
                        "v7.0.0": False,
                        "v7.0.5": False,
                        "v7.0.4": False,
                        "v6.4.4": False,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "archive_block": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "options": [
                        {
                            "value": "encrypted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "corrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "partiallycorrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "multipart",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "nested",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "mailbomb",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "timeout",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "unhandled",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "fileslimit",
                            "revisions": {
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "archive_log": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "options": [
                        {
                            "value": "encrypted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "corrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "partiallycorrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "multipart",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "nested",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "mailbomb",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "timeout",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "unhandled",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "fileslimit",
                            "revisions": {
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "outbreak_prevention": {
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
                                "v6.4.4": False,
                                "v6.0.5": False,
                                "v6.0.0": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": False,
                                "v7.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": False,
                                "v6.2.7": False,
                                "v6.0.11": False,
                            },
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": False,
                                "v6.0.5": False,
                                "v6.0.0": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": False,
                                "v7.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": False,
                                "v6.2.7": False,
                                "v6.0.11": False,
                            },
                        },
                        {
                            "value": "monitor",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": False,
                                "v6.0.5": False,
                                "v6.0.0": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": False,
                                "v7.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": False,
                                "v6.2.7": False,
                                "v6.0.11": False,
                            },
                        },
                        {
                            "value": "disabled",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "files",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "full-archive",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "options": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "options": [
                        {
                            "value": "scan",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "avmonitor",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "quarantine",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "fortiai": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                        {
                            "value": "monitor",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                    ],
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": False,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": False,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
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
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "extended_log": {
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
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
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "imap": {
            "type": "dict",
            "children": {
                "executables": {
                    "type": "string",
                    "options": [
                        {
                            "value": "default",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "virus",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "fortisandbox": {
                    "type": "string",
                    "options": [
                        {"value": "disable", "revisions": {"v7.2.0": True}},
                        {"value": "block", "revisions": {"v7.2.0": True}},
                        {"value": "monitor", "revisions": {"v7.2.0": True}},
                    ],
                    "revisions": {
                        "v7.0.3": False,
                        "v7.0.2": False,
                        "v7.0.1": False,
                        "v7.0.0": False,
                        "v7.0.5": False,
                        "v7.0.4": False,
                        "v6.4.4": False,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "av_scan": {
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
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "block",
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
                            "value": "monitor",
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
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "external_blocklist": {
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
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "block",
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
                            "value": "monitor",
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
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "quarantine": {
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
                                "v7.2.0": True,
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
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "content_disarm": {
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "emulator": {
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "fortindr": {
                    "type": "string",
                    "options": [
                        {"value": "disable", "revisions": {"v7.2.0": True}},
                        {"value": "block", "revisions": {"v7.2.0": True}},
                        {"value": "monitor", "revisions": {"v7.2.0": True}},
                    ],
                    "revisions": {
                        "v7.0.3": False,
                        "v7.0.2": False,
                        "v7.0.1": False,
                        "v7.0.0": False,
                        "v7.0.5": False,
                        "v7.0.4": False,
                        "v6.4.4": False,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "archive_block": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "options": [
                        {
                            "value": "encrypted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "corrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "partiallycorrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "multipart",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "nested",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "mailbomb",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "timeout",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "unhandled",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "fileslimit",
                            "revisions": {
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "archive_log": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "options": [
                        {
                            "value": "encrypted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "corrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "partiallycorrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "multipart",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "nested",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "mailbomb",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "timeout",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "unhandled",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "fileslimit",
                            "revisions": {
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "outbreak_prevention": {
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
                                "v6.4.4": False,
                                "v6.0.5": False,
                                "v6.0.0": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": False,
                                "v7.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": False,
                                "v6.2.7": False,
                                "v6.0.11": False,
                            },
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": False,
                                "v6.0.5": False,
                                "v6.0.0": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": False,
                                "v7.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": False,
                                "v6.2.7": False,
                                "v6.0.11": False,
                            },
                        },
                        {
                            "value": "monitor",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": False,
                                "v6.0.5": False,
                                "v6.0.0": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": False,
                                "v7.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": False,
                                "v6.2.7": False,
                                "v6.0.11": False,
                            },
                        },
                        {
                            "value": "disabled",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "files",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "full-archive",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "options": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "options": [
                        {
                            "value": "scan",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "avmonitor",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "quarantine",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "fortiai": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                        {
                            "value": "monitor",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                    ],
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": False,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": False,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
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
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "fortisandbox_timeout_action": {
            "type": "string",
            "options": [
                {"value": "log-only", "revisions": {"v7.2.0": True}},
                {"value": "block", "revisions": {"v7.2.0": True}},
                {"value": "ignore", "revisions": {"v7.2.0": True}},
            ],
            "revisions": {
                "v7.0.3": False,
                "v7.0.2": False,
                "v7.0.1": False,
                "v7.0.0": False,
                "v7.0.5": False,
                "v7.0.4": False,
                "v6.4.4": False,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "content_disarm": {
            "type": "dict",
            "children": {
                "office_action": {
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
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": False,
                    },
                },
                "pdf_act_launch": {
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "office_dde": {
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
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": False,
                    },
                },
                "office_hylink": {
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "pdf_embedfile": {
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "office_macro": {
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "cover_page": {
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "office_linked": {
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "pdf_javacode": {
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "pdf_hyperlink": {
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "detect_only": {
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "pdf_act_gotor": {
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "pdf_act_form": {
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "original_file_destination": {
                    "type": "string",
                    "options": [
                        {
                            "value": "fortisandbox",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "quarantine",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "discard",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "office_embed": {
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "pdf_act_sound": {
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "pdf_act_java": {
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "pdf_act_movie": {
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "error_action": {
                    "type": "string",
                    "options": [
                        {
                            "value": "block",
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
                            "value": "log-only",
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
                            "value": "ignore",
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
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": True,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
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
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "nntp": {
            "type": "dict",
            "children": {
                "fortisandbox": {
                    "type": "string",
                    "options": [
                        {"value": "disable", "revisions": {"v7.2.0": True}},
                        {"value": "block", "revisions": {"v7.2.0": True}},
                        {"value": "monitor", "revisions": {"v7.2.0": True}},
                    ],
                    "revisions": {
                        "v7.0.3": False,
                        "v7.0.2": False,
                        "v7.0.1": False,
                        "v7.0.0": False,
                        "v7.0.5": False,
                        "v7.0.4": False,
                        "v6.4.4": False,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "av_scan": {
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
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "block",
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
                            "value": "monitor",
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
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "external_blocklist": {
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
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "block",
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
                            "value": "monitor",
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
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "quarantine": {
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
                                "v7.2.0": True,
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
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "emulator": {
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "fortindr": {
                    "type": "string",
                    "options": [
                        {"value": "disable", "revisions": {"v7.2.0": True}},
                        {"value": "block", "revisions": {"v7.2.0": True}},
                        {"value": "monitor", "revisions": {"v7.2.0": True}},
                    ],
                    "revisions": {
                        "v7.0.3": False,
                        "v7.0.2": False,
                        "v7.0.1": False,
                        "v7.0.0": False,
                        "v7.0.5": False,
                        "v7.0.4": False,
                        "v6.4.4": False,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "archive_block": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "options": [
                        {
                            "value": "encrypted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "corrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "partiallycorrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "multipart",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "nested",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "mailbomb",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "timeout",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "unhandled",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "fileslimit",
                            "revisions": {
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "archive_log": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "options": [
                        {
                            "value": "encrypted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "corrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "partiallycorrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "multipart",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "nested",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "mailbomb",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "timeout",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "unhandled",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "fileslimit",
                            "revisions": {
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "outbreak_prevention": {
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
                                "v6.4.4": False,
                                "v6.0.5": False,
                                "v6.0.0": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": False,
                                "v7.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": False,
                                "v6.2.7": False,
                                "v6.0.11": False,
                            },
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": False,
                                "v6.0.5": False,
                                "v6.0.0": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": False,
                                "v7.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": False,
                                "v6.2.7": False,
                                "v6.0.11": False,
                            },
                        },
                        {
                            "value": "monitor",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": False,
                                "v6.0.5": False,
                                "v6.0.0": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": False,
                                "v7.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": False,
                                "v6.2.7": False,
                                "v6.0.11": False,
                            },
                        },
                        {
                            "value": "disabled",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "files",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "full-archive",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "options": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "options": [
                        {
                            "value": "scan",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "avmonitor",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "quarantine",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "fortiai": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                        {
                            "value": "monitor",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                    ],
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": False,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": False,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
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
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "smb": {
            "type": "dict",
            "children": {
                "archive_block": {
                    "type": "string",
                    "options": [
                        {
                            "value": "encrypted",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "corrupted",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "partiallycorrupted",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "multipart",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "nested",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "mailbomb",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "fileslimit",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "timeout",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "unhandled",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "archive_log": {
                    "type": "string",
                    "options": [
                        {
                            "value": "encrypted",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "corrupted",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "partiallycorrupted",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "multipart",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "nested",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "mailbomb",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "fileslimit",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "timeout",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "unhandled",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "outbreak_prevention": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disabled",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "files",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "full-archive",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "options": {
                    "type": "string",
                    "options": [
                        {
                            "value": "scan",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "avmonitor",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                        {
                            "value": "quarantine",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True,
                            },
                        },
                    ],
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                "emulator": {
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
            },
            "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
        },
        "analytics_wl_filetype": {
            "type": "integer",
            "revisions": {
                "v6.0.0": True,
                "v6.0.5": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "http": {
            "type": "dict",
            "children": {
                "fortisandbox": {
                    "type": "string",
                    "options": [
                        {"value": "disable", "revisions": {"v7.2.0": True}},
                        {"value": "block", "revisions": {"v7.2.0": True}},
                        {"value": "monitor", "revisions": {"v7.2.0": True}},
                    ],
                    "revisions": {
                        "v7.0.3": False,
                        "v7.0.2": False,
                        "v7.0.1": False,
                        "v7.0.0": False,
                        "v7.0.5": False,
                        "v7.0.4": False,
                        "v6.4.4": False,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "av_scan": {
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
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "block",
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
                            "value": "monitor",
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
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "external_blocklist": {
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
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "block",
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
                            "value": "monitor",
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
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "quarantine": {
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
                                "v7.2.0": True,
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
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "content_disarm": {
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "emulator": {
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "fortindr": {
                    "type": "string",
                    "options": [
                        {"value": "disable", "revisions": {"v7.2.0": True}},
                        {"value": "block", "revisions": {"v7.2.0": True}},
                        {"value": "monitor", "revisions": {"v7.2.0": True}},
                    ],
                    "revisions": {
                        "v7.0.3": False,
                        "v7.0.2": False,
                        "v7.0.1": False,
                        "v7.0.0": False,
                        "v7.0.5": False,
                        "v7.0.4": False,
                        "v6.4.4": False,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "archive_block": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "options": [
                        {
                            "value": "encrypted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "corrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "partiallycorrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "multipart",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "nested",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "mailbomb",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "timeout",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "unhandled",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "fileslimit",
                            "revisions": {
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "archive_log": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "options": [
                        {
                            "value": "encrypted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "corrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "partiallycorrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "multipart",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "nested",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "mailbomb",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "timeout",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "unhandled",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "fileslimit",
                            "revisions": {
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "outbreak_prevention": {
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
                                "v6.4.4": False,
                                "v6.0.5": False,
                                "v6.0.0": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": False,
                                "v7.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": False,
                                "v6.2.7": False,
                                "v6.0.11": False,
                            },
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": False,
                                "v6.0.5": False,
                                "v6.0.0": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": False,
                                "v7.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": False,
                                "v6.2.7": False,
                                "v6.0.11": False,
                            },
                        },
                        {
                            "value": "monitor",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": False,
                                "v6.0.5": False,
                                "v6.0.0": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": False,
                                "v7.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": False,
                                "v6.2.7": False,
                                "v6.0.11": False,
                            },
                        },
                        {
                            "value": "disabled",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "files",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "full-archive",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "options": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "options": [
                        {
                            "value": "scan",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "avmonitor",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "quarantine",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "fortiai": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                        {
                            "value": "monitor",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                    ],
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": False,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": False,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
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
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "cifs": {
            "type": "dict",
            "children": {
                "fortisandbox": {
                    "type": "string",
                    "options": [
                        {"value": "disable", "revisions": {"v7.2.0": True}},
                        {"value": "block", "revisions": {"v7.2.0": True}},
                        {"value": "monitor", "revisions": {"v7.2.0": True}},
                    ],
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
                "av_scan": {
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
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "block",
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
                            "value": "monitor",
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
                "external_blocklist": {
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
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "block",
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
                            "value": "monitor",
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
                "quarantine": {
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
                                "v7.2.0": True,
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
                "emulator": {
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
                "fortindr": {
                    "type": "string",
                    "options": [
                        {"value": "disable", "revisions": {"v7.2.0": True}},
                        {"value": "block", "revisions": {"v7.2.0": True}},
                        {"value": "monitor", "revisions": {"v7.2.0": True}},
                    ],
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
                "archive_block": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "options": [
                        {
                            "value": "encrypted",
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
                            "value": "corrupted",
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
                            "value": "partiallycorrupted",
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
                            "value": "multipart",
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
                            "value": "nested",
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
                            "value": "mailbomb",
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
                            "value": "timeout",
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
                            "value": "unhandled",
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
                            "value": "fileslimit",
                            "revisions": {
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
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
                "archive_log": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "options": [
                        {
                            "value": "encrypted",
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
                            "value": "corrupted",
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
                            "value": "partiallycorrupted",
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
                            "value": "multipart",
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
                            "value": "nested",
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
                            "value": "mailbomb",
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
                            "value": "timeout",
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
                            "value": "unhandled",
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
                            "value": "fileslimit",
                            "revisions": {
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
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
                "outbreak_prevention": {
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
                        {
                            "value": "block",
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
                        {
                            "value": "monitor",
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
                        {
                            "value": "disabled",
                            "revisions": {
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                            },
                        },
                        {
                            "value": "files",
                            "revisions": {
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                            },
                        },
                        {
                            "value": "full-archive",
                            "revisions": {
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
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
                "options": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "options": [
                        {
                            "value": "scan",
                            "revisions": {
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                            },
                        },
                        {
                            "value": "avmonitor",
                            "revisions": {
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                            },
                        },
                        {
                            "value": "quarantine",
                            "revisions": {
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                            },
                        },
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                },
                "fortiai": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                        {
                            "value": "monitor",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                    ],
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
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
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
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": False,
            },
        },
        "fortisandbox_error_action": {
            "type": "string",
            "options": [
                {"value": "log-only", "revisions": {"v7.2.0": True}},
                {"value": "block", "revisions": {"v7.2.0": True}},
                {"value": "ignore", "revisions": {"v7.2.0": True}},
            ],
            "revisions": {
                "v7.0.3": False,
                "v7.0.2": False,
                "v7.0.1": False,
                "v7.0.0": False,
                "v7.0.5": False,
                "v7.0.4": False,
                "v6.4.4": False,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "nac_quar": {
            "type": "dict",
            "children": {
                "infected": {
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "quar-src-ip",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "log": {
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "expiry": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
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
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "ems_threat_feed": {
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
                        "v7.2.0": True,
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
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "ssh": {
            "type": "dict",
            "children": {
                "fortisandbox": {
                    "type": "string",
                    "options": [
                        {"value": "disable", "revisions": {"v7.2.0": True}},
                        {"value": "block", "revisions": {"v7.2.0": True}},
                        {"value": "monitor", "revisions": {"v7.2.0": True}},
                    ],
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
                "av_scan": {
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
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "block",
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
                            "value": "monitor",
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
                "external_blocklist": {
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
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "block",
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
                            "value": "monitor",
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
                "quarantine": {
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
                                "v7.2.0": True,
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
                "emulator": {
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
                "fortindr": {
                    "type": "string",
                    "options": [
                        {"value": "disable", "revisions": {"v7.2.0": True}},
                        {"value": "block", "revisions": {"v7.2.0": True}},
                        {"value": "monitor", "revisions": {"v7.2.0": True}},
                    ],
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
                "archive_block": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "options": [
                        {
                            "value": "encrypted",
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
                            "value": "corrupted",
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
                            "value": "partiallycorrupted",
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
                            "value": "multipart",
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
                            "value": "nested",
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
                            "value": "mailbomb",
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
                            "value": "timeout",
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
                            "value": "unhandled",
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
                            "value": "fileslimit",
                            "revisions": {
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
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
                "archive_log": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "options": [
                        {
                            "value": "encrypted",
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
                            "value": "corrupted",
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
                            "value": "partiallycorrupted",
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
                            "value": "multipart",
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
                            "value": "nested",
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
                            "value": "mailbomb",
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
                            "value": "timeout",
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
                            "value": "unhandled",
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
                            "value": "fileslimit",
                            "revisions": {
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
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
                "outbreak_prevention": {
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
                        {
                            "value": "block",
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
                        {
                            "value": "monitor",
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
                        {
                            "value": "disabled",
                            "revisions": {
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                            },
                        },
                        {
                            "value": "files",
                            "revisions": {
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                            },
                        },
                        {
                            "value": "full-archive",
                            "revisions": {
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
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
                "options": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "options": [
                        {
                            "value": "scan",
                            "revisions": {
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                            },
                        },
                        {
                            "value": "avmonitor",
                            "revisions": {
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                            },
                        },
                        {
                            "value": "quarantine",
                            "revisions": {
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                            },
                        },
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                },
                "fortiai": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                        {
                            "value": "monitor",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                    ],
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
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
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
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": False,
            },
        },
        "fortisandbox_mode": {
            "type": "string",
            "options": [
                {"value": "inline", "revisions": {"v7.2.0": True}},
                {"value": "analytics-suspicious", "revisions": {"v7.2.0": True}},
                {"value": "analytics-everything", "revisions": {"v7.2.0": True}},
            ],
            "revisions": {
                "v7.0.3": False,
                "v7.0.2": False,
                "v7.0.1": False,
                "v7.0.0": False,
                "v7.0.5": False,
                "v7.0.4": False,
                "v6.4.4": False,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "av_block_log": {
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
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
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "fortisandbox_max_upload": {
            "type": "integer",
            "revisions": {
                "v7.0.3": False,
                "v7.0.2": False,
                "v7.0.1": False,
                "v7.0.0": False,
                "v7.0.5": False,
                "v7.0.4": False,
                "v6.4.4": False,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
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
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "pop3": {
            "type": "dict",
            "children": {
                "executables": {
                    "type": "string",
                    "options": [
                        {
                            "value": "default",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "virus",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "fortisandbox": {
                    "type": "string",
                    "options": [
                        {"value": "disable", "revisions": {"v7.2.0": True}},
                        {"value": "block", "revisions": {"v7.2.0": True}},
                        {"value": "monitor", "revisions": {"v7.2.0": True}},
                    ],
                    "revisions": {
                        "v7.0.3": False,
                        "v7.0.2": False,
                        "v7.0.1": False,
                        "v7.0.0": False,
                        "v7.0.5": False,
                        "v7.0.4": False,
                        "v6.4.4": False,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "av_scan": {
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
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "block",
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
                            "value": "monitor",
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
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "external_blocklist": {
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
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "block",
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
                            "value": "monitor",
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
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "quarantine": {
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
                                "v7.2.0": True,
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
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "content_disarm": {
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "emulator": {
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "fortindr": {
                    "type": "string",
                    "options": [
                        {"value": "disable", "revisions": {"v7.2.0": True}},
                        {"value": "block", "revisions": {"v7.2.0": True}},
                        {"value": "monitor", "revisions": {"v7.2.0": True}},
                    ],
                    "revisions": {
                        "v7.0.3": False,
                        "v7.0.2": False,
                        "v7.0.1": False,
                        "v7.0.0": False,
                        "v7.0.5": False,
                        "v7.0.4": False,
                        "v6.4.4": False,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v7.2.0": True,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
                    },
                },
                "archive_block": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "options": [
                        {
                            "value": "encrypted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "corrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "partiallycorrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "multipart",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "nested",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "mailbomb",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "timeout",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "unhandled",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "fileslimit",
                            "revisions": {
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "archive_log": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "options": [
                        {
                            "value": "encrypted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "corrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "partiallycorrupted",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "multipart",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "nested",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "mailbomb",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "timeout",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "unhandled",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.0.5": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v7.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "fileslimit",
                            "revisions": {
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "outbreak_prevention": {
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
                                "v6.4.4": False,
                                "v6.0.5": False,
                                "v6.0.0": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": False,
                                "v7.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": False,
                                "v6.2.7": False,
                                "v6.0.11": False,
                            },
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": False,
                                "v6.0.5": False,
                                "v6.0.0": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": False,
                                "v7.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": False,
                                "v6.2.7": False,
                                "v6.0.11": False,
                            },
                        },
                        {
                            "value": "monitor",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": False,
                                "v6.0.5": False,
                                "v6.0.0": False,
                                "v6.4.0": False,
                                "v6.4.1": False,
                                "v6.2.0": False,
                                "v7.2.0": True,
                                "v6.2.3": False,
                                "v6.2.5": False,
                                "v6.2.7": False,
                                "v6.0.11": False,
                            },
                        },
                        {
                            "value": "disabled",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "files",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "full-archive",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "options": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
                    "options": [
                        {
                            "value": "scan",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "avmonitor",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                        {
                            "value": "quarantine",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True,
                            },
                        },
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                "fortiai": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                        {
                            "value": "monitor",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                    ],
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": False,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": False,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": False,
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
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "external_blocklist": {
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
                "v6.4.4": False,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "ftgd_analytics": {
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                {
                    "value": "suspicious",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
                    },
                },
                {
                    "value": "everything",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
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
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "scan_mode": {
            "type": "string",
            "options": [
                {
                    "value": "default",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": False,
                    },
                },
                {
                    "value": "legacy",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.0.5": False,
                        "v6.0.0": False,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": False,
                    },
                },
                {
                    "value": "quick",
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                {
                    "value": "full",
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
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
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "mobile_malware_db": {
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
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
                        "v6.0.5": True,
                        "v6.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v7.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True,
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
                "v6.0.5": True,
                "v6.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v7.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True,
            },
        },
        "fortindr_error_action": {
            "type": "string",
            "options": [
                {"value": "log-only", "revisions": {"v7.2.0": True}},
                {"value": "block", "revisions": {"v7.2.0": True}},
                {"value": "ignore", "revisions": {"v7.2.0": True}},
            ],
            "revisions": {
                "v7.0.3": False,
                "v7.0.2": False,
                "v7.0.1": False,
                "v7.0.0": False,
                "v7.0.5": False,
                "v7.0.4": False,
                "v6.4.4": False,
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "external_blocklist_enable_all": {
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
                        "v7.2.0": True,
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
                "v6.0.5": False,
                "v6.0.0": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v6.2.0": False,
                "v7.2.0": True,
                "v6.2.3": False,
                "v6.2.5": False,
                "v6.2.7": False,
                "v6.0.11": False,
            },
        },
        "outbreak_prevention": {
            "type": "dict",
            "children": {
                "external_blocklist": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                            },
                        },
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                            },
                        },
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                },
                "ftgd_service": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                            },
                        },
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                            },
                        },
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                    },
                },
            },
            "revisions": {
                "v6.0.0": False,
                "v6.0.5": False,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": False,
            },
        },
        "inspection_mode": {
            "type": "string",
            "options": [
                {
                    "value": "proxy",
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
                {
                    "value": "flow-based",
                    "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
                },
            ],
            "revisions": {"v6.0.11": True, "v6.0.0": True, "v6.0.5": True},
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
        "v6.0.5": True,
        "v6.0.0": True,
        "v6.4.0": True,
        "v6.4.1": True,
        "v6.2.0": True,
        "v7.2.0": True,
        "v6.2.3": True,
        "v6.2.5": True,
        "v6.2.7": True,
        "v6.0.11": True,
    },
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "name"
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
        "antivirus_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["antivirus_profile"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["antivirus_profile"]["options"][attribute_name]["required"] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=False)
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
            fos, versioned_schema, "antivirus_profile"
        )

        is_error, has_changed, result, diff = fortios_antivirus(module.params, fos)

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
