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
module: fortios_firewall_profile_protocol_options
short_description: Configure protocol options in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and profile_protocol_options category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.4.0
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
    firewall_profile_protocol_options:
        description:
            - Configure protocol options.
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
            cifs:
                description:
                    - Configure CIFS protocol options.
                type: dict
                suboptions:
                    options:
                        description:
                            - One or more options that can be applied to the session.
                        type: str
                        choices:
                            - oversize
                    oversize_limit:
                        description:
                            - Maximum in-memory file size that can be scanned (1 - 383 MB).
                        type: int
                    ports:
                        description:
                            - Ports to scan for content (1 - 65535).
                        type: int
                    scan_bzip2:
                        description:
                            - Enable/disable scanning of BZip2 compressed files.
                        type: str
                        choices:
                            - enable
                            - disable
                    status:
                        description:
                            - Enable/disable the active status of scanning for this protocol.
                        type: str
                        choices:
                            - enable
                            - disable
                    tcp_window_maximum:
                        description:
                            - Maximum dynamic TCP window size .
                        type: int
                    tcp_window_minimum:
                        description:
                            - Minimum dynamic TCP window size .
                        type: int
                    tcp_window_size:
                        description:
                            - Set TCP static window size .
                        type: int
                    tcp_window_type:
                        description:
                            - Specify type of TCP window to use for this protocol.
                        type: str
                        choices:
                            - system
                            - static
                            - dynamic
                    uncompressed_nest_limit:
                        description:
                            - Maximum nested levels of compression that can be uncompressed and scanned (2 - 100).
                        type: int
                    uncompressed_oversize_limit:
                        description:
                            - Maximum in-memory uncompressed file size that can be scanned (0 - 383 MB, 0 = unlimited).
                        type: int
            comment:
                description:
                    - Optional comments.
                type: str
            dns:
                description:
                    - Configure DNS protocol options.
                type: dict
                suboptions:
                    ports:
                        description:
                            - Ports to scan for content (1 - 65535).
                        type: int
                    status:
                        description:
                            - Enable/disable the active status of scanning for this protocol.
                        type: str
                        choices:
                            - enable
                            - disable
            feature_set:
                description:
                    - Flow/proxy feature set.
                type: str
                choices:
                    - flow
                    - proxy
            ftp:
                description:
                    - Configure FTP protocol options.
                type: dict
                suboptions:
                    comfort_amount:
                        description:
                            - Amount of data to send in a transmission for client comforting (1 - 65535 bytes).
                        type: int
                    comfort_interval:
                        description:
                            - Period of time between start, or last transmission, and the next client comfort transmission of data (1 - 900 sec).
                        type: int
                    inspect_all:
                        description:
                            - Enable/disable the inspection of all ports for the protocol.
                        type: str
                        choices:
                            - enable
                            - disable
                    options:
                        description:
                            - One or more options that can be applied to the session.
                        type: str
                        choices:
                            - clientcomfort
                            - oversize
                            - splice
                            - bypass-rest-command
                            - bypass-mode-command
                    oversize_limit:
                        description:
                            - Maximum in-memory file size that can be scanned (1 - 383 MB).
                        type: int
                    ports:
                        description:
                            - Ports to scan for content (1 - 65535).
                        type: int
                    scan_bzip2:
                        description:
                            - Enable/disable scanning of BZip2 compressed files.
                        type: str
                        choices:
                            - enable
                            - disable
                    ssl_offloaded:
                        description:
                            - SSL decryption and encryption performed by an external device.
                        type: str
                        choices:
                            - no
                            - yes
                    status:
                        description:
                            - Enable/disable the active status of scanning for this protocol.
                        type: str
                        choices:
                            - enable
                            - disable
                    uncompressed_nest_limit:
                        description:
                            - Maximum nested levels of compression that can be uncompressed and scanned (2 - 100).
                        type: int
                    uncompressed_oversize_limit:
                        description:
                            - Maximum in-memory uncompressed file size that can be scanned (0 - 383 MB, 0 = unlimited).
                        type: int
            http:
                description:
                    - Configure HTTP protocol options.
                type: dict
                suboptions:
                    block_page_status_code:
                        description:
                            - Code number returned for blocked HTTP pages (non-FortiGuard only) (100 - 599).
                        type: int
                    comfort_amount:
                        description:
                            - Amount of data to send in a transmission for client comforting (1 - 65535 bytes).
                        type: int
                    comfort_interval:
                        description:
                            - Period of time between start, or last transmission, and the next client comfort transmission of data (1 - 900 sec).
                        type: int
                    fortinet_bar:
                        description:
                            - Enable/disable Fortinet bar on HTML content.
                        type: str
                        choices:
                            - enable
                            - disable
                    fortinet_bar_port:
                        description:
                            - Port for use by Fortinet Bar (1 - 65535).
                        type: int
                    inspect_all:
                        description:
                            - Enable/disable the inspection of all ports for the protocol.
                        type: str
                        choices:
                            - enable
                            - disable
                    options:
                        description:
                            - One or more options that can be applied to the session.
                        type: str
                        choices:
                            - clientcomfort
                            - servercomfort
                            - oversize
                            - chunkedbypass
                    oversize_limit:
                        description:
                            - Maximum in-memory file size that can be scanned (1 - 383 MB).
                        type: int
                    ports:
                        description:
                            - Ports to scan for content (1 - 65535).
                        type: int
                    post_lang:
                        description:
                            - ID codes for character sets to be used to convert to UTF-8 for banned words and DLP on HTTP posts (maximum of 5 character sets).
                        type: str
                        choices:
                            - jisx0201
                            - jisx0208
                            - jisx0212
                            - gb2312
                            - ksc5601-ex
                            - euc-jp
                            - sjis
                            - iso2022-jp
                            - iso2022-jp-1
                            - iso2022-jp-2
                            - euc-cn
                            - ces-gbk
                            - hz
                            - ces-big5
                            - euc-kr
                            - iso2022-jp-3
                            - iso8859-1
                            - tis620
                            - cp874
                            - cp1252
                            - cp1251
                    proxy_after_tcp_handshake:
                        description:
                            - Proxy traffic after the TCP 3-way handshake has been established (not before).
                        type: str
                        choices:
                            - enable
                            - disable
                    range_block:
                        description:
                            - Enable/disable blocking of partial downloads.
                        type: str
                        choices:
                            - disable
                            - enable
                    retry_count:
                        description:
                            - Number of attempts to retry HTTP connection (0 - 100).
                        type: int
                    scan_bzip2:
                        description:
                            - Enable/disable scanning of BZip2 compressed files.
                        type: str
                        choices:
                            - enable
                            - disable
                    ssl_offloaded:
                        description:
                            - SSL decryption and encryption performed by an external device.
                        type: str
                        choices:
                            - no
                            - yes
                    status:
                        description:
                            - Enable/disable the active status of scanning for this protocol.
                        type: str
                        choices:
                            - enable
                            - disable
                    stream_based_uncompressed_limit:
                        description:
                            - Maximum stream-based uncompressed data size that will be scanned (MB, 0 = unlimited (default).  Stream-based uncompression used
                               only under certain conditions.).
                        type: int
                    streaming_content_bypass:
                        description:
                            - Enable/disable bypassing of streaming content from buffering.
                        type: str
                        choices:
                            - enable
                            - disable
                    strip_x_forwarded_for:
                        description:
                            - Enable/disable stripping of HTTP X-Forwarded-For header.
                        type: str
                        choices:
                            - disable
                            - enable
                    switching_protocols:
                        description:
                            - Bypass from scanning, or block a connection that attempts to switch protocol.
                        type: str
                        choices:
                            - bypass
                            - block
                    tcp_window_maximum:
                        description:
                            - Maximum dynamic TCP window size .
                        type: int
                    tcp_window_minimum:
                        description:
                            - Minimum dynamic TCP window size .
                        type: int
                    tcp_window_size:
                        description:
                            - Set TCP static window size .
                        type: int
                    tcp_window_type:
                        description:
                            - Specify type of TCP window to use for this protocol.
                        type: str
                        choices:
                            - system
                            - static
                            - dynamic
                    tunnel_non_http:
                        description:
                            - Configure how to process non-HTTP traffic when a profile configured for HTTP traffic accepts a non-HTTP session. Can occur if an
                               application sends non-HTTP traffic using an HTTP destination port.
                        type: str
                        choices:
                            - enable
                            - disable
                    uncompressed_nest_limit:
                        description:
                            - Maximum nested levels of compression that can be uncompressed and scanned (2 - 100).
                        type: int
                    uncompressed_oversize_limit:
                        description:
                            - Maximum in-memory uncompressed file size that can be scanned (0 - 383 MB, 0 = unlimited).
                        type: int
                    unknown_http_version:
                        description:
                            - How to handle HTTP sessions that do not comply with HTTP 0.9, 1.0, or 1.1.
                        type: str
                        choices:
                            - reject
                            - tunnel
                            - best-effort
            imap:
                description:
                    - Configure IMAP protocol options.
                type: dict
                suboptions:
                    inspect_all:
                        description:
                            - Enable/disable the inspection of all ports for the protocol.
                        type: str
                        choices:
                            - enable
                            - disable
                    options:
                        description:
                            - One or more options that can be applied to the session.
                        type: str
                        choices:
                            - fragmail
                            - oversize
                    oversize_limit:
                        description:
                            - Maximum in-memory file size that can be scanned (1 - 383 MB).
                        type: int
                    ports:
                        description:
                            - Ports to scan for content (1 - 65535).
                        type: int
                    proxy_after_tcp_handshake:
                        description:
                            - Proxy traffic after the TCP 3-way handshake has been established (not before).
                        type: str
                        choices:
                            - enable
                            - disable
                    scan_bzip2:
                        description:
                            - Enable/disable scanning of BZip2 compressed files.
                        type: str
                        choices:
                            - enable
                            - disable
                    ssl_offloaded:
                        description:
                            - SSL decryption and encryption performed by an external device.
                        type: str
                        choices:
                            - no
                            - yes
                    status:
                        description:
                            - Enable/disable the active status of scanning for this protocol.
                        type: str
                        choices:
                            - enable
                            - disable
                    uncompressed_nest_limit:
                        description:
                            - Maximum nested levels of compression that can be uncompressed and scanned (2 - 100).
                        type: int
                    uncompressed_oversize_limit:
                        description:
                            - Maximum in-memory uncompressed file size that can be scanned (0 - 383 MB, 0 = unlimited).
                        type: int
            mail_signature:
                description:
                    - Configure Mail signature.
                type: dict
                suboptions:
                    signature:
                        description:
                            - Email signature to be added to outgoing email (if the signature contains spaces, enclose with quotation marks).
                        type: str
                    status:
                        description:
                            - Enable/disable adding an email signature to SMTP email messages as they pass through the FortiGate.
                        type: str
                        choices:
                            - disable
                            - enable
            mapi:
                description:
                    - Configure MAPI protocol options.
                type: dict
                suboptions:
                    options:
                        description:
                            - One or more options that can be applied to the session.
                        type: str
                        choices:
                            - fragmail
                            - oversize
                    oversize_limit:
                        description:
                            - Maximum in-memory file size that can be scanned (1 - 383 MB).
                        type: int
                    ports:
                        description:
                            - Ports to scan for content (1 - 65535).
                        type: int
                    scan_bzip2:
                        description:
                            - Enable/disable scanning of BZip2 compressed files.
                        type: str
                        choices:
                            - enable
                            - disable
                    status:
                        description:
                            - Enable/disable the active status of scanning for this protocol.
                        type: str
                        choices:
                            - enable
                            - disable
                    uncompressed_nest_limit:
                        description:
                            - Maximum nested levels of compression that can be uncompressed and scanned (2 - 100).
                        type: int
                    uncompressed_oversize_limit:
                        description:
                            - Maximum in-memory uncompressed file size that can be scanned (0 - 383 MB, 0 = unlimited).
                        type: int
            name:
                description:
                    - Name.
                required: true
                type: str
            nntp:
                description:
                    - Configure NNTP protocol options.
                type: dict
                suboptions:
                    inspect_all:
                        description:
                            - Enable/disable the inspection of all ports for the protocol.
                        type: str
                        choices:
                            - enable
                            - disable
                    options:
                        description:
                            - One or more options that can be applied to the session.
                        type: str
                        choices:
                            - oversize
                            - splice
                    oversize_limit:
                        description:
                            - Maximum in-memory file size that can be scanned (1 - 383 MB).
                        type: int
                    ports:
                        description:
                            - Ports to scan for content (1 - 65535).
                        type: int
                    proxy_after_tcp_handshake:
                        description:
                            - Proxy traffic after the TCP 3-way handshake has been established (not before).
                        type: str
                        choices:
                            - enable
                            - disable
                    scan_bzip2:
                        description:
                            - Enable/disable scanning of BZip2 compressed files.
                        type: str
                        choices:
                            - enable
                            - disable
                    status:
                        description:
                            - Enable/disable the active status of scanning for this protocol.
                        type: str
                        choices:
                            - enable
                            - disable
                    uncompressed_nest_limit:
                        description:
                            - Maximum nested levels of compression that can be uncompressed and scanned (2 - 100).
                        type: int
                    uncompressed_oversize_limit:
                        description:
                            - Maximum in-memory uncompressed file size that can be scanned (0 - 383 MB, 0 = unlimited).
                        type: int
            oversize_log:
                description:
                    - Enable/disable logging for antivirus oversize file blocking.
                type: str
                choices:
                    - disable
                    - enable
            pop3:
                description:
                    - Configure POP3 protocol options.
                type: dict
                suboptions:
                    inspect_all:
                        description:
                            - Enable/disable the inspection of all ports for the protocol.
                        type: str
                        choices:
                            - enable
                            - disable
                    options:
                        description:
                            - One or more options that can be applied to the session.
                        type: str
                        choices:
                            - fragmail
                            - oversize
                    oversize_limit:
                        description:
                            - Maximum in-memory file size that can be scanned (1 - 383 MB).
                        type: int
                    ports:
                        description:
                            - Ports to scan for content (1 - 65535).
                        type: int
                    proxy_after_tcp_handshake:
                        description:
                            - Proxy traffic after the TCP 3-way handshake has been established (not before).
                        type: str
                        choices:
                            - enable
                            - disable
                    scan_bzip2:
                        description:
                            - Enable/disable scanning of BZip2 compressed files.
                        type: str
                        choices:
                            - enable
                            - disable
                    ssl_offloaded:
                        description:
                            - SSL decryption and encryption performed by an external device.
                        type: str
                        choices:
                            - no
                            - yes
                    status:
                        description:
                            - Enable/disable the active status of scanning for this protocol.
                        type: str
                        choices:
                            - enable
                            - disable
                    uncompressed_nest_limit:
                        description:
                            - Maximum nested levels of compression that can be uncompressed and scanned (2 - 100).
                        type: int
                    uncompressed_oversize_limit:
                        description:
                            - Maximum in-memory uncompressed file size that can be scanned (0 - 383 MB, 0 = unlimited).
                        type: int
            replacemsg_group:
                description:
                    - Name of the replacement message group to be used Source system.replacemsg-group.name.
                type: str
            rpc_over_http:
                description:
                    - Enable/disable inspection of RPC over HTTP.
                type: str
                choices:
                    - enable
                    - disable
            smtp:
                description:
                    - Configure SMTP protocol options.
                type: dict
                suboptions:
                    inspect_all:
                        description:
                            - Enable/disable the inspection of all ports for the protocol.
                        type: str
                        choices:
                            - enable
                            - disable
                    options:
                        description:
                            - One or more options that can be applied to the session.
                        type: str
                        choices:
                            - fragmail
                            - oversize
                            - splice
                    oversize_limit:
                        description:
                            - Maximum in-memory file size that can be scanned (1 - 383 MB).
                        type: int
                    ports:
                        description:
                            - Ports to scan for content (1 - 65535).
                        type: int
                    proxy_after_tcp_handshake:
                        description:
                            - Proxy traffic after the TCP 3-way handshake has been established (not before).
                        type: str
                        choices:
                            - enable
                            - disable
                    scan_bzip2:
                        description:
                            - Enable/disable scanning of BZip2 compressed files.
                        type: str
                        choices:
                            - enable
                            - disable
                    server_busy:
                        description:
                            - Enable/disable SMTP server busy when server not available.
                        type: str
                        choices:
                            - enable
                            - disable
                    ssl_offloaded:
                        description:
                            - SSL decryption and encryption performed by an external device.
                        type: str
                        choices:
                            - no
                            - yes
                    status:
                        description:
                            - Enable/disable the active status of scanning for this protocol.
                        type: str
                        choices:
                            - enable
                            - disable
                    uncompressed_nest_limit:
                        description:
                            - Maximum nested levels of compression that can be uncompressed and scanned (2 - 100).
                        type: int
                    uncompressed_oversize_limit:
                        description:
                            - Maximum in-memory uncompressed file size that can be scanned (0 - 383 MB, 0 = unlimited).
                        type: int
            ssh:
                description:
                    - Configure SFTP and SCP protocol options.
                type: dict
                suboptions:
                    comfort_amount:
                        description:
                            - Amount of data to send in a transmission for client comforting (1 - 65535 bytes).
                        type: int
                    comfort_interval:
                        description:
                            - Period of time between start, or last transmission, and the next client comfort transmission of data (1 - 900 sec).
                        type: int
                    options:
                        description:
                            - One or more options that can be applied to the session.
                        type: str
                        choices:
                            - oversize
                            - clientcomfort
                            - servercomfort
                    oversize_limit:
                        description:
                            - Maximum in-memory file size that can be scanned (1 - 383 MB).
                        type: int
                    scan_bzip2:
                        description:
                            - Enable/disable scanning of BZip2 compressed files.
                        type: str
                        choices:
                            - enable
                            - disable
                    uncompressed_nest_limit:
                        description:
                            - Maximum nested levels of compression that can be uncompressed and scanned (2 - 100).
                        type: int
                    uncompressed_oversize_limit:
                        description:
                            - Maximum in-memory uncompressed file size that can be scanned (0 - 383 MB, 0 = unlimited).
                        type: int
            switching_protocols_log:
                description:
                    - Enable/disable logging for HTTP/HTTPS switching protocols.
                type: str
                choices:
                    - disable
                    - enable
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
  - name: Configure protocol options.
    fortios_firewall_profile_protocol_options:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_profile_protocol_options:
        cifs:
            options: "oversize"
            oversize_limit: "5"
            ports: "6"
            scan_bzip2: "enable"
            status: "enable"
            tcp_window_maximum: "9"
            tcp_window_minimum: "10"
            tcp_window_size: "11"
            tcp_window_type: "system"
            uncompressed_nest_limit: "13"
            uncompressed_oversize_limit: "14"
        comment: "Optional comments."
        dns:
            ports: "17"
            status: "enable"
        feature_set: "flow"
        ftp:
            comfort_amount: "21"
            comfort_interval: "22"
            inspect_all: "enable"
            options: "clientcomfort"
            oversize_limit: "25"
            ports: "26"
            scan_bzip2: "enable"
            ssl_offloaded: "no"
            status: "enable"
            uncompressed_nest_limit: "30"
            uncompressed_oversize_limit: "31"
        http:
            block_page_status_code: "33"
            comfort_amount: "34"
            comfort_interval: "35"
            fortinet_bar: "enable"
            fortinet_bar_port: "37"
            inspect_all: "enable"
            options: "clientcomfort"
            oversize_limit: "40"
            ports: "41"
            post_lang: "jisx0201"
            proxy_after_tcp_handshake: "enable"
            range_block: "disable"
            retry_count: "45"
            scan_bzip2: "enable"
            ssl_offloaded: "no"
            status: "enable"
            stream_based_uncompressed_limit: "49"
            streaming_content_bypass: "enable"
            strip_x_forwarded_for: "disable"
            switching_protocols: "bypass"
            tcp_window_maximum: "53"
            tcp_window_minimum: "54"
            tcp_window_size: "55"
            tcp_window_type: "system"
            tunnel_non_http: "enable"
            uncompressed_nest_limit: "58"
            uncompressed_oversize_limit: "59"
            unknown_http_version: "reject"
        imap:
            inspect_all: "enable"
            options: "fragmail"
            oversize_limit: "64"
            ports: "65"
            proxy_after_tcp_handshake: "enable"
            scan_bzip2: "enable"
            ssl_offloaded: "no"
            status: "enable"
            uncompressed_nest_limit: "70"
            uncompressed_oversize_limit: "71"
        mail_signature:
            signature: "<your_own_value>"
            status: "disable"
        mapi:
            options: "fragmail"
            oversize_limit: "77"
            ports: "78"
            scan_bzip2: "enable"
            status: "enable"
            uncompressed_nest_limit: "81"
            uncompressed_oversize_limit: "82"
        name: "default_name_83"
        nntp:
            inspect_all: "enable"
            options: "oversize"
            oversize_limit: "87"
            ports: "88"
            proxy_after_tcp_handshake: "enable"
            scan_bzip2: "enable"
            status: "enable"
            uncompressed_nest_limit: "92"
            uncompressed_oversize_limit: "93"
        oversize_log: "disable"
        pop3:
            inspect_all: "enable"
            options: "fragmail"
            oversize_limit: "98"
            ports: "99"
            proxy_after_tcp_handshake: "enable"
            scan_bzip2: "enable"
            ssl_offloaded: "no"
            status: "enable"
            uncompressed_nest_limit: "104"
            uncompressed_oversize_limit: "105"
        replacemsg_group: "<your_own_value> (source system.replacemsg-group.name)"
        rpc_over_http: "enable"
        smtp:
            inspect_all: "enable"
            options: "fragmail"
            oversize_limit: "111"
            ports: "112"
            proxy_after_tcp_handshake: "enable"
            scan_bzip2: "enable"
            server_busy: "enable"
            ssl_offloaded: "no"
            status: "enable"
            uncompressed_nest_limit: "118"
            uncompressed_oversize_limit: "119"
        ssh:
            comfort_amount: "121"
            comfort_interval: "122"
            options: "oversize"
            oversize_limit: "124"
            scan_bzip2: "enable"
            uncompressed_nest_limit: "126"
            uncompressed_oversize_limit: "127"
        switching_protocols_log: "disable"

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


def filter_firewall_profile_protocol_options_data(json):
    option_list = ['cifs', 'comment', 'dns',
                   'feature_set', 'ftp', 'http',
                   'imap', 'mail_signature', 'mapi',
                   'name', 'nntp', 'oversize_log',
                   'pop3', 'replacemsg_group', 'rpc_over_http',
                   'smtp', 'ssh', 'switching_protocols_log']
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


def firewall_profile_protocol_options(data, fos):
    vdom = data['vdom']
    if 'state' in data and data['state']:
        state = data['state']
    elif 'state' in data['firewall_profile_protocol_options'] and data['firewall_profile_protocol_options']['state']:
        state = data['firewall_profile_protocol_options']['state']
    else:
        state = True
    firewall_profile_protocol_options_data = data['firewall_profile_protocol_options']
    filtered_data = underscore_to_hyphen(filter_firewall_profile_protocol_options_data(firewall_profile_protocol_options_data))

    if state == "present":
        return fos.set('firewall',
                       'profile-protocol-options',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('firewall',
                          'profile-protocol-options',
                          mkey=filtered_data['name'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_firewall(data, fos):

    if data['firewall_profile_protocol_options']:
        resp = firewall_profile_protocol_options(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('firewall_profile_protocol_options'))

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
        "firewall_profile_protocol_options": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "state": {"required": False, "type": "str",
                          "choices": ["present", "absent"]},
                "cifs": {"required": False, "type": "dict",
                         "options": {
                             "options": {"required": False, "type": "str",
                                         "choices": ["oversize"]},
                             "oversize_limit": {"required": False, "type": "int"},
                             "ports": {"required": False, "type": "int"},
                             "scan_bzip2": {"required": False, "type": "str",
                                            "choices": ["enable",
                                                        "disable"]},
                             "status": {"required": False, "type": "str",
                                        "choices": ["enable",
                                                    "disable"]},
                             "tcp_window_maximum": {"required": False, "type": "int"},
                             "tcp_window_minimum": {"required": False, "type": "int"},
                             "tcp_window_size": {"required": False, "type": "int"},
                             "tcp_window_type": {"required": False, "type": "str",
                                                 "choices": ["system",
                                                             "static",
                                                             "dynamic"]},
                             "uncompressed_nest_limit": {"required": False, "type": "int"},
                             "uncompressed_oversize_limit": {"required": False, "type": "int"}
                         }},
                "comment": {"required": False, "type": "str"},
                "dns": {"required": False, "type": "dict",
                        "options": {
                            "ports": {"required": False, "type": "int"},
                            "status": {"required": False, "type": "str",
                                       "choices": ["enable",
                                                   "disable"]}
                        }},
                "feature_set": {"required": False, "type": "str",
                                "choices": ["flow",
                                            "proxy"]},
                "ftp": {"required": False, "type": "dict",
                        "options": {
                            "comfort_amount": {"required": False, "type": "int"},
                            "comfort_interval": {"required": False, "type": "int"},
                            "inspect_all": {"required": False, "type": "str",
                                            "choices": ["enable",
                                                        "disable"]},
                            "options": {"required": False, "type": "str",
                                        "choices": ["clientcomfort",
                                                    "oversize",
                                                    "splice",
                                                    "bypass-rest-command",
                                                    "bypass-mode-command"]},
                            "oversize_limit": {"required": False, "type": "int"},
                            "ports": {"required": False, "type": "int"},
                            "scan_bzip2": {"required": False, "type": "str",
                                           "choices": ["enable",
                                                       "disable"]},
                            "ssl_offloaded": {"required": False, "type": "str",
                                              "choices": ["no",
                                                          "yes"]},
                            "status": {"required": False, "type": "str",
                                       "choices": ["enable",
                                                   "disable"]},
                            "uncompressed_nest_limit": {"required": False, "type": "int"},
                            "uncompressed_oversize_limit": {"required": False, "type": "int"}
                        }},
                "http": {"required": False, "type": "dict",
                         "options": {
                             "block_page_status_code": {"required": False, "type": "int"},
                             "comfort_amount": {"required": False, "type": "int"},
                             "comfort_interval": {"required": False, "type": "int"},
                             "fortinet_bar": {"required": False, "type": "str",
                                              "choices": ["enable",
                                                          "disable"]},
                             "fortinet_bar_port": {"required": False, "type": "int"},
                             "inspect_all": {"required": False, "type": "str",
                                             "choices": ["enable",
                                                         "disable"]},
                             "options": {"required": False, "type": "str",
                                         "choices": ["clientcomfort",
                                                     "servercomfort",
                                                     "oversize",
                                                     "chunkedbypass"]},
                             "oversize_limit": {"required": False, "type": "int"},
                             "ports": {"required": False, "type": "int"},
                             "post_lang": {"required": False, "type": "str",
                                           "choices": ["jisx0201",
                                                       "jisx0208",
                                                       "jisx0212",
                                                       "gb2312",
                                                       "ksc5601-ex",
                                                       "euc-jp",
                                                       "sjis",
                                                       "iso2022-jp",
                                                       "iso2022-jp-1",
                                                       "iso2022-jp-2",
                                                       "euc-cn",
                                                       "ces-gbk",
                                                       "hz",
                                                       "ces-big5",
                                                       "euc-kr",
                                                       "iso2022-jp-3",
                                                       "iso8859-1",
                                                       "tis620",
                                                       "cp874",
                                                       "cp1252",
                                                       "cp1251"]},
                             "proxy_after_tcp_handshake": {"required": False, "type": "str",
                                                           "choices": ["enable",
                                                                       "disable"]},
                             "range_block": {"required": False, "type": "str",
                                             "choices": ["disable",
                                                         "enable"]},
                             "retry_count": {"required": False, "type": "int"},
                             "scan_bzip2": {"required": False, "type": "str",
                                            "choices": ["enable",
                                                        "disable"]},
                             "ssl_offloaded": {"required": False, "type": "str",
                                               "choices": ["no",
                                                           "yes"]},
                             "status": {"required": False, "type": "str",
                                        "choices": ["enable",
                                                    "disable"]},
                             "stream_based_uncompressed_limit": {"required": False, "type": "int"},
                             "streaming_content_bypass": {"required": False, "type": "str",
                                                          "choices": ["enable",
                                                                      "disable"]},
                             "strip_x_forwarded_for": {"required": False, "type": "str",
                                                       "choices": ["disable",
                                                                   "enable"]},
                             "switching_protocols": {"required": False, "type": "str",
                                                     "choices": ["bypass",
                                                                 "block"]},
                             "tcp_window_maximum": {"required": False, "type": "int"},
                             "tcp_window_minimum": {"required": False, "type": "int"},
                             "tcp_window_size": {"required": False, "type": "int"},
                             "tcp_window_type": {"required": False, "type": "str",
                                                 "choices": ["system",
                                                             "static",
                                                             "dynamic"]},
                             "tunnel_non_http": {"required": False, "type": "str",
                                                 "choices": ["enable",
                                                             "disable"]},
                             "uncompressed_nest_limit": {"required": False, "type": "int"},
                             "uncompressed_oversize_limit": {"required": False, "type": "int"},
                             "unknown_http_version": {"required": False, "type": "str",
                                                      "choices": ["reject",
                                                                  "tunnel",
                                                                  "best-effort"]}
                         }},
                "imap": {"required": False, "type": "dict",
                         "options": {
                             "inspect_all": {"required": False, "type": "str",
                                             "choices": ["enable",
                                                         "disable"]},
                             "options": {"required": False, "type": "str",
                                         "choices": ["fragmail",
                                                     "oversize"]},
                             "oversize_limit": {"required": False, "type": "int"},
                             "ports": {"required": False, "type": "int"},
                             "proxy_after_tcp_handshake": {"required": False, "type": "str",
                                                           "choices": ["enable",
                                                                       "disable"]},
                             "scan_bzip2": {"required": False, "type": "str",
                                            "choices": ["enable",
                                                        "disable"]},
                             "ssl_offloaded": {"required": False, "type": "str",
                                               "choices": ["no",
                                                           "yes"]},
                             "status": {"required": False, "type": "str",
                                        "choices": ["enable",
                                                    "disable"]},
                             "uncompressed_nest_limit": {"required": False, "type": "int"},
                             "uncompressed_oversize_limit": {"required": False, "type": "int"}
                         }},
                "mail_signature": {"required": False, "type": "dict",
                                   "options": {
                                       "signature": {"required": False, "type": "str"},
                                       "status": {"required": False, "type": "str",
                                                  "choices": ["disable",
                                                              "enable"]}
                                   }},
                "mapi": {"required": False, "type": "dict",
                         "options": {
                             "options": {"required": False, "type": "str",
                                         "choices": ["fragmail",
                                                     "oversize"]},
                             "oversize_limit": {"required": False, "type": "int"},
                             "ports": {"required": False, "type": "int"},
                             "scan_bzip2": {"required": False, "type": "str",
                                            "choices": ["enable",
                                                        "disable"]},
                             "status": {"required": False, "type": "str",
                                        "choices": ["enable",
                                                    "disable"]},
                             "uncompressed_nest_limit": {"required": False, "type": "int"},
                             "uncompressed_oversize_limit": {"required": False, "type": "int"}
                         }},
                "name": {"required": True, "type": "str"},
                "nntp": {"required": False, "type": "dict",
                         "options": {
                             "inspect_all": {"required": False, "type": "str",
                                             "choices": ["enable",
                                                         "disable"]},
                             "options": {"required": False, "type": "str",
                                         "choices": ["oversize",
                                                     "splice"]},
                             "oversize_limit": {"required": False, "type": "int"},
                             "ports": {"required": False, "type": "int"},
                             "proxy_after_tcp_handshake": {"required": False, "type": "str",
                                                           "choices": ["enable",
                                                                       "disable"]},
                             "scan_bzip2": {"required": False, "type": "str",
                                            "choices": ["enable",
                                                        "disable"]},
                             "status": {"required": False, "type": "str",
                                        "choices": ["enable",
                                                    "disable"]},
                             "uncompressed_nest_limit": {"required": False, "type": "int"},
                             "uncompressed_oversize_limit": {"required": False, "type": "int"}
                         }},
                "oversize_log": {"required": False, "type": "str",
                                 "choices": ["disable",
                                             "enable"]},
                "pop3": {"required": False, "type": "dict",
                         "options": {
                             "inspect_all": {"required": False, "type": "str",
                                             "choices": ["enable",
                                                         "disable"]},
                             "options": {"required": False, "type": "str",
                                         "choices": ["fragmail",
                                                     "oversize"]},
                             "oversize_limit": {"required": False, "type": "int"},
                             "ports": {"required": False, "type": "int"},
                             "proxy_after_tcp_handshake": {"required": False, "type": "str",
                                                           "choices": ["enable",
                                                                       "disable"]},
                             "scan_bzip2": {"required": False, "type": "str",
                                            "choices": ["enable",
                                                        "disable"]},
                             "ssl_offloaded": {"required": False, "type": "str",
                                               "choices": ["no",
                                                           "yes"]},
                             "status": {"required": False, "type": "str",
                                        "choices": ["enable",
                                                    "disable"]},
                             "uncompressed_nest_limit": {"required": False, "type": "int"},
                             "uncompressed_oversize_limit": {"required": False, "type": "int"}
                         }},
                "replacemsg_group": {"required": False, "type": "str"},
                "rpc_over_http": {"required": False, "type": "str",
                                  "choices": ["enable",
                                              "disable"]},
                "smtp": {"required": False, "type": "dict",
                         "options": {
                             "inspect_all": {"required": False, "type": "str",
                                             "choices": ["enable",
                                                         "disable"]},
                             "options": {"required": False, "type": "str",
                                         "choices": ["fragmail",
                                                     "oversize",
                                                     "splice"]},
                             "oversize_limit": {"required": False, "type": "int"},
                             "ports": {"required": False, "type": "int"},
                             "proxy_after_tcp_handshake": {"required": False, "type": "str",
                                                           "choices": ["enable",
                                                                       "disable"]},
                             "scan_bzip2": {"required": False, "type": "str",
                                            "choices": ["enable",
                                                        "disable"]},
                             "server_busy": {"required": False, "type": "str",
                                             "choices": ["enable",
                                                         "disable"]},
                             "ssl_offloaded": {"required": False, "type": "str",
                                               "choices": ["no",
                                                           "yes"]},
                             "status": {"required": False, "type": "str",
                                        "choices": ["enable",
                                                    "disable"]},
                             "uncompressed_nest_limit": {"required": False, "type": "int"},
                             "uncompressed_oversize_limit": {"required": False, "type": "int"}
                         }},
                "ssh": {"required": False, "type": "dict",
                        "options": {
                            "comfort_amount": {"required": False, "type": "int"},
                            "comfort_interval": {"required": False, "type": "int"},
                            "options": {"required": False, "type": "str",
                                        "choices": ["oversize",
                                                    "clientcomfort",
                                                    "servercomfort"]},
                            "oversize_limit": {"required": False, "type": "int"},
                            "scan_bzip2": {"required": False, "type": "str",
                                           "choices": ["enable",
                                                       "disable"]},
                            "uncompressed_nest_limit": {"required": False, "type": "int"},
                            "uncompressed_oversize_limit": {"required": False, "type": "int"}
                        }},
                "switching_protocols_log": {"required": False, "type": "str",
                                            "choices": ["disable",
                                                        "enable"]}

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

        is_error, has_changed, result = fortios_firewall(module.params, fos)
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
