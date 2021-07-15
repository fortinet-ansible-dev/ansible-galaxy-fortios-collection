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
module: fortios_firewall_ssl_ssh_profile
short_description: Configure SSL/SSH protocol options in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and ssl_ssh_profile category.
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
    firewall_ssl_ssh_profile:
        description:
            - Configure SSL/SSH protocol options.
        default: null
        type: dict
        suboptions:
            allowlist:
                description:
                    - Enable/disable exempting servers by FortiGuard allowlist.
                type: str
                choices:
                    - enable
                    - disable
            block_blacklisted_certificates:
                description:
                    - Enable/disable blocking SSL-based botnet communication by FortiGuard certificate blacklist.
                type: str
                choices:
                    - disable
                    - enable
            block_blocklisted_certificates:
                description:
                    - Enable/disable blocking SSL-based botnet communication by FortiGuard certificate blocklist.
                type: str
                choices:
                    - disable
                    - enable
            caname:
                description:
                    - CA certificate used by SSL Inspection. Source vpn.certificate.local.name.
                type: str
            comment:
                description:
                    - Optional comments.
                type: str
            dot:
                description:
                    - Configure DNS over TLS options.
                type: dict
                suboptions:
                    cert_validation_failure:
                        description:
                            - Action based on certificate validation failure.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    cert_validation_timeout:
                        description:
                            - Action based on certificate validation timeout.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    client_certificate:
                        description:
                            - Action based on received client certificate.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    expired_server_cert:
                        description:
                            - Action based on server certificate is expired.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    proxy_after_tcp_handshake:
                        description:
                            - Proxy traffic after the TCP 3-way handshake has been established (not before).
                        type: str
                        choices:
                            - enable
                            - disable
                    revoked_server_cert:
                        description:
                            - Action based on server certificate is revoked.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    sni_server_cert_check:
                        description:
                            - Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        type: str
                        choices:
                            - enable
                            - strict
                            - disable
                    status:
                        description:
                            - Configure protocol inspection status.
                        type: str
                        choices:
                            - disable
                            - deep-inspection
                    unsupported_ssl_cipher:
                        description:
                            - Action based on the SSL cipher used being unsupported.
                        type: str
                        choices:
                            - allow
                            - block
                    unsupported_ssl_negotiation:
                        description:
                            - Action based on the SSL negotiation used being unsupported.
                        type: str
                        choices:
                            - allow
                            - block
                    untrusted_server_cert:
                        description:
                            - Action based on server certificate is not issued by a trusted CA.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
            ftps:
                description:
                    - Configure FTPS options.
                type: dict
                suboptions:
                    allow_invalid_server_cert:
                        description:
                            - When enabled, allows SSL sessions whose server certificate validation failed.
                        type: str
                        choices:
                            - enable
                            - disable
                    cert_validation_failure:
                        description:
                            - Action based on certificate validation failure.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    cert_validation_timeout:
                        description:
                            - Action based on certificate validation timeout.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    client_cert_request:
                        description:
                            - Action based on client certificate request.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    client_certificate:
                        description:
                            - Action based on received client certificate.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    expired_server_cert:
                        description:
                            - Action based on server certificate is expired.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    invalid_server_cert:
                        description:
                            - Allow or block the invalid SSL session server certificate.
                        type: str
                        choices:
                            - allow
                            - block
                    ports:
                        description:
                            - Ports to use for scanning (1 - 65535).
                        type: int
                    revoked_server_cert:
                        description:
                            - Action based on server certificate is revoked.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    sni_server_cert_check:
                        description:
                            - Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        type: str
                        choices:
                            - enable
                            - strict
                            - disable
                    status:
                        description:
                            - Configure protocol inspection status.
                        type: str
                        choices:
                            - disable
                            - deep-inspection
                    unsupported_ssl:
                        description:
                            - Action based on the SSL encryption used being unsupported.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    unsupported_ssl_cipher:
                        description:
                            - Action based on the SSL cipher used being unsupported.
                        type: str
                        choices:
                            - allow
                            - block
                    unsupported_ssl_negotiation:
                        description:
                            - Action based on the SSL negotiation used being unsupported.
                        type: str
                        choices:
                            - allow
                            - block
                    untrusted_cert:
                        description:
                            - Allow, ignore, or block the untrusted SSL session server certificate.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    untrusted_server_cert:
                        description:
                            - Allow, ignore, or block the untrusted SSL session server certificate.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
            https:
                description:
                    - Configure HTTPS options.
                type: dict
                suboptions:
                    allow_invalid_server_cert:
                        description:
                            - When enabled, allows SSL sessions whose server certificate validation failed.
                        type: str
                        choices:
                            - enable
                            - disable
                    cert_probe_failure:
                        description:
                            - Action based on certificate probe failure.
                        type: str
                        choices:
                            - allow
                            - block
                    cert_validation_failure:
                        description:
                            - Action based on certificate validation failure.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    cert_validation_timeout:
                        description:
                            - Action based on certificate validation timeout.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    client_cert_request:
                        description:
                            - Action based on client certificate request.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    client_certificate:
                        description:
                            - Action based on received client certificate.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    expired_server_cert:
                        description:
                            - Action based on server certificate is expired.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    invalid_server_cert:
                        description:
                            - Allow or block the invalid SSL session server certificate.
                        type: str
                        choices:
                            - allow
                            - block
                    ports:
                        description:
                            - Ports to use for scanning (1 - 65535).
                        type: int
                    proxy_after_tcp_handshake:
                        description:
                            - Proxy traffic after the TCP 3-way handshake has been established (not before).
                        type: str
                        choices:
                            - enable
                            - disable
                    revoked_server_cert:
                        description:
                            - Action based on server certificate is revoked.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    sni_server_cert_check:
                        description:
                            - Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        type: str
                        choices:
                            - enable
                            - strict
                            - disable
                    status:
                        description:
                            - Configure protocol inspection status.
                        type: str
                        choices:
                            - disable
                            - certificate-inspection
                            - deep-inspection
                    unsupported_ssl:
                        description:
                            - Action based on the SSL encryption used being unsupported.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    unsupported_ssl_cipher:
                        description:
                            - Action based on the SSL cipher used being unsupported.
                        type: str
                        choices:
                            - allow
                            - block
                    unsupported_ssl_negotiation:
                        description:
                            - Action based on the SSL negotiation used being unsupported.
                        type: str
                        choices:
                            - allow
                            - block
                    untrusted_cert:
                        description:
                            - Allow, ignore, or block the untrusted SSL session server certificate.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    untrusted_server_cert:
                        description:
                            - Allow, ignore, or block the untrusted SSL session server certificate.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
            imaps:
                description:
                    - Configure IMAPS options.
                type: dict
                suboptions:
                    allow_invalid_server_cert:
                        description:
                            - When enabled, allows SSL sessions whose server certificate validation failed.
                        type: str
                        choices:
                            - enable
                            - disable
                    cert_validation_failure:
                        description:
                            - Action based on certificate validation failure.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    cert_validation_timeout:
                        description:
                            - Action based on certificate validation timeout.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    client_cert_request:
                        description:
                            - Action based on client certificate request.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    client_certificate:
                        description:
                            - Action based on received client certificate.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    expired_server_cert:
                        description:
                            - Action based on server certificate is expired.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    invalid_server_cert:
                        description:
                            - Allow or block the invalid SSL session server certificate.
                        type: str
                        choices:
                            - allow
                            - block
                    ports:
                        description:
                            - Ports to use for scanning (1 - 65535).
                        type: int
                    proxy_after_tcp_handshake:
                        description:
                            - Proxy traffic after the TCP 3-way handshake has been established (not before).
                        type: str
                        choices:
                            - enable
                            - disable
                    revoked_server_cert:
                        description:
                            - Action based on server certificate is revoked.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    sni_server_cert_check:
                        description:
                            - Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        type: str
                        choices:
                            - enable
                            - strict
                            - disable
                    status:
                        description:
                            - Configure protocol inspection status.
                        type: str
                        choices:
                            - disable
                            - deep-inspection
                    unsupported_ssl:
                        description:
                            - Action based on the SSL encryption used being unsupported.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    unsupported_ssl_cipher:
                        description:
                            - Action based on the SSL cipher used being unsupported.
                        type: str
                        choices:
                            - allow
                            - block
                    unsupported_ssl_negotiation:
                        description:
                            - Action based on the SSL negotiation used being unsupported.
                        type: str
                        choices:
                            - allow
                            - block
                    untrusted_cert:
                        description:
                            - Allow, ignore, or block the untrusted SSL session server certificate.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    untrusted_server_cert:
                        description:
                            - Allow, ignore, or block the untrusted SSL session server certificate.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
            mapi_over_https:
                description:
                    - Enable/disable inspection of MAPI over HTTPS.
                type: str
                choices:
                    - enable
                    - disable
            name:
                description:
                    - Name.
                required: true
                type: str
            pop3s:
                description:
                    - Configure POP3S options.
                type: dict
                suboptions:
                    allow_invalid_server_cert:
                        description:
                            - When enabled, allows SSL sessions whose server certificate validation failed.
                        type: str
                        choices:
                            - enable
                            - disable
                    cert_validation_failure:
                        description:
                            - Action based on certificate validation failure.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    cert_validation_timeout:
                        description:
                            - Action based on certificate validation timeout.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    client_cert_request:
                        description:
                            - Action based on client certificate request.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    client_certificate:
                        description:
                            - Action based on received client certificate.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    expired_server_cert:
                        description:
                            - Action based on server certificate is expired.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    invalid_server_cert:
                        description:
                            - Allow or block the invalid SSL session server certificate.
                        type: str
                        choices:
                            - allow
                            - block
                    ports:
                        description:
                            - Ports to use for scanning (1 - 65535).
                        type: int
                    proxy_after_tcp_handshake:
                        description:
                            - Proxy traffic after the TCP 3-way handshake has been established (not before).
                        type: str
                        choices:
                            - enable
                            - disable
                    revoked_server_cert:
                        description:
                            - Action based on server certificate is revoked.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    sni_server_cert_check:
                        description:
                            - Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        type: str
                        choices:
                            - enable
                            - strict
                            - disable
                    status:
                        description:
                            - Configure protocol inspection status.
                        type: str
                        choices:
                            - disable
                            - deep-inspection
                    unsupported_ssl:
                        description:
                            - Action based on the SSL encryption used being unsupported.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    unsupported_ssl_cipher:
                        description:
                            - Action based on the SSL cipher used being unsupported.
                        type: str
                        choices:
                            - allow
                            - block
                    unsupported_ssl_negotiation:
                        description:
                            - Action based on the SSL negotiation used being unsupported.
                        type: str
                        choices:
                            - allow
                            - block
                    untrusted_cert:
                        description:
                            - Allow, ignore, or block the untrusted SSL session server certificate.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    untrusted_server_cert:
                        description:
                            - Allow, ignore, or block the untrusted SSL session server certificate.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
            rpc_over_https:
                description:
                    - Enable/disable inspection of RPC over HTTPS.
                type: str
                choices:
                    - enable
                    - disable
            server_cert:
                description:
                    - Certificate used by SSL Inspection to replace server certificate. Source vpn.certificate.local.name.
                type: str
            server_cert_mode:
                description:
                    - Re-sign or replace the server"s certificate.
                type: str
                choices:
                    - re-sign
                    - replace
            smtps:
                description:
                    - Configure SMTPS options.
                type: dict
                suboptions:
                    allow_invalid_server_cert:
                        description:
                            - When enabled, allows SSL sessions whose server certificate validation failed.
                        type: str
                        choices:
                            - enable
                            - disable
                    cert_validation_failure:
                        description:
                            - Action based on certificate validation failure.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    cert_validation_timeout:
                        description:
                            - Action based on certificate validation timeout.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    client_cert_request:
                        description:
                            - Action based on client certificate request.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    client_certificate:
                        description:
                            - Action based on received client certificate.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    expired_server_cert:
                        description:
                            - Action based on server certificate is expired.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    invalid_server_cert:
                        description:
                            - Allow or block the invalid SSL session server certificate.
                        type: str
                        choices:
                            - allow
                            - block
                    ports:
                        description:
                            - Ports to use for scanning (1 - 65535).
                        type: int
                    proxy_after_tcp_handshake:
                        description:
                            - Proxy traffic after the TCP 3-way handshake has been established (not before).
                        type: str
                        choices:
                            - enable
                            - disable
                    revoked_server_cert:
                        description:
                            - Action based on server certificate is revoked.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    sni_server_cert_check:
                        description:
                            - Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        type: str
                        choices:
                            - enable
                            - strict
                            - disable
                    status:
                        description:
                            - Configure protocol inspection status.
                        type: str
                        choices:
                            - disable
                            - deep-inspection
                    unsupported_ssl:
                        description:
                            - Action based on the SSL encryption used being unsupported.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    unsupported_ssl_cipher:
                        description:
                            - Action based on the SSL cipher used being unsupported.
                        type: str
                        choices:
                            - allow
                            - block
                    unsupported_ssl_negotiation:
                        description:
                            - Action based on the SSL negotiation used being unsupported.
                        type: str
                        choices:
                            - allow
                            - block
                    untrusted_cert:
                        description:
                            - Allow, ignore, or block the untrusted SSL session server certificate.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    untrusted_server_cert:
                        description:
                            - Allow, ignore, or block the untrusted SSL session server certificate.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
            ssh:
                description:
                    - Configure SSH options.
                type: dict
                suboptions:
                    inspect_all:
                        description:
                            - Level of SSL inspection.
                        type: str
                        choices:
                            - disable
                            - deep-inspection
                    ports:
                        description:
                            - Ports to use for scanning (1 - 65535).
                        type: int
                    proxy_after_tcp_handshake:
                        description:
                            - Proxy traffic after the TCP 3-way handshake has been established (not before).
                        type: str
                        choices:
                            - enable
                            - disable
                    ssh_algorithm:
                        description:
                            - Relative strength of encryption algorithms accepted during negotiation.
                        type: str
                        choices:
                            - compatible
                            - high-encryption
                    ssh_policy_check:
                        description:
                            - Enable/disable SSH policy check.
                        type: str
                        choices:
                            - disable
                            - enable
                    ssh_tun_policy_check:
                        description:
                            - Enable/disable SSH tunnel policy check.
                        type: str
                        choices:
                            - disable
                            - enable
                    status:
                        description:
                            - Configure protocol inspection status.
                        type: str
                        choices:
                            - disable
                            - deep-inspection
                    unsupported_version:
                        description:
                            - Action based on SSH version being unsupported.
                        type: str
                        choices:
                            - bypass
                            - block
            ssl:
                description:
                    - Configure SSL options.
                type: dict
                suboptions:
                    allow_invalid_server_cert:
                        description:
                            - When enabled, allows SSL sessions whose server certificate validation failed.
                        type: str
                        choices:
                            - enable
                            - disable
                    cert_validation_failure:
                        description:
                            - Action based on certificate validation failure.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    cert_validation_timeout:
                        description:
                            - Action based on certificate validation timeout.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    client_cert_request:
                        description:
                            - Action based on client certificate request.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    client_certificate:
                        description:
                            - Action based on received client certificate.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    expired_server_cert:
                        description:
                            - Action based on server certificate is expired.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    inspect_all:
                        description:
                            - Level of SSL inspection.
                        type: str
                        choices:
                            - disable
                            - certificate-inspection
                            - deep-inspection
                    invalid_server_cert:
                        description:
                            - Allow or block the invalid SSL session server certificate.
                        type: str
                        choices:
                            - allow
                            - block
                    revoked_server_cert:
                        description:
                            - Action based on server certificate is revoked.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    sni_server_cert_check:
                        description:
                            - Check the SNI in the client hello message with the CN or SAN fields in the returned server certificate.
                        type: str
                        choices:
                            - enable
                            - strict
                            - disable
                    unsupported_ssl:
                        description:
                            - Action based on the SSL encryption used being unsupported.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    unsupported_ssl_cipher:
                        description:
                            - Action based on the SSL cipher used being unsupported.
                        type: str
                        choices:
                            - allow
                            - block
                    unsupported_ssl_negotiation:
                        description:
                            - Action based on the SSL negotiation used being unsupported.
                        type: str
                        choices:
                            - allow
                            - block
                    untrusted_cert:
                        description:
                            - Allow, ignore, or block the untrusted SSL session server certificate.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
                    untrusted_server_cert:
                        description:
                            - Allow, ignore, or block the untrusted SSL session server certificate.
                        type: str
                        choices:
                            - allow
                            - block
                            - ignore
            ssl_anomalies_log:
                description:
                    - Enable/disable logging SSL anomalies.
                type: str
                choices:
                    - disable
                    - enable
            ssl_exempt:
                description:
                    - Servers to exempt from SSL inspection.
                type: list
                suboptions:
                    address:
                        description:
                            - IPv4 address object. Source firewall.address.name firewall.addrgrp.name.
                        type: str
                    address6:
                        description:
                            - IPv6 address object. Source firewall.address6.name firewall.addrgrp6.name.
                        type: str
                    fortiguard_category:
                        description:
                            - FortiGuard category ID.
                        type: int
                    id:
                        description:
                            - ID number.
                        required: true
                        type: int
                    regex:
                        description:
                            - Exempt servers by regular expression.
                        type: str
                    type:
                        description:
                            - Type of address object (IPv4 or IPv6) or FortiGuard category.
                        type: str
                        choices:
                            - fortiguard-category
                            - address
                            - address6
                            - wildcard-fqdn
                            - regex
                    wildcard_fqdn:
                        description:
                            - Exempt servers by wildcard FQDN. Source firewall.wildcard-fqdn.custom.name firewall.wildcard-fqdn.group.name.
                        type: str
            ssl_exemptions_log:
                description:
                    - Enable/disable logging SSL exemptions.
                type: str
                choices:
                    - disable
                    - enable
            ssl_negotiation_log:
                description:
                    - Enable/disable logging SSL negotiation.
                type: str
                choices:
                    - disable
                    - enable
            ssl_server:
                description:
                    - SSL servers.
                type: list
                suboptions:
                    ftps_client_cert_request:
                        description:
                            - Action based on client certificate request during the FTPS handshake.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    ftps_client_certificate:
                        description:
                            - Action based on received client certificate during the FTPS handshake.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    https_client_cert_request:
                        description:
                            - Action based on client certificate request during the HTTPS handshake.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    https_client_certificate:
                        description:
                            - Action based on received client certificate during the HTTPS handshake.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    id:
                        description:
                            - SSL server ID.
                        required: true
                        type: int
                    imaps_client_cert_request:
                        description:
                            - Action based on client certificate request during the IMAPS handshake.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    imaps_client_certificate:
                        description:
                            - Action based on received client certificate during the IMAPS handshake.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    ip:
                        description:
                            - IPv4 address of the SSL server.
                        type: str
                    pop3s_client_cert_request:
                        description:
                            - Action based on client certificate request during the POP3S handshake.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    pop3s_client_certificate:
                        description:
                            - Action based on received client certificate during the POP3S handshake.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    smtps_client_cert_request:
                        description:
                            - Action based on client certificate request during the SMTPS handshake.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    smtps_client_certificate:
                        description:
                            - Action based on received client certificate during the SMTPS handshake.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    ssl_other_client_cert_request:
                        description:
                            - Action based on client certificate request during an SSL protocol handshake.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
                    ssl_other_client_certificate:
                        description:
                            - Action based on received client certificate during an SSL protocol handshake.
                        type: str
                        choices:
                            - bypass
                            - inspect
                            - block
            supported_alpn:
                description:
                    - Configure ALPN option.
                type: str
                choices:
                    - http1-1
                    - http2
                    - all
                    - none
            untrusted_caname:
                description:
                    - Untrusted CA certificate used by SSL Inspection. Source vpn.certificate.local.name.
                type: str
            use_ssl_server:
                description:
                    - Enable/disable the use of SSL server table for SSL offloading.
                type: str
                choices:
                    - disable
                    - enable
            whitelist:
                description:
                    - Enable/disable exempting servers by FortiGuard whitelist.
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
  - name: Configure SSL/SSH protocol options.
    fortios_firewall_ssl_ssh_profile:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_ssl_ssh_profile:
        allowlist: "enable"
        block_blacklisted_certificates: "disable"
        block_blocklisted_certificates: "disable"
        caname: "<your_own_value> (source vpn.certificate.local.name)"
        comment: "Optional comments."
        dot:
            cert_validation_failure: "allow"
            cert_validation_timeout: "allow"
            client_certificate: "bypass"
            expired_server_cert: "allow"
            proxy_after_tcp_handshake: "enable"
            revoked_server_cert: "allow"
            sni_server_cert_check: "enable"
            status: "disable"
            unsupported_ssl_cipher: "allow"
            unsupported_ssl_negotiation: "allow"
            untrusted_server_cert: "allow"
        ftps:
            allow_invalid_server_cert: "enable"
            cert_validation_failure: "allow"
            cert_validation_timeout: "allow"
            client_cert_request: "bypass"
            client_certificate: "bypass"
            expired_server_cert: "allow"
            invalid_server_cert: "allow"
            ports: "28"
            revoked_server_cert: "allow"
            sni_server_cert_check: "enable"
            status: "disable"
            unsupported_ssl: "bypass"
            unsupported_ssl_cipher: "allow"
            unsupported_ssl_negotiation: "allow"
            untrusted_cert: "allow"
            untrusted_server_cert: "allow"
        https:
            allow_invalid_server_cert: "enable"
            cert_probe_failure: "allow"
            cert_validation_failure: "allow"
            cert_validation_timeout: "allow"
            client_cert_request: "bypass"
            client_certificate: "bypass"
            expired_server_cert: "allow"
            invalid_server_cert: "allow"
            ports: "46"
            proxy_after_tcp_handshake: "enable"
            revoked_server_cert: "allow"
            sni_server_cert_check: "enable"
            status: "disable"
            unsupported_ssl: "bypass"
            unsupported_ssl_cipher: "allow"
            unsupported_ssl_negotiation: "allow"
            untrusted_cert: "allow"
            untrusted_server_cert: "allow"
        imaps:
            allow_invalid_server_cert: "enable"
            cert_validation_failure: "allow"
            cert_validation_timeout: "allow"
            client_cert_request: "bypass"
            client_certificate: "bypass"
            expired_server_cert: "allow"
            invalid_server_cert: "allow"
            ports: "64"
            proxy_after_tcp_handshake: "enable"
            revoked_server_cert: "allow"
            sni_server_cert_check: "enable"
            status: "disable"
            unsupported_ssl: "bypass"
            unsupported_ssl_cipher: "allow"
            unsupported_ssl_negotiation: "allow"
            untrusted_cert: "allow"
            untrusted_server_cert: "allow"
        mapi_over_https: "enable"
        name: "default_name_75"
        pop3s:
            allow_invalid_server_cert: "enable"
            cert_validation_failure: "allow"
            cert_validation_timeout: "allow"
            client_cert_request: "bypass"
            client_certificate: "bypass"
            expired_server_cert: "allow"
            invalid_server_cert: "allow"
            ports: "84"
            proxy_after_tcp_handshake: "enable"
            revoked_server_cert: "allow"
            sni_server_cert_check: "enable"
            status: "disable"
            unsupported_ssl: "bypass"
            unsupported_ssl_cipher: "allow"
            unsupported_ssl_negotiation: "allow"
            untrusted_cert: "allow"
            untrusted_server_cert: "allow"
        rpc_over_https: "enable"
        server_cert: "<your_own_value> (source vpn.certificate.local.name)"
        server_cert_mode: "re-sign"
        smtps:
            allow_invalid_server_cert: "enable"
            cert_validation_failure: "allow"
            cert_validation_timeout: "allow"
            client_cert_request: "bypass"
            client_certificate: "bypass"
            expired_server_cert: "allow"
            invalid_server_cert: "allow"
            ports: "105"
            proxy_after_tcp_handshake: "enable"
            revoked_server_cert: "allow"
            sni_server_cert_check: "enable"
            status: "disable"
            unsupported_ssl: "bypass"
            unsupported_ssl_cipher: "allow"
            unsupported_ssl_negotiation: "allow"
            untrusted_cert: "allow"
            untrusted_server_cert: "allow"
        ssh:
            inspect_all: "disable"
            ports: "117"
            proxy_after_tcp_handshake: "enable"
            ssh_algorithm: "compatible"
            ssh_policy_check: "disable"
            ssh_tun_policy_check: "disable"
            status: "disable"
            unsupported_version: "bypass"
        ssl:
            allow_invalid_server_cert: "enable"
            cert_validation_failure: "allow"
            cert_validation_timeout: "allow"
            client_cert_request: "bypass"
            client_certificate: "bypass"
            expired_server_cert: "allow"
            inspect_all: "disable"
            invalid_server_cert: "allow"
            revoked_server_cert: "allow"
            sni_server_cert_check: "enable"
            unsupported_ssl: "bypass"
            unsupported_ssl_cipher: "allow"
            unsupported_ssl_negotiation: "allow"
            untrusted_cert: "allow"
            untrusted_server_cert: "allow"
        ssl_anomalies_log: "disable"
        ssl_exempt:
         -
            address: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
            address6: "<your_own_value> (source firewall.address6.name firewall.addrgrp6.name)"
            fortiguard_category: "144"
            id:  "145"
            regex: "<your_own_value>"
            type: "fortiguard-category"
            wildcard_fqdn: "<your_own_value> (source firewall.wildcard-fqdn.custom.name firewall.wildcard-fqdn.group.name)"
        ssl_exemptions_log: "disable"
        ssl_negotiation_log: "disable"
        ssl_server:
         -
            ftps_client_cert_request: "bypass"
            ftps_client_certificate: "bypass"
            https_client_cert_request: "bypass"
            https_client_certificate: "bypass"
            id:  "156"
            imaps_client_cert_request: "bypass"
            imaps_client_certificate: "bypass"
            ip: "<your_own_value>"
            pop3s_client_cert_request: "bypass"
            pop3s_client_certificate: "bypass"
            smtps_client_cert_request: "bypass"
            smtps_client_certificate: "bypass"
            ssl_other_client_cert_request: "bypass"
            ssl_other_client_certificate: "bypass"
        supported_alpn: "http1-1"
        untrusted_caname: "<your_own_value> (source vpn.certificate.local.name)"
        use_ssl_server: "disable"
        whitelist: "enable"

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


def filter_firewall_ssl_ssh_profile_data(json):
    option_list = ['allowlist', 'block_blacklisted_certificates', 'block_blocklisted_certificates',
                   'caname', 'comment', 'dot',
                   'ftps', 'https', 'imaps',
                   'mapi_over_https', 'name', 'pop3s',
                   'rpc_over_https', 'server_cert', 'server_cert_mode',
                   'smtps', 'ssh', 'ssl',
                   'ssl_anomalies_log', 'ssl_exempt', 'ssl_exemptions_log',
                   'ssl_negotiation_log', 'ssl_server', 'supported_alpn',
                   'untrusted_caname', 'use_ssl_server', 'whitelist']
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


def firewall_ssl_ssh_profile(data, fos, check_mode=False):

    vdom = data['vdom']

    state = data['state']

    firewall_ssl_ssh_profile_data = data['firewall_ssl_ssh_profile']
    filtered_data = underscore_to_hyphen(filter_firewall_ssl_ssh_profile_data(firewall_ssl_ssh_profile_data))

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
        return fos.set('firewall',
                       'ssl-ssh-profile',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('firewall',
                          'ssl-ssh-profile',
                          mkey=filtered_data['name'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_firewall(data, fos, check_mode):

    if data['firewall_ssl_ssh_profile']:
        resp = firewall_ssl_ssh_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('firewall_ssl_ssh_profile'))
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
        "untrusted_caname": {
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
        "rpc_over_https": {
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
        "pop3s": {
            "type": "dict",
            "children": {
                "status": {
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
                            "value": "deep-inspection",
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
                "proxy_after_tcp_handshake": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "unsupported_ssl_negotiation": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "invalid_server_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": False,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "cert_validation_failure": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "unsupported_ssl": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
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
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "sni_server_cert_check": {
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
                            "value": "strict",
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
                "allow_invalid_server_cert": {
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
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": True
                    }
                },
                "revoked_server_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "expired_server_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "untrusted_server_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
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
                            "value": "block",
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
                            "value": "ignore",
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
                "untrusted_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": True
                    }
                },
                "unsupported_ssl_cipher": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "cert_validation_timeout": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "client_cert_request": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
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
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "ports": {
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
                "client_certificate": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
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
        "allowlist": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "caname": {
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
        "ftps": {
            "type": "dict",
            "children": {
                "status": {
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
                            "value": "deep-inspection",
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
                "unsupported_ssl_negotiation": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "invalid_server_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": False,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "cert_validation_failure": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "unsupported_ssl": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
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
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "sni_server_cert_check": {
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
                            "value": "strict",
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
                "allow_invalid_server_cert": {
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
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": True
                    }
                },
                "revoked_server_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "expired_server_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "untrusted_server_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
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
                            "value": "block",
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
                            "value": "ignore",
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
                "untrusted_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": True
                    }
                },
                "unsupported_ssl_cipher": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "cert_validation_timeout": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "client_cert_request": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
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
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "ports": {
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
                "client_certificate": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
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
        "use_ssl_server": {
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
        "server_cert_mode": {
            "type": "string",
            "options": [
                {
                    "value": "re-sign",
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
                    "value": "replace",
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
        "block_blocklisted_certificates": {
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "ssl_negotiation_log": {
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "supported_alpn": {
            "type": "string",
            "options": [
                {
                    "value": "http1-1",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "http2",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "all",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "none",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "https": {
            "type": "dict",
            "children": {
                "status": {
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
                            "value": "certificate-inspection",
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
                            "value": "deep-inspection",
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
                "proxy_after_tcp_handshake": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "unsupported_ssl_negotiation": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "invalid_server_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": False,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "cert_probe_failure": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "cert_validation_failure": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "unsupported_ssl": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
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
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "sni_server_cert_check": {
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
                            "value": "strict",
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
                "allow_invalid_server_cert": {
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
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": True
                    }
                },
                "revoked_server_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "expired_server_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "untrusted_server_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
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
                            "value": "block",
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
                            "value": "ignore",
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
                "untrusted_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": True
                    }
                },
                "unsupported_ssl_cipher": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "cert_validation_timeout": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "client_cert_request": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
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
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "ports": {
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
                "client_certificate": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
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
        "whitelist": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
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
                        "v6.0.11": True
                    }
                },
                {
                    "value": "disable",
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
                        "v6.0.11": True
                    }
                }
            ],
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": False,
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
        "server_cert": {
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
        "mapi_over_https": {
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
        "ssl": {
            "type": "dict",
            "children": {
                "unsupported_ssl_negotiation": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "invalid_server_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": False,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "cert_validation_failure": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "unsupported_ssl": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
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
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "sni_server_cert_check": {
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
                            "value": "strict",
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
                "allow_invalid_server_cert": {
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
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": True
                    }
                },
                "revoked_server_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "inspect_all": {
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
                            "value": "certificate-inspection",
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
                            "value": "deep-inspection",
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
                "untrusted_server_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
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
                            "value": "block",
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
                            "value": "ignore",
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
                "untrusted_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": True
                    }
                },
                "unsupported_ssl_cipher": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "cert_validation_timeout": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "client_cert_request": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
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
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "expired_server_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "client_certificate": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
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
        "ssl_server": {
            "type": "list",
            "children": {
                "ssl_other_client_cert_request": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
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
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "smtps_client_certificate": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "ip": {
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
                "https_client_cert_request": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
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
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "imaps_client_cert_request": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
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
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "pop3s_client_cert_request": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
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
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "ftps_client_cert_request": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
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
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "smtps_client_cert_request": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
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
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "ssl_other_client_certificate": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "ftps_client_certificate": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "pop3s_client_certificate": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
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
                "imaps_client_certificate": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "https_client_certificate": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
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
        "ssh": {
            "type": "dict",
            "children": {
                "status": {
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
                            "value": "deep-inspection",
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
                "proxy_after_tcp_handshake": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "ssh_policy_check": {
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
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": True
                    }
                },
                "ssh_tun_policy_check": {
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
                "ssh_algorithm": {
                    "type": "string",
                    "options": [
                        {
                            "value": "compatible",
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
                            "value": "high-encryption",
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
                "inspect_all": {
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
                            "value": "deep-inspection",
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
                "unsupported_version": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
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
                "ports": {
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
        "block_blacklisted_certificates": {
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
                        "v6.2.7": True
                    }
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
                        "v6.2.7": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": False,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True
            }
        },
        "ssl_exemptions_log": {
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
        "ssl_exempt": {
            "type": "list",
            "children": {
                "regex": {
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
                "wildcard_fqdn": {
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
                "address6": {
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
                "address": {
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
                "fortiguard_category": {
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
                "type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "fortiguard-category",
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
                            "value": "address",
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
                            "value": "address6",
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
                            "value": "wildcard-fqdn",
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
                            "value": "regex",
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
        "smtps": {
            "type": "dict",
            "children": {
                "status": {
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
                            "value": "deep-inspection",
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
                "proxy_after_tcp_handshake": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "unsupported_ssl_negotiation": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "invalid_server_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": False,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "cert_validation_failure": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "unsupported_ssl": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
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
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "sni_server_cert_check": {
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
                            "value": "strict",
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
                "allow_invalid_server_cert": {
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
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": True
                    }
                },
                "revoked_server_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "expired_server_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "untrusted_server_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
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
                            "value": "block",
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
                            "value": "ignore",
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
                "untrusted_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": True
                    }
                },
                "unsupported_ssl_cipher": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "cert_validation_timeout": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "client_cert_request": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
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
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "ports": {
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
                "client_certificate": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
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
        "imaps": {
            "type": "dict",
            "children": {
                "status": {
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
                            "value": "deep-inspection",
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
                "proxy_after_tcp_handshake": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "unsupported_ssl_negotiation": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "invalid_server_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": False,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True
                    }
                },
                "cert_validation_failure": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "unsupported_ssl": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
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
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "sni_server_cert_check": {
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
                            "value": "strict",
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
                "allow_invalid_server_cert": {
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
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": True
                    }
                },
                "revoked_server_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "expired_server_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "untrusted_server_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
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
                            "value": "block",
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
                            "value": "ignore",
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
                "untrusted_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.0.11": True,
                                "v6.0.0": True,
                                "v6.0.5": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": False,
                        "v6.2.3": False,
                        "v6.2.5": False,
                        "v6.2.7": False,
                        "v6.0.11": True
                    }
                },
                "unsupported_ssl_cipher": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "cert_validation_timeout": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                "client_cert_request": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
                                "v6.2.0": True,
                                "v6.2.3": True,
                                "v6.2.5": True,
                                "v6.2.7": True,
                                "v6.0.11": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.0.0": True,
                                "v6.0.5": True,
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
                        "v7.0.0": False,
                        "v6.0.5": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                "ports": {
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
                "client_certificate": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True,
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
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
        "ssl_anomalies_log": {
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
        "dot": {
            "type": "dict",
            "children": {
                "status": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "deep-inspection",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "proxy_after_tcp_handshake": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "unsupported_ssl_negotiation": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "cert_validation_failure": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "revoked_server_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "expired_server_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "untrusted_server_cert": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "unsupported_ssl_cipher": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "cert_validation_timeout": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "ignore",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "sni_server_cert_check": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "strict",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "client_certificate": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bypass",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "inspect",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            },
            "revisions": {
                "v7.0.0": True
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
        "firewall_ssl_ssh_profile": {
            "required": False, "type": "dict", "default": None,
            "options": {
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["firewall_ssl_ssh_profile"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_ssl_ssh_profile"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "firewall_ssl_ssh_profile")

        is_error, has_changed, result = fortios_firewall(module.params, fos, module.check_mode)

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
