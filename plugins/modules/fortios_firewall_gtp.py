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
module: fortios_firewall_gtp
short_description: Configure GTP in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify firewall feature and gtp category.
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
    firewall_gtp:
        description:
            - Configure GTP.
        default: null
        type: dict
        suboptions:
            addr_notify:
                description:
                    - overbilling notify address
                type: str
            apn:
                description:
                    - APN.
                type: list
                suboptions:
                    action:
                        description:
                            - Action.
                        type: str
                        choices:
                            - allow
                            - deny
                    apnmember:
                        description:
                            - APN member.
                        type: list
                        suboptions:
                            name:
                                description:
                                    - APN name. Source gtp.apn.name gtp.apngrp.name.
                                required: true
                                type: str
                    id:
                        description:
                            - ID.
                        required: true
                        type: int
                    selection_mode:
                        description:
                            - APN selection mode.
                        type: list
                        choices:
                            - ms
                            - net
                            - vrf
            apn_filter:
                description:
                    - apn filter
                type: str
                choices:
                    - enable
                    - disable
            authorized_ggsns:
                description:
                    - Authorized GGSN/PGW group. Source firewall.address.name firewall.addrgrp.name.
                type: str
            authorized_sgsns:
                description:
                    - Authorized SGSN/SGW group. Source firewall.address.name firewall.addrgrp.name.
                type: str
            comment:
                description:
                    - Comment.
                type: str
            context_id:
                description:
                    - Overbilling context.
                type: int
            control_plane_message_rate_limit:
                description:
                    - control plane message rate limit
                type: int
            default_apn_action:
                description:
                    - default apn action
                type: str
                choices:
                    - allow
                    - deny
            default_imsi_action:
                description:
                    - default imsi action
                type: str
                choices:
                    - allow
                    - deny
            default_ip_action:
                description:
                    - default action for encapsulated IP traffic
                type: str
                choices:
                    - allow
                    - deny
            default_noip_action:
                description:
                    - default action for encapsulated non-IP traffic
                type: str
                choices:
                    - allow
                    - deny
            default_policy_action:
                description:
                    - default advanced policy action
                type: str
                choices:
                    - allow
                    - deny
            denied_log:
                description:
                    - log denied
                type: str
                choices:
                    - enable
                    - disable
            echo_request_interval:
                description:
                    - echo request interval (in seconds)
                type: int
            extension_log:
                description:
                    - log in extension format
                type: str
                choices:
                    - enable
                    - disable
            forwarded_log:
                description:
                    - log forwarded
                type: str
                choices:
                    - enable
                    - disable
            global_tunnel_limit:
                description:
                    - Global tunnel limit. Source gtp.tunnel-limit.name.
                type: str
            gtp_in_gtp:
                description:
                    - gtp in gtp
                type: str
                choices:
                    - allow
                    - deny
            gtpu_denied_log:
                description:
                    - Enable/disable logging of denied GTP-U packets.
                type: str
                choices:
                    - enable
                    - disable
            gtpu_forwarded_log:
                description:
                    - Enable/disable logging of forwarded GTP-U packets.
                type: str
                choices:
                    - enable
                    - disable
            gtpu_log_freq:
                description:
                    - Logging of frequency of GTP-U packets.
                type: int
            half_close_timeout:
                description:
                    - Half-close tunnel timeout (in seconds).
                type: int
            half_open_timeout:
                description:
                    - Half-open tunnel timeout (in seconds).
                type: int
            handover_group:
                description:
                    - Handover SGSN/SGW group. Source firewall.address.name firewall.addrgrp.name.
                type: str
            ie_remove_policy:
                description:
                    - IE remove policy.
                type: list
                suboptions:
                    id:
                        description:
                            - ID.
                        required: true
                        type: int
                    remove_ies:
                        description:
                            - GTP IEs to be removed.
                        type: str
                        choices:
                            - apn_restriction
                            - rat_type
                            - rai
                            - uli
                            - imei
                    sgsn_addr:
                        description:
                            - SGSN address name. Source firewall.address.name firewall.addrgrp.name.
                        type: str
            ie_remover:
                description:
                    - IE removal policy.
                type: str
                choices:
                    - enable
                    - disable
            ie_validation:
                description:
                    - IE validation.
                type: dict
                suboptions:
                    apn_restriction:
                        description:
                            - Validate APN restriction.
                        type: str
                        choices:
                            - enable
                            - disable
                    charging_gateway_addr:
                        description:
                            - Validate charging gateway address.
                        type: str
                        choices:
                            - enable
                            - disable
                    charging_ID:
                        description:
                            - Validate charging ID.
                        type: str
                        choices:
                            - enable
                            - disable
                    end_user_addr:
                        description:
                            - Validate end user address.
                        type: str
                        choices:
                            - enable
                            - disable
                    gsn_addr:
                        description:
                            - Validate GSN address.
                        type: str
                        choices:
                            - enable
                            - disable
                    imei:
                        description:
                            - Validate IMEI(SV).
                        type: str
                        choices:
                            - enable
                            - disable
                    imsi:
                        description:
                            - Validate IMSI.
                        type: str
                        choices:
                            - enable
                            - disable
                    mm_context:
                        description:
                            - Validate MM context.
                        type: str
                        choices:
                            - enable
                            - disable
                    ms_tzone:
                        description:
                            - Validate MS time zone.
                        type: str
                        choices:
                            - enable
                            - disable
                    ms_validated:
                        description:
                            - Validate MS validated.
                        type: str
                        choices:
                            - enable
                            - disable
                    msisdn:
                        description:
                            - Validate MSISDN.
                        type: str
                        choices:
                            - enable
                            - disable
                    nsapi:
                        description:
                            - Validate NSAPI.
                        type: str
                        choices:
                            - enable
                            - disable
                    pdp_context:
                        description:
                            - Validate PDP context.
                        type: str
                        choices:
                            - enable
                            - disable
                    qos_profile:
                        description:
                            - Validate Quality of Service(QoS) profile.
                        type: str
                        choices:
                            - enable
                            - disable
                    rai:
                        description:
                            - Validate RAI.
                        type: str
                        choices:
                            - enable
                            - disable
                    rat_type:
                        description:
                            - Validate RAT type.
                        type: str
                        choices:
                            - enable
                            - disable
                    reordering_required:
                        description:
                            - Validate re-ordering required.
                        type: str
                        choices:
                            - enable
                            - disable
                    selection_mode:
                        description:
                            - Validate selection mode.
                        type: str
                        choices:
                            - enable
                            - disable
                    uli:
                        description:
                            - Validate user location information.
                        type: str
                        choices:
                            - enable
                            - disable
            ie_white_list_v0v1:
                description:
                    - IE white list. Source gtp.ie-white-list.name.
                type: str
            ie_white_list_v2:
                description:
                    - IE white list. Source gtp.ie-white-list.name.
                type: str
            imsi:
                description:
                    - IMSI.
                type: list
                suboptions:
                    action:
                        description:
                            - Action.
                        type: str
                        choices:
                            - allow
                            - deny
                    apnmember:
                        description:
                            - APN member.
                        type: list
                        suboptions:
                            name:
                                description:
                                    - APN name. Source gtp.apn.name gtp.apngrp.name.
                                required: true
                                type: str
                    id:
                        description:
                            - ID.
                        required: true
                        type: int
                    mcc_mnc:
                        description:
                            - MCC MNC.
                        type: str
                    msisdn_prefix:
                        description:
                            - MSISDN prefix.
                        type: str
                    selection_mode:
                        description:
                            - APN selection mode.
                        type: list
                        choices:
                            - ms
                            - net
                            - vrf
            imsi_filter:
                description:
                    - imsi filter
                type: str
                choices:
                    - enable
                    - disable
            interface_notify:
                description:
                    - overbilling interface Source system.interface.name.
                type: str
            invalid_reserved_field:
                description:
                    - Invalid reserved field in GTP header
                type: str
                choices:
                    - allow
                    - deny
            invalid_sgsns_to_log:
                description:
                    - Invalid SGSN group to be logged Source firewall.address.name firewall.addrgrp.name.
                type: str
            ip_filter:
                description:
                    - IP filter for encapsulted traffic
                type: str
                choices:
                    - enable
                    - disable
            ip_policy:
                description:
                    - IP policy.
                type: list
                suboptions:
                    action:
                        description:
                            - Action.
                        type: str
                        choices:
                            - allow
                            - deny
                    dstaddr:
                        description:
                            - Destination address name. Source firewall.address.name firewall.addrgrp.name.
                        type: str
                    id:
                        description:
                            - ID.
                        required: true
                        type: int
                    srcaddr:
                        description:
                            - Source address name. Source firewall.address.name firewall.addrgrp.name.
                        type: str
            log_freq:
                description:
                    - Logging of frequency of GTP-C packets.
                type: int
            log_gtpu_limit:
                description:
                    - the user data log limit (0-512 bytes)
                type: int
            log_imsi_prefix:
                description:
                    - IMSI prefix for selective logging.
                type: str
            log_msisdn_prefix:
                description:
                    - the msisdn prefix for selective logging
                type: str
            max_message_length:
                description:
                    - max message length
                type: int
            message_filter_v0v1:
                description:
                    - Message filter. Source gtp.message-filter-v0v1.name.
                type: str
            message_filter_v2:
                description:
                    - Message filter. Source gtp.message-filter-v2.name.
                type: str
            message_rate_limit:
                description:
                    - Message rate limiting.
                type: dict
                suboptions:
                    create_aa_pdp_request:
                        description:
                            - Rate limit for create AA PDP context request (packets per second).
                        type: int
                    create_aa_pdp_response:
                        description:
                            - Rate limit for create AA PDP context response (packets per second).
                        type: int
                    create_mbms_request:
                        description:
                            - Rate limit for create MBMS context request (packets per second).
                        type: int
                    create_mbms_response:
                        description:
                            - Rate limit for create MBMS context response (packets per second).
                        type: int
                    create_pdp_request:
                        description:
                            - Rate limit for create PDP context request (packets per second).
                        type: int
                    create_pdp_response:
                        description:
                            - Rate limit for create PDP context response (packets per second).
                        type: int
                    delete_aa_pdp_request:
                        description:
                            - Rate limit for delete AA PDP context request (packets per second).
                        type: int
                    delete_aa_pdp_response:
                        description:
                            - Rate limit for delete AA PDP context response (packets per second).
                        type: int
                    delete_mbms_request:
                        description:
                            - Rate limit for delete MBMS context request (packets per second).
                        type: int
                    delete_mbms_response:
                        description:
                            - Rate limit for delete MBMS context response (packets per second).
                        type: int
                    delete_pdp_request:
                        description:
                            - Rate limit for delete PDP context request (packets per second).
                        type: int
                    delete_pdp_response:
                        description:
                            - Rate limit for delete PDP context response (packets per second).
                        type: int
                    echo_reponse:
                        description:
                            - Rate limit for echo response (packets per second).
                        type: int
                    echo_request:
                        description:
                            - Rate limit for echo requests (packets per second).
                        type: int
                    error_indication:
                        description:
                            - Rate limit for error indication (packets per second).
                        type: int
                    failure_report_request:
                        description:
                            - Rate limit for failure report request (packets per second).
                        type: int
                    failure_report_response:
                        description:
                            - Rate limit for failure report response (packets per second).
                        type: int
                    fwd_reloc_complete_ack:
                        description:
                            - Rate limit for forward relocation complete acknowledge (packets per second).
                        type: int
                    fwd_relocation_complete:
                        description:
                            - Rate limit for forward relocation complete (packets per second).
                        type: int
                    fwd_relocation_request:
                        description:
                            - Rate limit for forward relocation request (packets per second).
                        type: int
                    fwd_relocation_response:
                        description:
                            - Rate limit for forward relocation response (packets per second).
                        type: int
                    fwd_srns_context:
                        description:
                            - Rate limit for forward SRNS context (packets per second).
                        type: int
                    fwd_srns_context_ack:
                        description:
                            - Rate limit for forward SRNS context acknowledge (packets per second).
                        type: int
                    g_pdu:
                        description:
                            - Rate limit for G-PDU (packets per second).
                        type: int
                    identification_request:
                        description:
                            - Rate limit for identification request (packets per second).
                        type: int
                    identification_response:
                        description:
                            - Rate limit for identification response (packets per second).
                        type: int
                    mbms_de_reg_request:
                        description:
                            - Rate limit for MBMS de-registration request (packets per second).
                        type: int
                    mbms_de_reg_response:
                        description:
                            - Rate limit for MBMS de-registration response (packets per second).
                        type: int
                    mbms_notify_rej_request:
                        description:
                            - Rate limit for MBMS notification reject request (packets per second).
                        type: int
                    mbms_notify_rej_response:
                        description:
                            - Rate limit for MBMS notification reject response (packets per second).
                        type: int
                    mbms_notify_request:
                        description:
                            - Rate limit for MBMS notification request (packets per second).
                        type: int
                    mbms_notify_response:
                        description:
                            - Rate limit for MBMS notification response (packets per second).
                        type: int
                    mbms_reg_request:
                        description:
                            - Rate limit for MBMS registration request (packets per second).
                        type: int
                    mbms_reg_response:
                        description:
                            - Rate limit for MBMS registration response (packets per second).
                        type: int
                    mbms_ses_start_request:
                        description:
                            - Rate limit for MBMS session start request (packets per second).
                        type: int
                    mbms_ses_start_response:
                        description:
                            - Rate limit for MBMS session start response (packets per second).
                        type: int
                    mbms_ses_stop_request:
                        description:
                            - Rate limit for MBMS session stop request (packets per second).
                        type: int
                    mbms_ses_stop_response:
                        description:
                            - Rate limit for MBMS session stop response (packets per second).
                        type: int
                    note_ms_request:
                        description:
                            - Rate limit for note MS GPRS present request (packets per second).
                        type: int
                    note_ms_response:
                        description:
                            - Rate limit for note MS GPRS present response (packets per second).
                        type: int
                    pdu_notify_rej_request:
                        description:
                            - Rate limit for PDU notify reject request (packets per second).
                        type: int
                    pdu_notify_rej_response:
                        description:
                            - Rate limit for PDU notify reject response (packets per second).
                        type: int
                    pdu_notify_request:
                        description:
                            - Rate limit for PDU notify request (packets per second).
                        type: int
                    pdu_notify_response:
                        description:
                            - Rate limit for PDU notify response (packets per second).
                        type: int
                    ran_info:
                        description:
                            - Rate limit for RAN information relay (packets per second).
                        type: int
                    relocation_cancel_request:
                        description:
                            - Rate limit for relocation cancel request (packets per second).
                        type: int
                    relocation_cancel_response:
                        description:
                            - Rate limit for relocation cancel response (packets per second).
                        type: int
                    send_route_request:
                        description:
                            - Rate limit for send routing information for GPRS request (packets per second).
                        type: int
                    send_route_response:
                        description:
                            - Rate limit for send routing information for GPRS response (packets per second).
                        type: int
                    sgsn_context_ack:
                        description:
                            - Rate limit for SGSN context acknowledgement (packets per second).
                        type: int
                    sgsn_context_request:
                        description:
                            - Rate limit for SGSN context request (packets per second).
                        type: int
                    sgsn_context_response:
                        description:
                            - Rate limit for SGSN context response (packets per second).
                        type: int
                    support_ext_hdr_notify:
                        description:
                            - Rate limit for support extension headers notification (packets per second).
                        type: int
                    update_mbms_request:
                        description:
                            - Rate limit for update MBMS context request (packets per second).
                        type: int
                    update_mbms_response:
                        description:
                            - Rate limit for update MBMS context response (packets per second).
                        type: int
                    update_pdp_request:
                        description:
                            - Rate limit for update PDP context request (packets per second).
                        type: int
                    update_pdp_response:
                        description:
                            - Rate limit for update PDP context response (packets per second).
                        type: int
                    version_not_support:
                        description:
                            - Rate limit for version not supported (packets per second).
                        type: int
            message_rate_limit_v0:
                description:
                    - Message rate limiting for GTP version 0.
                type: dict
                suboptions:
                    create_pdp_request:
                        description:
                            - Rate limit (packets/s) for create PDP context request.
                        type: int
                    delete_pdp_request:
                        description:
                            - Rate limit (packets/s) for delete PDP context request.
                        type: int
                    echo_request:
                        description:
                            - Rate limit (packets/s) for echo request.
                        type: int
            message_rate_limit_v1:
                description:
                    - Message rate limiting for GTP version 1.
                type: dict
                suboptions:
                    create_pdp_request:
                        description:
                            - Rate limit (packets/s) for create PDP context request.
                        type: int
                    delete_pdp_request:
                        description:
                            - Rate limit (packets/s) for delete PDP context request.
                        type: int
                    echo_request:
                        description:
                            - Rate limit (packets/s) for echo request.
                        type: int
            message_rate_limit_v2:
                description:
                    - Message rate limiting for GTP version 2.
                type: dict
                suboptions:
                    create_session_request:
                        description:
                            - Rate limit (packets/s) for create session request.
                        type: int
                    delete_session_request:
                        description:
                            - Rate limit (packets/s) for delete session request.
                        type: int
                    echo_request:
                        description:
                            - Rate limit (packets/s) for echo request.
                        type: int
            min_message_length:
                description:
                    - min message length
                type: int
            miss_must_ie:
                description:
                    - Missing mandatory information element
                type: str
                choices:
                    - allow
                    - deny
            monitor_mode:
                description:
                    - GTP monitor mode.
                type: str
                choices:
                    - enable
                    - disable
                    - vdom
            name:
                description:
                    - Profile name.
                required: true
                type: str
            noip_filter:
                description:
                    - non-IP filter for encapsulted traffic
                type: str
                choices:
                    - enable
                    - disable
            noip_policy:
                description:
                    - No IP policy.
                type: list
                suboptions:
                    action:
                        description:
                            - Action.
                        type: str
                        choices:
                            - allow
                            - deny
                    end:
                        description:
                            - End of protocol range (0 - 255).
                        type: int
                    id:
                        description:
                            - ID.
                        required: true
                        type: int
                    start:
                        description:
                            - Start of protocol range (0 - 255).
                        type: int
                    type:
                        description:
                            - Protocol field type.
                        type: str
                        choices:
                            - etsi
                            - ietf
            out_of_state_ie:
                description:
                    - Out of state information element.
                type: str
                choices:
                    - allow
                    - deny
            out_of_state_message:
                description:
                    - Out of state GTP message
                type: str
                choices:
                    - allow
                    - deny
            per_apn_shaper:
                description:
                    - Per APN shaper.
                type: list
                suboptions:
                    apn:
                        description:
                            - APN name. Source gtp.apn.name.
                        type: str
                    id:
                        description:
                            - ID.
                        required: true
                        type: int
                    rate_limit:
                        description:
                            - Rate limit (packets/s) for create PDP context request.
                        type: int
                    version:
                        description:
                            - 'GTP version number: 0 or 1.'
                        type: int
            policy:
                description:
                    - Policy.
                type: list
                suboptions:
                    action:
                        description:
                            - Action.
                        type: str
                        choices:
                            - allow
                            - deny
                    apn_sel_mode:
                        description:
                            - APN selection mode.
                        type: list
                        choices:
                            - ms
                            - net
                            - vrf
                    apnmember:
                        description:
                            - APN member.
                        type: list
                        suboptions:
                            name:
                                description:
                                    - APN name. Source gtp.apn.name gtp.apngrp.name.
                                required: true
                                type: str
                    id:
                        description:
                            - ID.
                        required: true
                        type: int
                    imei:
                        description:
                            - IMEI pattern.
                        type: str
                    imsi_prefix:
                        description:
                            - IMSI prefix.
                        type: str
                    max_apn_restriction:
                        description:
                            - Maximum APN restriction value.
                        type: str
                        choices:
                            - all
                            - public_1
                            - public_2
                            - private_1
                            - private_2
                    messages:
                        description:
                            - GTP messages.
                        type: list
                        choices:
                            - create_req
                            - create_res
                            - update_req
                            - update_res
                    msisdn_prefix:
                        description:
                            - MSISDN prefix.
                        type: str
                    rai:
                        description:
                            - RAI pattern.
                        type: str
                    rat_type:
                        description:
                            - RAT Type.
                        type: list
                        choices:
                            - any
                            - utran
                            - geran
                            - wlan
                            - gan
                            - hspa
                            - eutran
                            - virtual
                            - nbiot
                    uli:
                        description:
                            - ULI pattern.
                        type: str
            policy_filter:
                description:
                    - Advanced policy filter
                type: str
                choices:
                    - enable
                    - disable
            policy_v2:
                description:
                    - Apply allow or deny action to each GTPv2-c packet.
                type: list
                suboptions:
                    action:
                        description:
                            - Action.
                        type: str
                        choices:
                            - allow
                            - deny
                    apn_sel_mode:
                        description:
                            - APN selection mode.
                        type: str
                        choices:
                            - ms
                            - net
                            - vrf
                    apnmember:
                        description:
                            - APN member.
                        type: list
                        suboptions:
                            name:
                                description:
                                    - APN name. Source gtp.apn.name gtp.apngrp.name.
                                required: true
                                type: str
                    id:
                        description:
                            - ID.
                        required: true
                        type: int
                    imsi_prefix:
                        description:
                            - IMSI prefix.
                        type: str
                    max_apn_restriction:
                        description:
                            - Maximum APN restriction value.
                        type: str
                        choices:
                            - all
                            - public_1
                            - public_2
                            - private_1
                            - private_2
                    mei:
                        description:
                            - MEI pattern.
                        type: str
                    messages:
                        description:
                            - GTP messages.
                        type: str
                        choices:
                            - create_ses_req
                            - create_ses_res
                            - modify_bearer_req
                            - modify_bearer_res
                    msisdn_prefix:
                        description:
                            - MSISDN prefix.
                        type: str
                    rat_type:
                        description:
                            - RAT Type.
                        type: str
                        choices:
                            - any
                            - utran
                            - geran
                            - wlan
                            - gan
                            - hspa
                            - eutran
                            - virtual
                            - nbiot
                    uli:
                        description:
                            - GTPv2 ULI patterns (in order of CGI SAI RAI TAI ECGI LAI).
                        type: str
            port_notify:
                description:
                    - overbilling notify port
                type: int
            rate_limit_mode:
                description:
                    - GTP rate limit mode.
                type: str
                choices:
                    - per_profile
                    - per_stream
                    - per_apn
            rate_limited_log:
                description:
                    - log rate limited
                type: str
                choices:
                    - enable
                    - disable
            rate_sampling_interval:
                description:
                    - rate sampling interval (1-3600 seconds)
                type: int
            remove_if_echo_expires:
                description:
                    - remove if echo response expires
                type: str
                choices:
                    - enable
                    - disable
            remove_if_recovery_differ:
                description:
                    - remove upon different Recovery IE
                type: str
                choices:
                    - enable
                    - disable
            reserved_ie:
                description:
                    - reserved information element
                type: str
                choices:
                    - allow
                    - deny
            send_delete_when_timeout:
                description:
                    - send DELETE request to path endpoints when GTPv0/v1 tunnel timeout.
                type: str
                choices:
                    - enable
                    - disable
            send_delete_when_timeout_v2:
                description:
                    - send DELETE request to path endpoints when GTPv2 tunnel timeout.
                type: str
                choices:
                    - enable
                    - disable
            spoof_src_addr:
                description:
                    - Spoofed source address for Mobile Station.
                type: str
                choices:
                    - allow
                    - deny
            state_invalid_log:
                description:
                    - log state invalid
                type: str
                choices:
                    - enable
                    - disable
            sub_second_interval:
                description:
                    - Sub-second interval (0.1, 0.25, or 0.5 sec).
                type: str
                choices:
                    - 0.5
                    - 0.25
                    - 0.1
            sub_second_sampling:
                description:
                    - Enable/disable sub-second sampling.
                type: str
                choices:
                    - enable
                    - disable
            traffic_count_log:
                description:
                    - log tunnel traffic counter
                type: str
                choices:
                    - enable
                    - disable
            tunnel_limit:
                description:
                    - tunnel limit
                type: int
            tunnel_limit_log:
                description:
                    - tunnel limit
                type: str
                choices:
                    - enable
                    - disable
            tunnel_timeout:
                description:
                    - Established tunnel timeout (in seconds).
                type: int
            unknown_version_action:
                description:
                    - action for unknown gtp version
                type: str
                choices:
                    - allow
                    - deny
            user_plane_message_rate_limit:
                description:
                    - user plane message rate limit
                type: int
            warning_threshold:
                description:
                    - Warning threshold for rate limiting (0 - 99 percent).
                type: int
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
  - name: Configure GTP.
    fortios_firewall_gtp:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      firewall_gtp:
        addr_notify: "<your_own_value>"
        apn:
         -
            action: "allow"
            apnmember:
             -
                name: "default_name_7 (source gtp.apn.name gtp.apngrp.name)"
            id:  "8"
            selection_mode: "ms"
        apn_filter: "enable"
        authorized_ggsns: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
        authorized_sgsns: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
        comment: "Comment."
        context_id: "14"
        control_plane_message_rate_limit: "15"
        default_apn_action: "allow"
        default_imsi_action: "allow"
        default_ip_action: "allow"
        default_noip_action: "allow"
        default_policy_action: "allow"
        denied_log: "enable"
        echo_request_interval: "22"
        extension_log: "enable"
        forwarded_log: "enable"
        global_tunnel_limit: "<your_own_value> (source gtp.tunnel-limit.name)"
        gtp_in_gtp: "allow"
        gtpu_denied_log: "enable"
        gtpu_forwarded_log: "enable"
        gtpu_log_freq: "29"
        half_close_timeout: "30"
        half_open_timeout: "31"
        handover_group: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
        ie_remove_policy:
         -
            id:  "34"
            remove_ies: "apn_restriction"
            sgsn_addr: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
        ie_remover: "enable"
        ie_validation:
            apn_restriction: "enable"
            charging_gateway_addr: "enable"
            charging_ID: "enable"
            end_user_addr: "enable"
            gsn_addr: "enable"
            imei: "enable"
            imsi: "enable"
            mm_context: "enable"
            ms_tzone: "enable"
            ms_validated: "enable"
            msisdn: "enable"
            nsapi: "enable"
            pdp_context: "enable"
            qos_profile: "enable"
            rai: "enable"
            rat_type: "enable"
            reordering_required: "enable"
            selection_mode: "enable"
            uli: "enable"
        ie_white_list_v0v1: "<your_own_value> (source gtp.ie-white-list.name)"
        ie_white_list_v2: "<your_own_value> (source gtp.ie-white-list.name)"
        imsi:
         -
            action: "allow"
            apnmember:
             -
                name: "default_name_63 (source gtp.apn.name gtp.apngrp.name)"
            id:  "64"
            mcc_mnc: "<your_own_value>"
            msisdn_prefix: "<your_own_value>"
            selection_mode: "ms"
        imsi_filter: "enable"
        interface_notify: "<your_own_value> (source system.interface.name)"
        invalid_reserved_field: "allow"
        invalid_sgsns_to_log: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
        ip_filter: "enable"
        ip_policy:
         -
            action: "allow"
            dstaddr: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
            id:  "76"
            srcaddr: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
        log_freq: "78"
        log_gtpu_limit: "79"
        log_imsi_prefix: "<your_own_value>"
        log_msisdn_prefix: "<your_own_value>"
        max_message_length: "82"
        message_filter_v0v1: "<your_own_value> (source gtp.message-filter-v0v1.name)"
        message_filter_v2: "<your_own_value> (source gtp.message-filter-v2.name)"
        message_rate_limit:
            create_aa_pdp_request: "86"
            create_aa_pdp_response: "87"
            create_mbms_request: "88"
            create_mbms_response: "89"
            create_pdp_request: "90"
            create_pdp_response: "91"
            delete_aa_pdp_request: "92"
            delete_aa_pdp_response: "93"
            delete_mbms_request: "94"
            delete_mbms_response: "95"
            delete_pdp_request: "96"
            delete_pdp_response: "97"
            echo_reponse: "98"
            echo_request: "99"
            error_indication: "100"
            failure_report_request: "101"
            failure_report_response: "102"
            fwd_reloc_complete_ack: "103"
            fwd_relocation_complete: "104"
            fwd_relocation_request: "105"
            fwd_relocation_response: "106"
            fwd_srns_context: "107"
            fwd_srns_context_ack: "108"
            g_pdu: "109"
            identification_request: "110"
            identification_response: "111"
            mbms_de_reg_request: "112"
            mbms_de_reg_response: "113"
            mbms_notify_rej_request: "114"
            mbms_notify_rej_response: "115"
            mbms_notify_request: "116"
            mbms_notify_response: "117"
            mbms_reg_request: "118"
            mbms_reg_response: "119"
            mbms_ses_start_request: "120"
            mbms_ses_start_response: "121"
            mbms_ses_stop_request: "122"
            mbms_ses_stop_response: "123"
            note_ms_request: "124"
            note_ms_response: "125"
            pdu_notify_rej_request: "126"
            pdu_notify_rej_response: "127"
            pdu_notify_request: "128"
            pdu_notify_response: "129"
            ran_info: "130"
            relocation_cancel_request: "131"
            relocation_cancel_response: "132"
            send_route_request: "133"
            send_route_response: "134"
            sgsn_context_ack: "135"
            sgsn_context_request: "136"
            sgsn_context_response: "137"
            support_ext_hdr_notify: "138"
            update_mbms_request: "139"
            update_mbms_response: "140"
            update_pdp_request: "141"
            update_pdp_response: "142"
            version_not_support: "143"
        message_rate_limit_v0:
            create_pdp_request: "145"
            delete_pdp_request: "146"
            echo_request: "147"
        message_rate_limit_v1:
            create_pdp_request: "149"
            delete_pdp_request: "150"
            echo_request: "151"
        message_rate_limit_v2:
            create_session_request: "153"
            delete_session_request: "154"
            echo_request: "155"
        min_message_length: "156"
        miss_must_ie: "allow"
        monitor_mode: "enable"
        name: "default_name_159"
        noip_filter: "enable"
        noip_policy:
         -
            action: "allow"
            end: "163"
            id:  "164"
            start: "165"
            type: "etsi"
        out_of_state_ie: "allow"
        out_of_state_message: "allow"
        per_apn_shaper:
         -
            apn: "<your_own_value> (source gtp.apn.name)"
            id:  "171"
            rate_limit: "172"
            version: "173"
        policy:
         -
            action: "allow"
            apn_sel_mode: "ms"
            apnmember:
             -
                name: "default_name_178 (source gtp.apn.name gtp.apngrp.name)"
            id:  "179"
            imei: "<your_own_value>"
            imsi_prefix: "<your_own_value>"
            max_apn_restriction: "all"
            messages: "create_req"
            msisdn_prefix: "<your_own_value>"
            rai: "<your_own_value>"
            rat_type: "any"
            uli: "<your_own_value>"
        policy_filter: "enable"
        policy_v2:
         -
            action: "allow"
            apn_sel_mode: "ms"
            apnmember:
             -
                name: "default_name_193 (source gtp.apn.name gtp.apngrp.name)"
            id:  "194"
            imsi_prefix: "<your_own_value>"
            max_apn_restriction: "all"
            mei: "<your_own_value>"
            messages: "create_ses_req"
            msisdn_prefix: "<your_own_value>"
            rat_type: "any"
            uli: "<your_own_value>"
        port_notify: "202"
        rate_limit_mode: "per_profile"
        rate_limited_log: "enable"
        rate_sampling_interval: "205"
        remove_if_echo_expires: "enable"
        remove_if_recovery_differ: "enable"
        reserved_ie: "allow"
        send_delete_when_timeout: "enable"
        send_delete_when_timeout_v2: "enable"
        spoof_src_addr: "allow"
        state_invalid_log: "enable"
        sub_second_interval: "0.5"
        sub_second_sampling: "enable"
        traffic_count_log: "enable"
        tunnel_limit: "216"
        tunnel_limit_log: "enable"
        tunnel_timeout: "218"
        unknown_version_action: "allow"
        user_plane_message_rate_limit: "220"
        warning_threshold: "221"

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


def filter_firewall_gtp_data(json):
    option_list = ['addr_notify', 'apn', 'apn_filter',
                   'authorized_ggsns', 'authorized_sgsns', 'comment',
                   'context_id', 'control_plane_message_rate_limit', 'default_apn_action',
                   'default_imsi_action', 'default_ip_action', 'default_noip_action',
                   'default_policy_action', 'denied_log', 'echo_request_interval',
                   'extension_log', 'forwarded_log', 'global_tunnel_limit',
                   'gtp_in_gtp', 'gtpu_denied_log', 'gtpu_forwarded_log',
                   'gtpu_log_freq', 'half_close_timeout', 'half_open_timeout',
                   'handover_group', 'ie_remove_policy', 'ie_remover',
                   'ie_validation', 'ie_white_list_v0v1', 'ie_white_list_v2',
                   'imsi', 'imsi_filter', 'interface_notify',
                   'invalid_reserved_field', 'invalid_sgsns_to_log', 'ip_filter',
                   'ip_policy', 'log_freq', 'log_gtpu_limit',
                   'log_imsi_prefix', 'log_msisdn_prefix', 'max_message_length',
                   'message_filter_v0v1', 'message_filter_v2', 'message_rate_limit',
                   'message_rate_limit_v0', 'message_rate_limit_v1', 'message_rate_limit_v2',
                   'min_message_length', 'miss_must_ie', 'monitor_mode',
                   'name', 'noip_filter', 'noip_policy',
                   'out_of_state_ie', 'out_of_state_message', 'per_apn_shaper',
                   'policy', 'policy_filter', 'policy_v2',
                   'port_notify', 'rate_limit_mode', 'rate_limited_log',
                   'rate_sampling_interval', 'remove_if_echo_expires', 'remove_if_recovery_differ',
                   'reserved_ie', 'send_delete_when_timeout', 'send_delete_when_timeout_v2',
                   'spoof_src_addr', 'state_invalid_log', 'sub_second_interval',
                   'sub_second_sampling', 'traffic_count_log', 'tunnel_limit',
                   'tunnel_limit_log', 'tunnel_timeout', 'unknown_version_action',
                   'user_plane_message_rate_limit', 'warning_threshold']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def flatten_multilists_attributes(data):
    multilist_attrs = [[u'policy_v2', u'rat_type'], [u'policy_v2', u'messages'], [u'policy_v2', u'apn_sel_mode'], [u'imsi', u'selection_mode'], [u'policy',
                                                                                                                                                 u'rat_type'], [u'policy', u'messages'], [u'policy', u'apn_sel_mode'], [u'ie_remove_policy', u'remove_ies'], [u'apn', u'selection_mode']]

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


def firewall_gtp(data, fos):
    vdom = data['vdom']

    state = data['state']

    firewall_gtp_data = data['firewall_gtp']
    firewall_gtp_data = flatten_multilists_attributes(firewall_gtp_data)
    filtered_data = underscore_to_hyphen(filter_firewall_gtp_data(firewall_gtp_data))

    if state == "present" or state == True:
        return fos.set('firewall',
                       'gtp',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('firewall',
                          'gtp',
                          mkey=filtered_data['name'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_firewall(data, fos):

    if data['firewall_gtp']:
        resp = firewall_gtp(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('firewall_gtp'))

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
                "v6.4.1": True
            }
        },
        "sub_second_sampling": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "default_noip_action": {
            "type": "string",
            "options": [
                {
                    "value": "allow",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "deny",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "denied_log": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "context_id": {
            "type": "integer",
            "revisions": {
                "v6.4.1": True
            }
        },
        "user_plane_message_rate_limit": {
            "type": "integer",
            "revisions": {
                "v6.4.1": True
            }
        },
        "invalid_sgsns_to_log": {
            "type": "string",
            "revisions": {
                "v6.4.1": True
            }
        },
        "rate_limited_log": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "remove_if_recovery_differ": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "min_message_length": {
            "type": "integer",
            "revisions": {
                "v6.4.1": True
            }
        },
        "out_of_state_ie": {
            "type": "string",
            "options": [
                {
                    "value": "allow",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "deny",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "noip_policy": {
            "type": "list",
            "children": {
                "action": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "deny",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "start": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "end": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "id": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "etsi",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "ietf",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            },
            "revisions": {
                "v6.4.1": True
            }
        },
        "gtpu_log_freq": {
            "type": "integer",
            "revisions": {
                "v6.4.1": True
            }
        },
        "half_open_timeout": {
            "type": "integer",
            "revisions": {
                "v6.4.1": True
            }
        },
        "rate_sampling_interval": {
            "type": "integer",
            "revisions": {
                "v6.4.1": True
            }
        },
        "log_imsi_prefix": {
            "type": "string",
            "revisions": {
                "v6.4.1": True
            }
        },
        "miss_must_ie": {
            "type": "string",
            "options": [
                {
                    "value": "allow",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "deny",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "unknown_version_action": {
            "type": "string",
            "options": [
                {
                    "value": "allow",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "deny",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "interface_notify": {
            "type": "string",
            "revisions": {
                "v6.4.1": True
            }
        },
        "forwarded_log": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "handover_group": {
            "type": "string",
            "revisions": {
                "v6.4.1": True
            }
        },
        "control_plane_message_rate_limit": {
            "type": "integer",
            "revisions": {
                "v6.4.1": True
            }
        },
        "message_filter_v2": {
            "type": "string",
            "revisions": {
                "v6.4.1": True
            }
        },
        "traffic_count_log": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "ip_policy": {
            "type": "list",
            "children": {
                "srcaddr": {
                    "type": "string",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "action": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "deny",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "dstaddr": {
                    "type": "string",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "id": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            },
            "revisions": {
                "v6.4.1": True
            }
        },
        "rate_limit_mode": {
            "type": "string",
            "options": [
                {
                    "value": "per-profile",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "per-stream",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "per-apn",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "policy_v2": {
            "type": "list",
            "children": {
                "imsi_prefix": {
                    "type": "string",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "rat_type": {
                    "multiple_values": True,
                    "type": "list",
                    "options": [
                        {
                            "value": "any",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "utran",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "geran",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "wlan",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "gan",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "hspa",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "eutran",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "virtual",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "nbiot",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "messages": {
                    "multiple_values": True,
                    "type": "list",
                    "options": [
                        {
                            "value": "create-ses-req",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "create-ses-res",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "modify-bearer-req",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "modify-bearer-res",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "mei": {
                    "type": "string",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "max_apn_restriction": {
                    "type": "string",
                    "options": [
                        {
                            "value": "all",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "public-1",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "public-2",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "private-1",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "private-2",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "apnmember": {
                    "type": "list",
                    "children": {
                        "name": {
                            "type": "string",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    },
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "uli": {
                    "type": "string",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "action": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "deny",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "apn_sel_mode": {
                    "multiple_values": True,
                    "type": "list",
                    "options": [
                        {
                            "value": "ms",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "net",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "vrf",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "msisdn_prefix": {
                    "type": "string",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "id": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            },
            "revisions": {
                "v6.4.1": True
            }
        },
        "gtpu_forwarded_log": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "global_tunnel_limit": {
            "type": "string",
            "revisions": {
                "v6.4.1": True
            }
        },
        "out_of_state_message": {
            "type": "string",
            "options": [
                {
                    "value": "allow",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "deny",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "send_delete_when_timeout": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "half_close_timeout": {
            "type": "integer",
            "revisions": {
                "v6.4.1": True
            }
        },
        "ip_filter": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "warning_threshold": {
            "type": "integer",
            "revisions": {
                "v6.4.1": True
            }
        },
        "ie_remover": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "spoof_src_addr": {
            "type": "string",
            "options": [
                {
                    "value": "allow",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "deny",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "imsi": {
            "type": "list",
            "children": {
                "selection_mode": {
                    "multiple_values": True,
                    "type": "list",
                    "options": [
                        {
                            "value": "ms",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "net",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "vrf",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "action": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "deny",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "apnmember": {
                    "type": "list",
                    "children": {
                        "name": {
                            "type": "string",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    },
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "mcc_mnc": {
                    "type": "string",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "msisdn_prefix": {
                    "type": "string",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "id": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            },
            "revisions": {
                "v6.4.1": True
            }
        },
        "sub_second_interval": {
            "type": "string",
            "options": [
                {
                    "value": "0.5",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "0.25",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "0.1",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "tunnel_limit": {
            "type": "integer",
            "revisions": {
                "v6.4.1": True
            }
        },
        "imsi_filter": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "remove_if_echo_expires": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "max_message_length": {
            "type": "integer",
            "revisions": {
                "v6.4.1": True
            }
        },
        "extension_log": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "echo_request_interval": {
            "type": "integer",
            "revisions": {
                "v6.4.1": True
            }
        },
        "monitor_mode": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "vdom",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "policy": {
            "type": "list",
            "children": {
                "imsi_prefix": {
                    "type": "string",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "imei": {
                    "type": "string",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "rat_type": {
                    "multiple_values": True,
                    "type": "list",
                    "options": [
                        {
                            "value": "any",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "utran",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "geran",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "wlan",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "gan",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "hspa",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "eutran",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "virtual",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "nbiot",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "id": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "messages": {
                    "multiple_values": True,
                    "type": "list",
                    "options": [
                        {
                            "value": "create-req",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "create-res",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "update-req",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "update-res",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "rai": {
                    "type": "string",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "max_apn_restriction": {
                    "type": "string",
                    "options": [
                        {
                            "value": "all",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "public-1",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "public-2",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "private-1",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "private-2",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "apn_sel_mode": {
                    "multiple_values": True,
                    "type": "list",
                    "options": [
                        {
                            "value": "ms",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "net",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "vrf",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "uli": {
                    "type": "string",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "apnmember": {
                    "type": "list",
                    "children": {
                        "name": {
                            "type": "string",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    },
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "msisdn_prefix": {
                    "type": "string",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "action": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "deny",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            },
            "revisions": {
                "v6.4.1": True
            }
        },
        "log_msisdn_prefix": {
            "type": "string",
            "revisions": {
                "v6.4.1": True
            }
        },
        "addr_notify": {
            "type": "string",
            "revisions": {
                "v6.4.1": True
            }
        },
        "tunnel_limit_log": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "default_ip_action": {
            "type": "string",
            "options": [
                {
                    "value": "allow",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "deny",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "tunnel_timeout": {
            "type": "integer",
            "revisions": {
                "v6.4.1": True
            }
        },
        "message_rate_limit_v2": {
            "type": "dict",
            "children": {
                "delete_session_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "echo_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "create_session_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            },
            "revisions": {
                "v6.4.1": True
            }
        },
        "gtpu_denied_log": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "ie_white_list_v0v1": {
            "type": "string",
            "revisions": {
                "v6.4.1": True
            }
        },
        "port_notify": {
            "type": "integer",
            "revisions": {
                "v6.4.1": True
            }
        },
        "default_policy_action": {
            "type": "string",
            "options": [
                {
                    "value": "allow",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "deny",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "reserved_ie": {
            "type": "string",
            "options": [
                {
                    "value": "allow",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "deny",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "apn_filter": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "log_gtpu_limit": {
            "type": "integer",
            "revisions": {
                "v6.4.1": True
            }
        },
        "per_apn_shaper": {
            "type": "list",
            "children": {
                "rate_limit": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "version": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "apn": {
                    "type": "string",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "id": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            },
            "revisions": {
                "v6.4.1": True
            }
        },
        "name": {
            "type": "string",
            "revisions": {
                "v6.4.1": True
            }
        },
        "ie_white_list_v2": {
            "type": "string",
            "revisions": {
                "v6.4.1": True
            }
        },
        "ie_remove_policy": {
            "type": "list",
            "children": {
                "sgsn_addr": {
                    "type": "string",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "remove_ies": {
                    "multiple_values": True,
                    "type": "list",
                    "options": [
                        {
                            "value": "apn-restriction",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "rat-type",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "rai",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "uli",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "imei",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "id": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            },
            "revisions": {
                "v6.4.1": True
            }
        },
        "send_delete_when_timeout_v2": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "invalid_reserved_field": {
            "type": "string",
            "options": [
                {
                    "value": "allow",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "deny",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "message_rate_limit": {
            "type": "dict",
            "children": {
                "identification_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "pdu_notify_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "update_pdp_response": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "fwd_relocation_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "identification_response": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "support_ext_hdr_notify": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "delete_aa_pdp_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "update_pdp_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "delete_mbms_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "fwd_relocation_response": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "create_pdp_response": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "mbms_ses_start_response": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "g_pdu": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "create_aa_pdp_response": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "create_mbms_response": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "echo_reponse": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "create_aa_pdp_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "relocation_cancel_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "mbms_reg_response": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "echo_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "fwd_reloc_complete_ack": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "update_mbms_response": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "create_mbms_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "pdu_notify_rej_response": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "mbms_reg_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "note_ms_response": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "create_pdp_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "send_route_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "mbms_notify_rej_response": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "mbms_ses_stop_response": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "send_route_response": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "mbms_ses_start_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "error_indication": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "mbms_notify_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "mbms_de_reg_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "mbms_ses_stop_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "delete_pdp_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "ran_info": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "delete_pdp_response": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "relocation_cancel_response": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "note_ms_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "fwd_relocation_complete": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "failure_report_response": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "mbms_notify_response": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "pdu_notify_rej_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "fwd_srns_context": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "version_not_support": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "mbms_notify_rej_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "delete_mbms_response": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "delete_aa_pdp_response": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "fwd_srns_context_ack": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "sgsn_context_response": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "failure_report_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "sgsn_context_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "pdu_notify_response": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "mbms_de_reg_response": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "update_mbms_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "sgsn_context_ack": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            },
            "revisions": {
                "v6.4.1": True
            }
        },
        "message_rate_limit_v0": {
            "type": "dict",
            "children": {
                "create_pdp_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "delete_pdp_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "echo_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            },
            "revisions": {
                "v6.4.1": True
            }
        },
        "message_rate_limit_v1": {
            "type": "dict",
            "children": {
                "create_pdp_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "delete_pdp_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "echo_request": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            },
            "revisions": {
                "v6.4.1": True
            }
        },
        "default_apn_action": {
            "type": "string",
            "options": [
                {
                    "value": "allow",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "deny",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "default_imsi_action": {
            "type": "string",
            "options": [
                {
                    "value": "allow",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "deny",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "policy_filter": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "state_invalid_log": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "message_filter_v0v1": {
            "type": "string",
            "revisions": {
                "v6.4.1": True
            }
        },
        "apn": {
            "type": "list",
            "children": {
                "apnmember": {
                    "type": "list",
                    "children": {
                        "name": {
                            "type": "string",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    },
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "action": {
                    "type": "string",
                    "options": [
                        {
                            "value": "allow",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "deny",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "selection_mode": {
                    "multiple_values": True,
                    "type": "list",
                    "options": [
                        {
                            "value": "ms",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "net",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "vrf",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "id": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            },
            "revisions": {
                "v6.4.1": True
            }
        },
        "authorized_ggsns": {
            "type": "string",
            "revisions": {
                "v6.4.1": True
            }
        },
        "log_freq": {
            "type": "integer",
            "revisions": {
                "v6.4.1": True
            }
        },
        "noip_filter": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        },
        "ie_validation": {
            "type": "dict",
            "children": {
                "gsn_addr": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "ms_tzone": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "nsapi": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "msisdn": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "selection_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "uli": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "rat_type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "end_user_addr": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "rai": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "charging_gateway_addr": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "pdp_context": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "charging_ID": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "reordering_required": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "imei": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "mm_context": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "qos_profile": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "apn_restriction": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "imsi": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                "ms_validated": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.1": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            },
            "revisions": {
                "v6.4.1": True
            }
        },
        "authorized_sgsns": {
            "type": "string",
            "revisions": {
                "v6.4.1": True
            }
        },
        "gtp_in_gtp": {
            "type": "string",
            "options": [
                {
                    "value": "allow",
                    "revisions": {
                        "v6.4.1": True
                    }
                },
                {
                    "value": "deny",
                    "revisions": {
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.1": True
            }
        }
    },
    "revisions": {
        "v6.4.1": True
    }
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = 'name'
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "state": {"required": True, "type": "str",
                  "choices": ["present", "absent"]},
        "firewall_gtp": {
            "required": False, "type": "dict", "default": None,
            "options": {
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["firewall_gtp"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["firewall_gtp"]['options'][attribute_name]['required'] = True

    check_legacy_fortiosapi()
    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if 'access_token' in module.params:
            connection.set_option('access_token', module.params['access_token'])

        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(fos, versioned_schema, "firewall_gtp")

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
