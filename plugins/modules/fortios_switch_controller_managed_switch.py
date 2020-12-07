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
module: fortios_switch_controller_managed_switch
short_description: Configure FortiSwitch devices that are managed by this FortiGate in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify switch_controller feature and managed_switch category.
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
    switch_controller_managed_switch:
        description:
            - Configure FortiSwitch devices that are managed by this FortiGate.
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
            settings_802_1X:
                description:
                    - Configuration method to edit FortiSwitch 802.1X global settings.
                type: dict
                suboptions:
                    link_down_auth:
                        description:
                            - Authentication state to set if a link is down.
                        type: str
                        choices:
                            - set-unauth
                            - no-action
                    local_override:
                        description:
                            - Enable to override global 802.1X settings on individual FortiSwitches.
                        type: str
                        choices:
                            - enable
                            - disable
                    max_reauth_attempt:
                        description:
                            - Maximum number of authentication attempts (0 - 15).
                        type: int
                    reauth_period:
                        description:
                            - Reauthentication time interval (1 - 1440 min).
                        type: int
                    tx_period:
                        description:
                            - 802.1X Tx period (seconds).
                        type: int
            access_profile:
                description:
                    - FortiSwitch access profile. Source switch-controller.security-policy.local-access.name.
                type: str
            custom_command:
                description:
                    - Configuration method to edit FortiSwitch commands to be pushed to this FortiSwitch device upon rebooting the FortiGate switch controller
                       or the FortiSwitch.
                type: list
                suboptions:
                    command_entry:
                        description:
                            - List of FortiSwitch commands.
                        type: str
                    command_name:
                        description:
                            - Names of commands to be pushed to this FortiSwitch device, as configured under config switch-controller custom-command. Source
                               switch-controller.custom-command.command-name.
                        type: str
            delayed_restart_trigger:
                description:
                    - Delayed restart triggered for this FortiSwitch.
                type: int
            description:
                description:
                    - Description.
                type: str
            directly_connected:
                description:
                    - Directly connected FortiSwitch.
                type: int
            dynamic_capability:
                description:
                    - List of features this FortiSwitch supports (not configurable) that is sent to the FortiGate device for subsequent configuration
                       initiated by the FortiGate device.
                type: int
            dynamically_discovered:
                description:
                    - Dynamically discovered FortiSwitch.
                type: int
            flow_identity:
                description:
                    - Flow-tracking netflow ipfix switch identity in hex format(00000000-FFFFFFFF ).
                type: str
            fsw_wan1_admin:
                description:
                    - FortiSwitch WAN1 admin status; enable to authorize the FortiSwitch as a managed switch.
                type: str
                choices:
                    - discovered
                    - disable
                    - enable
            fsw_wan1_peer:
                description:
                    - Fortiswitch WAN1 peer port.
                type: str
            igmp_snooping:
                description:
                    - Configure FortiSwitch IGMP snooping global settings.
                type: dict
                suboptions:
                    aging_time:
                        description:
                            - Maximum time to retain a multicast snooping entry for which no packets have been seen (15 - 3600 sec).
                        type: int
                    flood_unknown_multicast:
                        description:
                            - Enable/disable unknown multicast flooding.
                        type: str
                        choices:
                            - enable
                            - disable
                    local_override:
                        description:
                            - Enable/disable overriding the global IGMP snooping configuration.
                        type: str
                        choices:
                            - enable
                            - disable
            ip_source_guard:
                description:
                    - IP source guard.
                type: list
                suboptions:
                    binding_entry:
                        description:
                            - IP and MAC address configuration.
                        type: list
                        suboptions:
                            entry_name:
                                description:
                                    - Configure binding pair.
                                type: str
                            ip:
                                description:
                                    - Source IP for this rule.
                                type: str
                            mac:
                                description:
                                    - MAC address for this rule.
                                type: str
                    description:
                        description:
                            - Description.
                        type: str
                    port:
                        description:
                            - Ingress interface to which source guard is bound.
                        required: true
                        type: str
            l3_discovered:
                description:
                    - Layer 3 management discovered.
                type: int
            mclag_igmp_snooping_aware:
                description:
                    - Enable/disable MCLAG IGMP-snooping awareness.
                type: str
                choices:
                    - enable
                    - disable
            mirror:
                description:
                    - Configuration method to edit FortiSwitch packet mirror.
                type: list
                suboptions:
                    dst:
                        description:
                            - Destination port.
                        type: str
                    name:
                        description:
                            - Mirror name.
                        required: true
                        type: str
                    src_egress:
                        description:
                            - Source egress interfaces.
                        type: list
                        suboptions:
                            name:
                                description:
                                    - Interface name.
                                required: true
                                type: str
                    src_ingress:
                        description:
                            - Source ingress interfaces.
                        type: list
                        suboptions:
                            name:
                                description:
                                    - Interface name.
                                required: true
                                type: str
                    status:
                        description:
                            - Active/inactive mirror configuration.
                        type: str
                        choices:
                            - active
                            - inactive
                    switching_packet:
                        description:
                            - Enable/disable switching functionality when mirroring.
                        type: str
                        choices:
                            - enable
                            - disable
            name:
                description:
                    - Managed-switch name.
                type: str
            override_snmp_community:
                description:
                    - Enable/disable overriding the global SNMP communities.
                type: str
                choices:
                    - enable
                    - disable
            override_snmp_sysinfo:
                description:
                    - Enable/disable overriding the global SNMP system information.
                type: str
                choices:
                    - disable
                    - enable
            override_snmp_trap_threshold:
                description:
                    - Enable/disable overriding the global SNMP trap threshold values.
                type: str
                choices:
                    - enable
                    - disable
            override_snmp_user:
                description:
                    - Enable/disable overriding the global SNMP users.
                type: str
                choices:
                    - enable
                    - disable
            owner_vdom:
                description:
                    - VDOM which owner of port belongs to.
                type: str
            poe_detection_type:
                description:
                    - PoE detection type for FortiSwitch.
                type: int
            poe_pre_standard_detection:
                description:
                    - Enable/disable PoE pre-standard detection.
                type: str
                choices:
                    - enable
                    - disable
            ports:
                description:
                    - Managed-switch port list.
                type: list
                suboptions:
                    access_mode:
                        description:
                            - Access mode of the port.
                        type: str
                        choices:
                            - normal
                            - nac
                    allowed_vlans:
                        description:
                            - Configure switch port tagged vlans
                        type: list
                        suboptions:
                            vlan_name:
                                description:
                                    - VLAN name. Source system.interface.name.
                                type: str
                    allowed_vlans_all:
                        description:
                            - Enable/disable all defined vlans on this port.
                        type: str
                        choices:
                            - enable
                            - disable
                    arp_inspection_trust:
                        description:
                            - Trusted or untrusted dynamic ARP inspection.
                        type: str
                        choices:
                            - untrusted
                            - trusted
                    bundle:
                        description:
                            - Enable/disable Link Aggregation Group (LAG) bundling for non-FortiLink interfaces.
                        type: str
                        choices:
                            - enable
                            - disable
                    description:
                        description:
                            - Description for port.
                        type: str
                    dhcp_snoop_option82_trust:
                        description:
                            - Enable/disable allowance of DHCP with option-82 on untrusted interface.
                        type: str
                        choices:
                            - enable
                            - disable
                    dhcp_snooping:
                        description:
                            - Trusted or untrusted DHCP-snooping interface.
                        type: str
                        choices:
                            - untrusted
                            - trusted
                    discard_mode:
                        description:
                            - Configure discard mode for port.
                        type: str
                        choices:
                            - none
                            - all-untagged
                            - all-tagged
                    edge_port:
                        description:
                            - Enable/disable this interface as an edge port, bridging connections between workstations and/or computers.
                        type: str
                        choices:
                            - enable
                            - disable
                    export_tags:
                        description:
                            - Configure export tag(s) for FortiSwitch port when exported to a virtual port pool.
                        type: list
                        suboptions:
                            tag_name:
                                description:
                                    - FortiSwitch port tag name when exported to a virtual port pool. Source switch-controller.switch-interface-tag.name.
                                type: str
                    export_to:
                        description:
                            - Export managed-switch port to a tenant VDOM. Source system.vdom.name.
                        type: str
                    export_to_pool:
                        description:
                            - Switch controller export port to pool-list. Source switch-controller.virtual-port-pool.name.
                        type: str
                    fgt_peer_device_name:
                        description:
                            - FGT peer device name.
                        type: str
                    fgt_peer_port_name:
                        description:
                            - FGT peer port name.
                        type: str
                    fiber_port:
                        description:
                            - Fiber-port.
                        type: int
                    flags:
                        description:
                            - Port properties flags.
                        type: int
                    fortilink_port:
                        description:
                            - FortiLink uplink port.
                        type: int
                    igmps_flood_reports:
                        description:
                            - Enable/disable flooding of IGMP reports to this interface when igmp-snooping enabled.
                        type: str
                        choices:
                            - enable
                            - disable
                    igmps_flood_traffic:
                        description:
                            - Enable/disable flooding of IGMP snooping traffic to this interface.
                        type: str
                        choices:
                            - enable
                            - disable
                    ip_source_guard:
                        description:
                            - Enable/disable IP source guard.
                        type: str
                        choices:
                            - disable
                            - enable
                    isl_local_trunk_name:
                        description:
                            - ISL local trunk name.
                        type: str
                    isl_peer_device_name:
                        description:
                            - ISL peer device name.
                        type: str
                    isl_peer_port_name:
                        description:
                            - ISL peer port name.
                        type: str
                    lacp_speed:
                        description:
                            - end Link Aggregation Control Protocol (LACP) messages every 30 seconds (slow) or every second (fast).
                        type: str
                        choices:
                            - slow
                            - fast
                    learning_limit:
                        description:
                            - Limit the number of dynamic MAC addresses on this Port (1 - 128, 0 = no limit, default).
                        type: int
                    lldp_profile:
                        description:
                            - LLDP port TLV profile. Source switch-controller.lldp-profile.name.
                        type: str
                    lldp_status:
                        description:
                            - LLDP transmit and receive status.
                        type: str
                        choices:
                            - disable
                            - rx-only
                            - tx-only
                            - tx-rx
                    loop_guard:
                        description:
                            - Enable/disable loop-guard on this interface, an STP optimization used to prevent network loops.
                        type: str
                        choices:
                            - enabled
                            - disabled
                    loop_guard_timeout:
                        description:
                            - Loop-guard timeout (0 - 120 min).
                        type: int
                    mac_addr:
                        description:
                            - Port/Trunk MAC.
                        type: str
                    max_bundle:
                        description:
                            - Maximum size of LAG bundle (1 - 24)
                        type: int
                    mclag:
                        description:
                            - Enable/disable multi-chassis link aggregation (MCLAG).
                        type: str
                        choices:
                            - enable
                            - disable
                    mclag_icl_port:
                        description:
                            - MCLAG-ICL port.
                        type: int
                    member_withdrawal_behavior:
                        description:
                            - Port behavior after it withdraws because of loss of control packets.
                        type: str
                        choices:
                            - forward
                            - block
                    members:
                        description:
                            - Aggregated LAG bundle interfaces.
                        type: list
                        suboptions:
                            member_name:
                                description:
                                    - Interface name from available options.
                                type: str
                    min_bundle:
                        description:
                            - Minimum size of LAG bundle (1 - 24)
                        type: int
                    mode:
                        description:
                            - 'LACP mode: ignore and do not send control messages, or negotiate 802.3ad aggregation passively or actively.'
                        type: str
                        choices:
                            - static
                            - lacp-passive
                            - lacp-active
                    p2p_port:
                        description:
                            - General peer to peer tunnel port.
                        type: int
                    packet_sample_rate:
                        description:
                            - Packet sampling rate (0 - 99999 p/sec).
                        type: int
                    packet_sampler:
                        description:
                            - Enable/disable packet sampling on this interface.
                        type: str
                        choices:
                            - enabled
                            - disabled
                    poe_capable:
                        description:
                            - PoE capable.
                        type: int
                    poe_pre_standard_detection:
                        description:
                            - Enable/disable PoE pre-standard detection.
                        type: str
                        choices:
                            - enable
                            - disable
                    poe_status:
                        description:
                            - Enable/disable PoE status.
                        type: str
                        choices:
                            - enable
                            - disable
                    port_name:
                        description:
                            - Switch port name.
                        type: str
                    port_number:
                        description:
                            - Port number.
                        type: int
                    port_owner:
                        description:
                            - Switch port name.
                        type: str
                    port_prefix_type:
                        description:
                            - Port prefix type.
                        type: int
                    port_security_policy:
                        description:
                            - Switch controller authentication policy to apply to this managed switch from available options. Source switch-controller
                              .security-policy.802-1X.name switch-controller.security-policy.captive-portal.name.
                        type: str
                    port_selection_criteria:
                        description:
                            - Algorithm for aggregate port selection.
                        type: str
                        choices:
                            - src-mac
                            - dst-mac
                            - src-dst-mac
                            - src-ip
                            - dst-ip
                            - src-dst-ip
                    qos_policy:
                        description:
                            - Switch controller QoS policy from available options. Source switch-controller.qos.qos-policy.name.
                        type: str
                    sample_direction:
                        description:
                            - Packet sampling direction.
                        type: str
                        choices:
                            - tx
                            - rx
                            - both
                    sflow_counter_interval:
                        description:
                            - sFlow sampling counter polling interval (0 - 255 sec).
                        type: int
                    speed:
                        description:
                            - Switch port speed; default and available settings depend on hardware.
                        type: str
                        choices:
                            - 10half
                            - 10full
                            - 100half
                            - 100full
                            - 1000auto
                            - 1000fiber
                            - 1000full
                            - 10000
                            - 40000
                            - auto
                            - auto-module
                            - 100FX-half
                            - 100FX-full
                            - 100000full
                            - 2500auto
                            - 25000full
                            - 50000full
                            - 10000cr
                            - 10000sr
                            - 100000sr4
                            - 100000cr4
                            - 25000cr4
                            - 25000sr4
                            - 5000full
                    stacking_port:
                        description:
                            - Stacking port.
                        type: int
                    status:
                        description:
                            - 'Switch port admin status: up or down.'
                        type: str
                        choices:
                            - up
                            - down
                    sticky_mac:
                        description:
                            - Enable or disable sticky-mac on the interface.
                        type: str
                        choices:
                            - enable
                            - disable
                    storm_control_policy:
                        description:
                            - Switch controller storm control policy from available options. Source switch-controller.storm-control-policy.name.
                        type: str
                    stp_bpdu_guard:
                        description:
                            - Enable/disable STP BPDU guard on this interface.
                        type: str
                        choices:
                            - enabled
                            - disabled
                    stp_bpdu_guard_timeout:
                        description:
                            - BPDU Guard disabling protection (0 - 120 min).
                        type: int
                    stp_root_guard:
                        description:
                            - Enable/disable STP root guard on this interface.
                        type: str
                        choices:
                            - enabled
                            - disabled
                    stp_state:
                        description:
                            - Enable/disable Spanning Tree Protocol (STP) on this interface.
                        type: str
                        choices:
                            - enabled
                            - disabled
                    switch_id:
                        description:
                            - Switch id.
                        type: str
                    type:
                        description:
                            - 'Interface type: physical or trunk port.'
                        type: str
                        choices:
                            - physical
                            - trunk
                    untagged_vlans:
                        description:
                            - Configure switch port untagged vlans
                        type: list
                        suboptions:
                            vlan_name:
                                description:
                                    - VLAN name. Source system.interface.name.
                                type: str
                    vlan:
                        description:
                            - Assign switch ports to a VLAN. Source system.interface.name.
                        type: str
            pre_provisioned:
                description:
                    - Pre-provisioned managed switch.
                type: int
            qos_drop_policy:
                description:
                    - Set QoS drop-policy.
                type: str
                choices:
                    - taildrop
                    - random-early-detection
            qos_red_probability:
                description:
                    - Set QoS RED/WRED drop probability.
                type: int
            remote_log:
                description:
                    - Configure logging by FortiSwitch device to a remote syslog server.
                type: list
                suboptions:
                    csv:
                        description:
                            - Enable/disable comma-separated value (CSV) strings.
                        type: str
                        choices:
                            - enable
                            - disable
                    facility:
                        description:
                            - Facility to log to remote syslog server.
                        type: str
                        choices:
                            - kernel
                            - user
                            - mail
                            - daemon
                            - auth
                            - syslog
                            - lpr
                            - news
                            - uucp
                            - cron
                            - authpriv
                            - ftp
                            - ntp
                            - audit
                            - alert
                            - clock
                            - local0
                            - local1
                            - local2
                            - local3
                            - local4
                            - local5
                            - local6
                            - local7
                    name:
                        description:
                            - Remote log name.
                        required: true
                        type: str
                    port:
                        description:
                            - Remote syslog server listening port.
                        type: int
                    server:
                        description:
                            - IPv4 address of the remote syslog server.
                        type: str
                    severity:
                        description:
                            - Severity of logs to be transferred to remote log server.
                        type: str
                        choices:
                            - emergency
                            - alert
                            - critical
                            - error
                            - warning
                            - notification
                            - information
                            - debug
                    status:
                        description:
                            - Enable/disable logging by FortiSwitch device to a remote syslog server.
                        type: str
                        choices:
                            - enable
                            - disable
            snmp_community:
                description:
                    - Configuration method to edit Simple Network Management Protocol (SNMP) communities.
                type: list
                suboptions:
                    events:
                        description:
                            - SNMP notifications (traps) to send.
                        type: str
                        choices:
                            - cpu-high
                            - mem-low
                            - log-full
                            - intf-ip
                            - ent-conf-change
                    hosts:
                        description:
                            - Configure IPv4 SNMP managers (hosts).
                        type: list
                        suboptions:
                            id:
                                description:
                                    - Host entry ID.
                                required: true
                                type: int
                            ip:
                                description:
                                    - IPv4 address of the SNMP manager (host).
                                type: str
                    id:
                        description:
                            - SNMP community ID.
                        required: true
                        type: int
                    name:
                        description:
                            - SNMP community name.
                        type: str
                    query_v1_port:
                        description:
                            - SNMP v1 query port .
                        type: int
                    query_v1_status:
                        description:
                            - Enable/disable SNMP v1 queries.
                        type: str
                        choices:
                            - disable
                            - enable
                    query_v2c_port:
                        description:
                            - SNMP v2c query port .
                        type: int
                    query_v2c_status:
                        description:
                            - Enable/disable SNMP v2c queries.
                        type: str
                        choices:
                            - disable
                            - enable
                    status:
                        description:
                            - Enable/disable this SNMP community.
                        type: str
                        choices:
                            - disable
                            - enable
                    trap_v1_lport:
                        description:
                            - SNMP v2c trap local port .
                        type: int
                    trap_v1_rport:
                        description:
                            - SNMP v2c trap remote port .
                        type: int
                    trap_v1_status:
                        description:
                            - Enable/disable SNMP v1 traps.
                        type: str
                        choices:
                            - disable
                            - enable
                    trap_v2c_lport:
                        description:
                            - SNMP v2c trap local port .
                        type: int
                    trap_v2c_rport:
                        description:
                            - SNMP v2c trap remote port .
                        type: int
                    trap_v2c_status:
                        description:
                            - Enable/disable SNMP v2c traps.
                        type: str
                        choices:
                            - disable
                            - enable
            snmp_sysinfo:
                description:
                    - Configuration method to edit Simple Network Management Protocol (SNMP) system info.
                type: dict
                suboptions:
                    contact_info:
                        description:
                            - Contact information.
                        type: str
                    description:
                        description:
                            - System description.
                        type: str
                    engine_id:
                        description:
                            - Local SNMP engine ID string (max 24 char).
                        type: str
                    location:
                        description:
                            - System location.
                        type: str
                    status:
                        description:
                            - Enable/disable SNMP.
                        type: str
                        choices:
                            - disable
                            - enable
            snmp_trap_threshold:
                description:
                    - Configuration method to edit Simple Network Management Protocol (SNMP) trap threshold values.
                type: dict
                suboptions:
                    trap_high_cpu_threshold:
                        description:
                            - CPU usage when trap is sent.
                        type: int
                    trap_log_full_threshold:
                        description:
                            - Log disk usage when trap is sent.
                        type: int
                    trap_low_memory_threshold:
                        description:
                            - Memory usage when trap is sent.
                        type: int
            snmp_user:
                description:
                    - Configuration method to edit Simple Network Management Protocol (SNMP) users.
                type: list
                suboptions:
                    auth_proto:
                        description:
                            - Authentication protocol.
                        type: str
                        choices:
                            - md5
                            - sha
                    auth_pwd:
                        description:
                            - Password for authentication protocol.
                        type: str
                    name:
                        description:
                            - SNMP user name.
                        required: true
                        type: str
                    priv_proto:
                        description:
                            - Privacy (encryption) protocol.
                        type: str
                        choices:
                            - aes
                            - des
                    priv_pwd:
                        description:
                            - Password for privacy (encryption) protocol.
                        type: str
                    queries:
                        description:
                            - Enable/disable SNMP queries for this user.
                        type: str
                        choices:
                            - disable
                            - enable
                    query_port:
                        description:
                            - SNMPv3 query port .
                        type: int
                    security_level:
                        description:
                            - Security level for message authentication and encryption.
                        type: str
                        choices:
                            - no-auth-no-priv
                            - auth-no-priv
                            - auth-priv
            staged_image_version:
                description:
                    - Staged image version for FortiSwitch.
                type: str
            static_mac:
                description:
                    - Configuration method to edit FortiSwitch Static and Sticky MAC.
                type: list
                suboptions:
                    description:
                        description:
                            - Description.
                        type: str
                    id:
                        description:
                            - Id
                        required: true
                        type: int
                    interface:
                        description:
                            - Interface name.
                        type: str
                    mac:
                        description:
                            - MAC address.
                        type: str
                    type:
                        description:
                            - Type.
                        type: str
                        choices:
                            - static
                            - sticky
                    vlan:
                        description:
                            - Vlan. Source system.interface.name.
                        type: str
            storm_control:
                description:
                    - Configuration method to edit FortiSwitch storm control for measuring traffic activity using data rates to prevent traffic disruption.
                type: dict
                suboptions:
                    broadcast:
                        description:
                            - Enable/disable storm control to drop broadcast traffic.
                        type: str
                        choices:
                            - enable
                            - disable
                    local_override:
                        description:
                            - Enable to override global FortiSwitch storm control settings for this FortiSwitch.
                        type: str
                        choices:
                            - enable
                            - disable
                    rate:
                        description:
                            - Rate in packets per second at which storm traffic is controlled (1 - 10000000). Storm control drops excess traffic data rates
                               beyond this threshold.
                        type: int
                    unknown_multicast:
                        description:
                            - Enable/disable storm control to drop unknown multicast traffic.
                        type: str
                        choices:
                            - enable
                            - disable
                    unknown_unicast:
                        description:
                            - Enable/disable storm control to drop unknown unicast traffic.
                        type: str
                        choices:
                            - enable
                            - disable
            stp_instance:
                description:
                    - Configuration method to edit Spanning Tree Protocol (STP) instances.
                type: list
                suboptions:
                    id:
                        description:
                            - Instance ID.
                        required: true
                        type: str
                    priority:
                        description:
                            - Priority.
                        type: str
                        choices:
                            - 0
                            - 4096
                            - 8192
                            - 12288
                            - 16384
                            - 20480
                            - 24576
                            - 28672
                            - 32768
                            - 36864
                            - 40960
                            - 45056
                            - 49152
                            - 53248
                            - 57344
                            - 61440
            stp_settings:
                description:
                    - Configuration method to edit Spanning Tree Protocol (STP) settings used to prevent bridge loops.
                type: dict
                suboptions:
                    forward_time:
                        description:
                            - Period of time a port is in listening and learning state (4 - 30 sec).
                        type: int
                    hello_time:
                        description:
                            - Period of time between successive STP frame Bridge Protocol Data Units (BPDUs) sent on a port (1 - 10 sec).
                        type: int
                    local_override:
                        description:
                            - Enable to configure local STP settings that override global STP settings.
                        type: str
                        choices:
                            - enable
                            - disable
                    max_age:
                        description:
                            - Maximum time before a bridge port saves its configuration BPDU information (6 - 40 sec).
                        type: int
                    max_hops:
                        description:
                            - Maximum number of hops between the root bridge and the furthest bridge (1- 40).
                        type: int
                    name:
                        description:
                            - Name of local STP settings configuration.
                        type: str
                    pending_timer:
                        description:
                            - Pending time (1 - 15 sec).
                        type: int
                    revision:
                        description:
                            - STP revision number (0 - 65535).
                        type: int
            switch_device_tag:
                description:
                    - User definable label/tag.
                type: str
            switch_dhcp_opt43_key:
                description:
                    - DHCP option43 key.
                type: str
            switch_id:
                description:
                    - Managed-switch id.
                type: str
            switch_log:
                description:
                    - Configuration method to edit FortiSwitch logging settings (logs are transferred to and inserted into the FortiGate event log).
                type: dict
                suboptions:
                    local_override:
                        description:
                            - Enable to configure local logging settings that override global logging settings.
                        type: str
                        choices:
                            - enable
                            - disable
                    severity:
                        description:
                            - Severity of FortiSwitch logs that are added to the FortiGate event log.
                        type: str
                        choices:
                            - emergency
                            - alert
                            - critical
                            - error
                            - warning
                            - notification
                            - information
                            - debug
                    status:
                        description:
                            - Enable/disable adding FortiSwitch logs to the FortiGate event log.
                        type: str
                        choices:
                            - enable
                            - disable
            switch_profile:
                description:
                    - FortiSwitch profile. Source switch-controller.switch-profile.name.
                type: str
            type:
                description:
                    - Indication of switch type, physical or virtual.
                type: str
                choices:
                    - virtual
                    - physical
            version:
                description:
                    - FortiSwitch version.
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
  - name: Configure FortiSwitch devices that are managed by this FortiGate.
    fortios_switch_controller_managed_switch:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      switch_controller_managed_switch:
        settings_802_1X:
            link_down_auth: "set-unauth"
            local_override: "enable"
            max_reauth_attempt: "6"
            reauth_period: "7"
            tx_period: "8"
        access_profile: "<your_own_value> (source switch-controller.security-policy.local-access.name)"
        custom_command:
         -
            command_entry: "<your_own_value>"
            command_name: "<your_own_value> (source switch-controller.custom-command.command-name)"
        delayed_restart_trigger: "13"
        description: "<your_own_value>"
        directly_connected: "15"
        dynamic_capability: "16"
        dynamically_discovered: "17"
        flow_identity: "<your_own_value>"
        fsw_wan1_admin: "discovered"
        fsw_wan1_peer: "<your_own_value>"
        igmp_snooping:
            aging_time: "22"
            flood_unknown_multicast: "enable"
            local_override: "enable"
        ip_source_guard:
         -
            binding_entry:
             -
                entry_name: "<your_own_value>"
                ip: "<your_own_value>"
                mac: "<your_own_value>"
            description: "<your_own_value>"
            port: "<your_own_value>"
        l3_discovered: "32"
        mclag_igmp_snooping_aware: "enable"
        mirror:
         -
            dst: "<your_own_value>"
            name: "default_name_36"
            src_egress:
             -
                name: "default_name_38"
            src_ingress:
             -
                name: "default_name_40"
            status: "active"
            switching_packet: "enable"
        name: "default_name_43"
        override_snmp_community: "enable"
        override_snmp_sysinfo: "disable"
        override_snmp_trap_threshold: "enable"
        override_snmp_user: "enable"
        owner_vdom: "<your_own_value>"
        poe_detection_type: "49"
        poe_pre_standard_detection: "enable"
        ports:
         -
            access_mode: "normal"
            allowed_vlans:
             -
                vlan_name: "<your_own_value> (source system.interface.name)"
            allowed_vlans_all: "enable"
            arp_inspection_trust: "untrusted"
            bundle: "enable"
            description: "<your_own_value>"
            dhcp_snoop_option82_trust: "enable"
            dhcp_snooping: "untrusted"
            discard_mode: "none"
            edge_port: "enable"
            export_tags:
             -
                tag_name: "<your_own_value> (source switch-controller.switch-interface-tag.name)"
            export_to: "<your_own_value> (source system.vdom.name)"
            export_to_pool: "<your_own_value> (source switch-controller.virtual-port-pool.name)"
            fgt_peer_device_name: "<your_own_value>"
            fgt_peer_port_name: "<your_own_value>"
            fiber_port: "69"
            flags: "70"
            fortilink_port: "71"
            igmps_flood_reports: "enable"
            igmps_flood_traffic: "enable"
            ip_source_guard: "disable"
            isl_local_trunk_name: "<your_own_value>"
            isl_peer_device_name: "<your_own_value>"
            isl_peer_port_name: "<your_own_value>"
            lacp_speed: "slow"
            learning_limit: "79"
            lldp_profile: "<your_own_value> (source switch-controller.lldp-profile.name)"
            lldp_status: "disable"
            loop_guard: "enabled"
            loop_guard_timeout: "83"
            mac_addr: "<your_own_value>"
            max_bundle: "85"
            mclag: "enable"
            mclag_icl_port: "87"
            member_withdrawal_behavior: "forward"
            members:
             -
                member_name: "<your_own_value>"
            min_bundle: "91"
            mode: "static"
            p2p_port: "93"
            packet_sample_rate: "94"
            packet_sampler: "enabled"
            poe_capable: "96"
            poe_pre_standard_detection: "enable"
            poe_status: "enable"
            port_name: "<your_own_value>"
            port_number: "100"
            port_owner: "<your_own_value>"
            port_prefix_type: "102"
            port_security_policy: "<your_own_value> (source switch-controller.security-policy.802-1X.name switch-controller.security-policy.captive-portal
              .name)"
            port_selection_criteria: "src-mac"
            qos_policy: "<your_own_value> (source switch-controller.qos.qos-policy.name)"
            sample_direction: "tx"
            sflow_counter_interval: "107"
            speed: "10half"
            stacking_port: "109"
            status: "up"
            sticky_mac: "enable"
            storm_control_policy: "<your_own_value> (source switch-controller.storm-control-policy.name)"
            stp_bpdu_guard: "enabled"
            stp_bpdu_guard_timeout: "114"
            stp_root_guard: "enabled"
            stp_state: "enabled"
            switch_id: "<your_own_value>"
            type: "physical"
            untagged_vlans:
             -
                vlan_name: "<your_own_value> (source system.interface.name)"
            vlan: "<your_own_value> (source system.interface.name)"
        pre_provisioned: "122"
        qos_drop_policy: "taildrop"
        qos_red_probability: "124"
        remote_log:
         -
            csv: "enable"
            facility: "kernel"
            name: "default_name_128"
            port: "129"
            server: "192.168.100.40"
            severity: "emergency"
            status: "enable"
        snmp_community:
         -
            events: "cpu-high"
            hosts:
             -
                id:  "136"
                ip: "<your_own_value>"
            id:  "138"
            name: "default_name_139"
            query_v1_port: "140"
            query_v1_status: "disable"
            query_v2c_port: "142"
            query_v2c_status: "disable"
            status: "disable"
            trap_v1_lport: "145"
            trap_v1_rport: "146"
            trap_v1_status: "disable"
            trap_v2c_lport: "148"
            trap_v2c_rport: "149"
            trap_v2c_status: "disable"
        snmp_sysinfo:
            contact_info: "<your_own_value>"
            description: "<your_own_value>"
            engine_id: "<your_own_value>"
            location: "<your_own_value>"
            status: "disable"
        snmp_trap_threshold:
            trap_high_cpu_threshold: "158"
            trap_log_full_threshold: "159"
            trap_low_memory_threshold: "160"
        snmp_user:
         -
            auth_proto: "md5"
            auth_pwd: "<your_own_value>"
            name: "default_name_164"
            priv_proto: "aes"
            priv_pwd: "<your_own_value>"
            queries: "disable"
            query_port: "168"
            security_level: "no-auth-no-priv"
        staged_image_version: "<your_own_value>"
        static_mac:
         -
            description: "<your_own_value>"
            id:  "173"
            interface: "<your_own_value>"
            mac: "<your_own_value>"
            type: "static"
            vlan: "<your_own_value> (source system.interface.name)"
        storm_control:
            broadcast: "enable"
            local_override: "enable"
            rate: "181"
            unknown_multicast: "enable"
            unknown_unicast: "enable"
        stp_instance:
         -
            id:  "185"
            priority: "0"
        stp_settings:
            forward_time: "188"
            hello_time: "189"
            local_override: "enable"
            max_age: "191"
            max_hops: "192"
            name: "default_name_193"
            pending_timer: "194"
            revision: "195"
        switch_device_tag: "<your_own_value>"
        switch_dhcp_opt43_key: "<your_own_value>"
        switch_id: "<your_own_value>"
        switch_log:
            local_override: "enable"
            severity: "emergency"
            status: "enable"
        switch_profile: "<your_own_value> (source switch-controller.switch-profile.name)"
        type: "virtual"
        version: "205"

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


def filter_switch_controller_managed_switch_data(json):
    option_list = ['settings_802_1X', 'access_profile', 'custom_command',
                   'delayed_restart_trigger', 'description', 'directly_connected',
                   'dynamic_capability', 'dynamically_discovered', 'flow_identity',
                   'fsw_wan1_admin', 'fsw_wan1_peer', 'igmp_snooping',
                   'ip_source_guard', 'l3_discovered', 'mclag_igmp_snooping_aware',
                   'mirror', 'name', 'override_snmp_community',
                   'override_snmp_sysinfo', 'override_snmp_trap_threshold', 'override_snmp_user',
                   'owner_vdom', 'poe_detection_type', 'poe_pre_standard_detection',
                   'ports', 'pre_provisioned', 'qos_drop_policy',
                   'qos_red_probability', 'remote_log', 'snmp_community',
                   'snmp_sysinfo', 'snmp_trap_threshold', 'snmp_user',
                   'staged_image_version', 'static_mac', 'storm_control',
                   'stp_instance', 'stp_settings', 'switch_device_tag',
                   'switch_dhcp_opt43_key', 'switch_id', 'switch_log',
                   'switch_profile', 'type', 'version']
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


def valid_attr_to_invalid_attr(data):
    specillist = {"802_1X_settings": "settings_802_1X"}

    for k, v in specillist.items():
        if v == data:
            return k

    return data


def valid_attr_to_invalid_attrs(data):
    if isinstance(data, list):
        for elem in data:
            elem = valid_attr_to_invalid_attrs(elem)
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[valid_attr_to_invalid_attr(k)] = valid_attr_to_invalid_attrs(v)
        data = new_data

    return data


def switch_controller_managed_switch(data, fos):
    vdom = data['vdom']
    if 'state' in data and data['state']:
        state = data['state']
    elif 'state' in data['switch_controller_managed_switch'] and data['switch_controller_managed_switch']['state']:
        state = data['switch_controller_managed_switch']['state']
    else:
        state = True
    switch_controller_managed_switch_data = data['switch_controller_managed_switch']
    filtered_data = underscore_to_hyphen(filter_switch_controller_managed_switch_data(switch_controller_managed_switch_data))
    converted_data = valid_attr_to_invalid_attrs(filtered_data)

    if state == "present":
        return fos.set('switch-controller',
                       'managed-switch',
                       data=converted_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('switch-controller',
                          'managed-switch',
                          mkey=filtered_data['switch-id'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_switch_controller(data, fos):

    if data['switch_controller_managed_switch']:
        resp = switch_controller_managed_switch(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('switch_controller_managed_switch'))

    return not is_successful_status(resp), \
        resp['status'] == "success" and \
        (resp['revision_changed'] if 'revision_changed' in resp else True), \
        resp


def main():
    mkeyname = 'switch-id'
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "state": {"required": False, "type": "str",
                  "choices": ["present", "absent"]},
        "switch_controller_managed_switch": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "state": {"required": False, "type": "str",
                          "choices": ["present", "absent"]},
                "settings_802_1X": {"required": False, "type": "dict",
                                    "options": {
                                        "link_down_auth": {"required": False, "type": "str",
                                                           "choices": ["set-unauth",
                                                                       "no-action"]},
                                        "local_override": {"required": False, "type": "str",
                                                           "choices": ["enable",
                                                                       "disable"]},
                                        "max_reauth_attempt": {"required": False, "type": "int"},
                                        "reauth_period": {"required": False, "type": "int"},
                                        "tx_period": {"required": False, "type": "int"}
                                    }},
                "access_profile": {"required": False, "type": "str"},
                "custom_command": {"required": False, "type": "list",
                                   "options": {
                                       "command_entry": {"required": False, "type": "str"},
                                       "command_name": {"required": False, "type": "str"}
                                   }},
                "delayed_restart_trigger": {"required": False, "type": "int"},
                "description": {"required": False, "type": "str"},
                "directly_connected": {"required": False, "type": "int"},
                "dynamic_capability": {"required": False, "type": "int"},
                "dynamically_discovered": {"required": False, "type": "int"},
                "flow_identity": {"required": False, "type": "str"},
                "fsw_wan1_admin": {"required": False, "type": "str",
                                   "choices": ["discovered",
                                               "disable",
                                               "enable"]},
                "fsw_wan1_peer": {"required": False, "type": "str"},
                "igmp_snooping": {"required": False, "type": "dict",
                                  "options": {
                                      "aging_time": {"required": False, "type": "int"},
                                      "flood_unknown_multicast": {"required": False, "type": "str",
                                                                  "choices": ["enable",
                                                                              "disable"]},
                                      "local_override": {"required": False, "type": "str",
                                                         "choices": ["enable",
                                                                     "disable"]}
                                  }},
                "ip_source_guard": {"required": False, "type": "list",
                                    "options": {
                                        "binding_entry": {"required": False, "type": "list",
                                                          "options": {
                                                              "entry_name": {"required": False, "type": "str"},
                                                              "ip": {"required": False, "type": "str"},
                                                              "mac": {"required": False, "type": "str"}
                                                          }},
                                        "description": {"required": False, "type": "str"},
                                        "port": {"required": True, "type": "str"}
                                    }},
                "l3_discovered": {"required": False, "type": "int"},
                "mclag_igmp_snooping_aware": {"required": False, "type": "str",
                                              "choices": ["enable",
                                                          "disable"]},
                "mirror": {"required": False, "type": "list",
                           "options": {
                               "dst": {"required": False, "type": "str"},
                               "name": {"required": True, "type": "str"},
                               "src_egress": {"required": False, "type": "list",
                                              "options": {
                                                  "name": {"required": True, "type": "str"}
                                              }},
                               "src_ingress": {"required": False, "type": "list",
                                               "options": {
                                                   "name": {"required": True, "type": "str"}
                                               }},
                               "status": {"required": False, "type": "str",
                                          "choices": ["active",
                                                      "inactive"]},
                               "switching_packet": {"required": False, "type": "str",
                                                    "choices": ["enable",
                                                                "disable"]}
                           }},
                "name": {"required": False, "type": "str"},
                "override_snmp_community": {"required": False, "type": "str",
                                            "choices": ["enable",
                                                        "disable"]},
                "override_snmp_sysinfo": {"required": False, "type": "str",
                                          "choices": ["disable",
                                                      "enable"]},
                "override_snmp_trap_threshold": {"required": False, "type": "str",
                                                 "choices": ["enable",
                                                             "disable"]},
                "override_snmp_user": {"required": False, "type": "str",
                                       "choices": ["enable",
                                                   "disable"]},
                "owner_vdom": {"required": False, "type": "str"},
                "poe_detection_type": {"required": False, "type": "int"},
                "poe_pre_standard_detection": {"required": False, "type": "str",
                                               "choices": ["enable",
                                                           "disable"]},
                "ports": {"required": False, "type": "list",
                          "options": {
                              "access_mode": {"required": False, "type": "str",
                                              "choices": ["normal",
                                                          "nac"]},
                              "allowed_vlans": {"required": False, "type": "list",
                                                "options": {
                                                    "vlan_name": {"required": False, "type": "str"}
                                                }},
                              "allowed_vlans_all": {"required": False, "type": "str",
                                                    "choices": ["enable",
                                                                "disable"]},
                              "arp_inspection_trust": {"required": False, "type": "str",
                                                       "choices": ["untrusted",
                                                                   "trusted"]},
                              "bundle": {"required": False, "type": "str",
                                         "choices": ["enable",
                                                     "disable"]},
                              "description": {"required": False, "type": "str"},
                              "dhcp_snoop_option82_trust": {"required": False, "type": "str",
                                                            "choices": ["enable",
                                                                        "disable"]},
                              "dhcp_snooping": {"required": False, "type": "str",
                                                "choices": ["untrusted",
                                                            "trusted"]},
                              "discard_mode": {"required": False, "type": "str",
                                               "choices": ["none",
                                                           "all-untagged",
                                                           "all-tagged"]},
                              "edge_port": {"required": False, "type": "str",
                                            "choices": ["enable",
                                                        "disable"]},
                              "export_tags": {"required": False, "type": "list",
                                              "options": {
                                                  "tag_name": {"required": False, "type": "str"}
                                              }},
                              "export_to": {"required": False, "type": "str"},
                              "export_to_pool": {"required": False, "type": "str"},
                              "fgt_peer_device_name": {"required": False, "type": "str"},
                              "fgt_peer_port_name": {"required": False, "type": "str"},
                              "fiber_port": {"required": False, "type": "int"},
                              "flags": {"required": False, "type": "int"},
                              "fortilink_port": {"required": False, "type": "int"},
                              "igmps_flood_reports": {"required": False, "type": "str",
                                                      "choices": ["enable",
                                                                  "disable"]},
                              "igmps_flood_traffic": {"required": False, "type": "str",
                                                      "choices": ["enable",
                                                                  "disable"]},
                              "ip_source_guard": {"required": False, "type": "str",
                                                  "choices": ["disable",
                                                              "enable"]},
                              "isl_local_trunk_name": {"required": False, "type": "str"},
                              "isl_peer_device_name": {"required": False, "type": "str"},
                              "isl_peer_port_name": {"required": False, "type": "str"},
                              "lacp_speed": {"required": False, "type": "str",
                                             "choices": ["slow",
                                                         "fast"]},
                              "learning_limit": {"required": False, "type": "int"},
                              "lldp_profile": {"required": False, "type": "str"},
                              "lldp_status": {"required": False, "type": "str",
                                              "choices": ["disable",
                                                          "rx-only",
                                                          "tx-only",
                                                          "tx-rx"]},
                              "loop_guard": {"required": False, "type": "str",
                                             "choices": ["enabled",
                                                         "disabled"]},
                              "loop_guard_timeout": {"required": False, "type": "int"},
                              "mac_addr": {"required": False, "type": "str"},
                              "max_bundle": {"required": False, "type": "int"},
                              "mclag": {"required": False, "type": "str",
                                        "choices": ["enable",
                                                    "disable"]},
                              "mclag_icl_port": {"required": False, "type": "int"},
                              "member_withdrawal_behavior": {"required": False, "type": "str",
                                                             "choices": ["forward",
                                                                         "block"]},
                              "members": {"required": False, "type": "list",
                                          "options": {
                                              "member_name": {"required": False, "type": "str"}
                                          }},
                              "min_bundle": {"required": False, "type": "int"},
                              "mode": {"required": False, "type": "str",
                                       "choices": ["static",
                                                   "lacp-passive",
                                                   "lacp-active"]},
                              "p2p_port": {"required": False, "type": "int"},
                              "packet_sample_rate": {"required": False, "type": "int"},
                              "packet_sampler": {"required": False, "type": "str",
                                                 "choices": ["enabled",
                                                             "disabled"]},
                              "poe_capable": {"required": False, "type": "int"},
                              "poe_pre_standard_detection": {"required": False, "type": "str",
                                                             "choices": ["enable",
                                                                         "disable"]},
                              "poe_status": {"required": False, "type": "str",
                                             "choices": ["enable",
                                                         "disable"]},
                              "port_name": {"required": False, "type": "str"},
                              "port_number": {"required": False, "type": "int"},
                              "port_owner": {"required": False, "type": "str"},
                              "port_prefix_type": {"required": False, "type": "int"},
                              "port_security_policy": {"required": False, "type": "str"},
                              "port_selection_criteria": {"required": False, "type": "str",
                                                          "choices": ["src-mac",
                                                                      "dst-mac",
                                                                      "src-dst-mac",
                                                                      "src-ip",
                                                                      "dst-ip",
                                                                      "src-dst-ip"]},
                              "qos_policy": {"required": False, "type": "str"},
                              "sample_direction": {"required": False, "type": "str",
                                                   "choices": ["tx",
                                                               "rx",
                                                               "both"]},
                              "sflow_counter_interval": {"required": False, "type": "int"},
                              "speed": {"required": False, "type": "str",
                                        "choices": ["10half",
                                                    "10full",
                                                    "100half",
                                                    "100full",
                                                    "1000auto",
                                                    "1000fiber",
                                                    "1000full",
                                                    "10000",
                                                    "40000",
                                                    "auto",
                                                    "auto-module",
                                                    "100FX-half",
                                                    "100FX-full",
                                                    "100000full",
                                                    "2500auto",
                                                    "25000full",
                                                    "50000full",
                                                    "10000cr",
                                                    "10000sr",
                                                    "100000sr4",
                                                    "100000cr4",
                                                    "25000cr4",
                                                    "25000sr4",
                                                    "5000full"]},
                              "stacking_port": {"required": False, "type": "int"},
                              "status": {"required": False, "type": "str",
                                         "choices": ["up",
                                                     "down"]},
                              "sticky_mac": {"required": False, "type": "str",
                                             "choices": ["enable",
                                                         "disable"]},
                              "storm_control_policy": {"required": False, "type": "str"},
                              "stp_bpdu_guard": {"required": False, "type": "str",
                                                 "choices": ["enabled",
                                                             "disabled"]},
                              "stp_bpdu_guard_timeout": {"required": False, "type": "int"},
                              "stp_root_guard": {"required": False, "type": "str",
                                                 "choices": ["enabled",
                                                             "disabled"]},
                              "stp_state": {"required": False, "type": "str",
                                            "choices": ["enabled",
                                                        "disabled"]},
                              "switch_id": {"required": False, "type": "str"},
                              "type": {"required": False, "type": "str",
                                       "choices": ["physical",
                                                   "trunk"]},
                              "untagged_vlans": {"required": False, "type": "list",
                                                 "options": {
                                                     "vlan_name": {"required": False, "type": "str"}
                                                 }},
                              "vlan": {"required": False, "type": "str"}
                          }},
                "pre_provisioned": {"required": False, "type": "int"},
                "qos_drop_policy": {"required": False, "type": "str",
                                    "choices": ["taildrop",
                                                "random-early-detection"]},
                "qos_red_probability": {"required": False, "type": "int"},
                "remote_log": {"required": False, "type": "list",
                               "options": {
                                   "csv": {"required": False, "type": "str",
                                           "choices": ["enable",
                                                       "disable"]},
                                   "facility": {"required": False, "type": "str",
                                                "choices": ["kernel",
                                                            "user",
                                                            "mail",
                                                            "daemon",
                                                            "auth",
                                                            "syslog",
                                                            "lpr",
                                                            "news",
                                                            "uucp",
                                                            "cron",
                                                            "authpriv",
                                                            "ftp",
                                                            "ntp",
                                                            "audit",
                                                            "alert",
                                                            "clock",
                                                            "local0",
                                                            "local1",
                                                            "local2",
                                                            "local3",
                                                            "local4",
                                                            "local5",
                                                            "local6",
                                                            "local7"]},
                                   "name": {"required": True, "type": "str"},
                                   "port": {"required": False, "type": "int"},
                                   "server": {"required": False, "type": "str"},
                                   "severity": {"required": False, "type": "str",
                                                "choices": ["emergency",
                                                            "alert",
                                                            "critical",
                                                            "error",
                                                            "warning",
                                                            "notification",
                                                            "information",
                                                            "debug"]},
                                   "status": {"required": False, "type": "str",
                                              "choices": ["enable",
                                                          "disable"]}
                               }},
                "snmp_community": {"required": False, "type": "list",
                                   "options": {
                                       "events": {"required": False, "type": "str",
                                                  "choices": ["cpu-high",
                                                              "mem-low",
                                                              "log-full",
                                                              "intf-ip",
                                                              "ent-conf-change"]},
                                       "hosts": {"required": False, "type": "list",
                                                 "options": {
                                                     "id": {"required": True, "type": "int"},
                                                     "ip": {"required": False, "type": "str"}
                                                 }},
                                       "id": {"required": True, "type": "int"},
                                       "name": {"required": False, "type": "str"},
                                       "query_v1_port": {"required": False, "type": "int"},
                                       "query_v1_status": {"required": False, "type": "str",
                                                           "choices": ["disable",
                                                                       "enable"]},
                                       "query_v2c_port": {"required": False, "type": "int"},
                                       "query_v2c_status": {"required": False, "type": "str",
                                                            "choices": ["disable",
                                                                        "enable"]},
                                       "status": {"required": False, "type": "str",
                                                  "choices": ["disable",
                                                              "enable"]},
                                       "trap_v1_lport": {"required": False, "type": "int"},
                                       "trap_v1_rport": {"required": False, "type": "int"},
                                       "trap_v1_status": {"required": False, "type": "str",
                                                          "choices": ["disable",
                                                                      "enable"]},
                                       "trap_v2c_lport": {"required": False, "type": "int"},
                                       "trap_v2c_rport": {"required": False, "type": "int"},
                                       "trap_v2c_status": {"required": False, "type": "str",
                                                           "choices": ["disable",
                                                                       "enable"]}
                                   }},
                "snmp_sysinfo": {"required": False, "type": "dict",
                                 "options": {
                                     "contact_info": {"required": False, "type": "str"},
                                     "description": {"required": False, "type": "str"},
                                     "engine_id": {"required": False, "type": "str"},
                                     "location": {"required": False, "type": "str"},
                                     "status": {"required": False, "type": "str",
                                                "choices": ["disable",
                                                            "enable"]}
                                 }},
                "snmp_trap_threshold": {"required": False, "type": "dict",
                                        "options": {
                                            "trap_high_cpu_threshold": {"required": False, "type": "int"},
                                            "trap_log_full_threshold": {"required": False, "type": "int"},
                                            "trap_low_memory_threshold": {"required": False, "type": "int"}
                                        }},
                "snmp_user": {"required": False, "type": "list",
                              "options": {
                                  "auth_proto": {"required": False, "type": "str",
                                                 "choices": ["md5",
                                                             "sha"]},
                                  "auth_pwd": {"required": False, "type": "str"},
                                  "name": {"required": True, "type": "str"},
                                  "priv_proto": {"required": False, "type": "str",
                                                 "choices": ["aes",
                                                             "des"]},
                                  "priv_pwd": {"required": False, "type": "str"},
                                  "queries": {"required": False, "type": "str",
                                              "choices": ["disable",
                                                          "enable"]},
                                  "query_port": {"required": False, "type": "int"},
                                  "security_level": {"required": False, "type": "str",
                                                     "choices": ["no-auth-no-priv",
                                                                 "auth-no-priv",
                                                                 "auth-priv"]}
                              }},
                "staged_image_version": {"required": False, "type": "str"},
                "static_mac": {"required": False, "type": "list",
                               "options": {
                                   "description": {"required": False, "type": "str"},
                                   "id": {"required": True, "type": "int"},
                                   "interface": {"required": False, "type": "str"},
                                   "mac": {"required": False, "type": "str"},
                                   "type": {"required": False, "type": "str",
                                            "choices": ["static",
                                                        "sticky"]},
                                   "vlan": {"required": False, "type": "str"}
                               }},
                "storm_control": {"required": False, "type": "dict",
                                  "options": {
                                      "broadcast": {"required": False, "type": "str",
                                                    "choices": ["enable",
                                                                "disable"]},
                                      "local_override": {"required": False, "type": "str",
                                                         "choices": ["enable",
                                                                     "disable"]},
                                      "rate": {"required": False, "type": "int"},
                                      "unknown_multicast": {"required": False, "type": "str",
                                                            "choices": ["enable",
                                                                        "disable"]},
                                      "unknown_unicast": {"required": False, "type": "str",
                                                          "choices": ["enable",
                                                                      "disable"]}
                                  }},
                "stp_instance": {"required": False, "type": "list",
                                 "options": {
                                     "id": {"required": True, "type": "str"},
                                     "priority": {"required": False, "type": "str",
                                                  "choices": ["0",
                                                              "4096",
                                                              "8192",
                                                              "12288",
                                                              "16384",
                                                              "20480",
                                                              "24576",
                                                              "28672",
                                                              "32768",
                                                              "36864",
                                                              "40960",
                                                              "45056",
                                                              "49152",
                                                              "53248",
                                                              "57344",
                                                              "61440"]}
                                 }},
                "stp_settings": {"required": False, "type": "dict",
                                 "options": {
                                     "forward_time": {"required": False, "type": "int"},
                                     "hello_time": {"required": False, "type": "int"},
                                     "local_override": {"required": False, "type": "str",
                                                        "choices": ["enable",
                                                                    "disable"]},
                                     "max_age": {"required": False, "type": "int"},
                                     "max_hops": {"required": False, "type": "int"},
                                     "name": {"required": False, "type": "str"},
                                     "pending_timer": {"required": False, "type": "int"},
                                     "revision": {"required": False, "type": "int"}
                                 }},
                "switch_device_tag": {"required": False, "type": "str"},
                "switch_dhcp_opt43_key": {"required": False, "type": "str"},
                "switch_id": {"required": False, "type": "str"},
                "switch_log": {"required": False, "type": "dict",
                               "options": {
                                   "local_override": {"required": False, "type": "str",
                                                      "choices": ["enable",
                                                                  "disable"]},
                                   "severity": {"required": False, "type": "str",
                                                "choices": ["emergency",
                                                            "alert",
                                                            "critical",
                                                            "error",
                                                            "warning",
                                                            "notification",
                                                            "information",
                                                            "debug"]},
                                   "status": {"required": False, "type": "str",
                                              "choices": ["enable",
                                                          "disable"]}
                               }},
                "switch_profile": {"required": False, "type": "str"},
                "type": {"required": False, "type": "str",
                         "choices": ["virtual",
                                     "physical"]},
                "version": {"required": False, "type": "int"}

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

        is_error, has_changed, result = fortios_switch_controller(module.params, fos)
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
