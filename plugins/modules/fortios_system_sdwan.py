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
module: fortios_system_sdwan
short_description: Configure redundant Internet connections with multiple outbound links and health-check profiles in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and sdwan category.
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

    system_sdwan:
        description:
            - Configure redundant Internet connections with multiple outbound links and health-check profiles.
        default: null
        type: dict
        suboptions:
            duplication:
                description:
                    - Create SD-WAN duplication rule.
                type: list
                elements: dict
                suboptions:
                    dstaddr:
                        description:
                            - Destination address or address group names.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Address or address group name. Source firewall.address.name firewall.addrgrp.name.
                                type: str
                    dstaddr6:
                        description:
                            - Destination address6 or address6 group names.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Address6 or address6 group name. Source firewall.address6.name firewall.addrgrp6.name.
                                type: str
                    dstintf:
                        description:
                            - Outgoing (egress) interfaces or zones.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Interface, zone or SDWAN zone name. Source system.interface.name system.zone.name system.sdwan.zone.name.
                                type: str
                    id:
                        description:
                            - Duplication rule ID (1 - 255).
                        type: int
                    packet_de_duplication:
                        description:
                            - Enable/disable discarding of packets that have been duplicated.
                        type: str
                        choices:
                            - enable
                            - disable
                    packet_duplication:
                        description:
                            - Configure packet duplication method.
                        type: str
                        choices:
                            - disable
                            - force
                            - on-demand
                    service:
                        description:
                            - Service and service group name.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Service and service group name. Source firewall.service.custom.name firewall.service.group.name.
                                type: str
                    service_id:
                        description:
                            - SD-WAN service rule ID list.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - SD-WAN service rule ID. Source system.sdwan.service.id.
                                type: int
                    sla_match_service:
                        description:
                            - Enable/disable packet duplication matching health-check SLAs in service rule.
                        type: str
                        choices:
                            - enable
                            - disable
                    srcaddr:
                        description:
                            - Source address or address group names.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Address or address group name. Source firewall.address.name firewall.addrgrp.name.
                                type: str
                    srcaddr6:
                        description:
                            - Source address6 or address6 group names.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Address6 or address6 group name. Source firewall.address6.name firewall.addrgrp6.name.
                                type: str
                    srcintf:
                        description:
                            - Incoming (ingress) interfaces or zones.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Interface, zone or SDWAN zone name. Source system.interface.name system.zone.name system.sdwan.zone.name.
                                type: str
            duplication_max_num:
                description:
                    - Maximum number of interface members a packet is duplicated in the SD-WAN zone (2 - 4).
                type: int
            fail_alert_interfaces:
                description:
                    - Physical interfaces that will be alerted.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Physical interface name. Source system.interface.name.
                        type: str
            fail_detect:
                description:
                    - Enable/disable SD-WAN Internet connection status checking (failure detection).
                type: str
                choices:
                    - enable
                    - disable
            health_check:
                description:
                    - SD-WAN status checking or health checking. Identify a server on the Internet and determine how SD-WAN verifies that the FortiGate can
                       communicate with it.
                type: list
                elements: dict
                suboptions:
                    addr_mode:
                        description:
                            - Address mode (IPv4 or IPv6).
                        type: str
                        choices:
                            - ipv4
                            - ipv6
                    detect_mode:
                        description:
                            - The mode determining how to detect the server.
                        type: str
                        choices:
                            - active
                            - passive
                            - prefer-passive
                    diffservcode:
                        description:
                            - Differentiated services code point (DSCP) in the IP header of the probe packet.
                        type: str
                    dns_match_ip:
                        description:
                            - Response IP expected from DNS server if the protocol is DNS.
                        type: str
                    dns_request_domain:
                        description:
                            - Fully qualified domain name to resolve for the DNS probe.
                        type: str
                    failtime:
                        description:
                            - Number of failures before server is considered lost (1 - 3600).
                        type: int
                    ftp_file:
                        description:
                            - Full path and file name on the FTP server to download for FTP health-check to probe.
                        type: str
                    ftp_mode:
                        description:
                            - FTP mode.
                        type: str
                        choices:
                            - passive
                            - port
                    ha_priority:
                        description:
                            - HA election priority (1 - 50).
                        type: int
                    http_agent:
                        description:
                            - String in the http-agent field in the HTTP header.
                        type: str
                    http_get:
                        description:
                            - URL used to communicate with the server if the protocol if the protocol is HTTP.
                        type: str
                    http_match:
                        description:
                            - Response string expected from the server if the protocol is HTTP.
                        type: str
                    interval:
                        description:
                            - Status check interval in milliseconds, or the time between attempting to connect to the server (500 - 3600*1000 msec).
                        type: int
                    members:
                        description:
                            - Member sequence number list.
                        type: list
                        elements: dict
                        suboptions:
                            seq_num:
                                description:
                                    - Member sequence number. Source system.sdwan.members.seq-num.
                                type: int
                    mos_codec:
                        description:
                            - Codec to use for MOS calculation .
                        type: str
                        choices:
                            - g711
                            - g722
                            - g729
                    name:
                        description:
                            - Status check or health check name.
                        type: str
                    packet_size:
                        description:
                            - Packet size of a TWAMP test session.
                        type: int
                    password:
                        description:
                            - TWAMP controller password in authentication mode.
                        type: str
                    port:
                        description:
                            - 'Port number used to communicate with the server over the selected protocol (0 - 65535).'
                        type: int
                    probe_count:
                        description:
                            - Number of most recent probes that should be used to calculate latency and jitter (5 - 30).
                        type: int
                    probe_packets:
                        description:
                            - Enable/disable transmission of probe packets.
                        type: str
                        choices:
                            - disable
                            - enable
                    probe_timeout:
                        description:
                            - Time to wait before a probe packet is considered lost (500 - 3600*1000 msec).
                        type: int
                    protocol:
                        description:
                            - Protocol used to determine if the FortiGate can communicate with the server.
                        type: str
                        choices:
                            - ping
                            - tcp-echo
                            - udp-echo
                            - http
                            - twamp
                            - dns
                            - tcp-connect
                            - ftp
                            - ping6
                    quality_measured_method:
                        description:
                            - Method to measure the quality of tcp-connect.
                        type: str
                        choices:
                            - half-open
                            - half-close
                    recoverytime:
                        description:
                            - Number of successful responses received before server is considered recovered (1 - 3600).
                        type: int
                    security_mode:
                        description:
                            - Twamp controller security mode.
                        type: str
                        choices:
                            - none
                            - authentication
                    server:
                        description:
                            - IP address or FQDN name of the server.
                        type: str
                    sla:
                        description:
                            - Service level agreement (SLA).
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - SLA ID.
                                type: int
                            jitter_threshold:
                                description:
                                    - Jitter for SLA to make decision in milliseconds. (0 - 10000000).
                                type: int
                            latency_threshold:
                                description:
                                    - Latency for SLA to make decision in milliseconds. (0 - 10000000).
                                type: int
                            link_cost_factor:
                                description:
                                    - Criteria on which to base link selection.
                                type: str
                                choices:
                                    - latency
                                    - jitter
                                    - packet-loss
                                    - mos
                            mos_threshold:
                                description:
                                    - Minimum Mean Opinion Score for SLA to be marked as pass. (1.0 - 5.0).
                                type: str
                            packetloss_threshold:
                                description:
                                    - Packet loss for SLA to make decision in percentage. (0 - 100).
                                type: int
                    sla_fail_log_period:
                        description:
                            - Time interval in seconds that SLA fail log messages will be generated (0 - 3600).
                        type: int
                    sla_pass_log_period:
                        description:
                            - Time interval in seconds that SLA pass log messages will be generated (0 - 3600).
                        type: int
                    source:
                        description:
                            - Source IP address used in the health-check packet to the server.
                        type: str
                    system_dns:
                        description:
                            - Enable/disable system DNS as the probe server.
                        type: str
                        choices:
                            - disable
                            - enable
                    threshold_alert_jitter:
                        description:
                            - Alert threshold for jitter (ms).
                        type: int
                    threshold_alert_latency:
                        description:
                            - Alert threshold for latency (ms).
                        type: int
                    threshold_alert_packetloss:
                        description:
                            - Alert threshold for packet loss (percentage).
                        type: int
                    threshold_warning_jitter:
                        description:
                            - Warning threshold for jitter (ms).
                        type: int
                    threshold_warning_latency:
                        description:
                            - Warning threshold for latency (ms).
                        type: int
                    threshold_warning_packetloss:
                        description:
                            - Warning threshold for packet loss (percentage).
                        type: int
                    update_cascade_interface:
                        description:
                            - Enable/disable update cascade interface.
                        type: str
                        choices:
                            - enable
                            - disable
                    update_static_route:
                        description:
                            - Enable/disable updating the static route.
                        type: str
                        choices:
                            - enable
                            - disable
                    user:
                        description:
                            - The user name to access probe server.
                        type: str
                    vrf:
                        description:
                            - Virtual Routing Forwarding ID.
                        type: int
            load_balance_mode:
                description:
                    - Algorithm or mode to use for load balancing Internet traffic to SD-WAN members.
                type: str
                choices:
                    - source-ip-based
                    - weight-based
                    - usage-based
                    - source-dest-ip-based
                    - measured-volume-based
            members:
                description:
                    - FortiGate interfaces added to the SD-WAN.
                type: list
                elements: dict
                suboptions:
                    comment:
                        description:
                            - Comments.
                        type: str
                    cost:
                        description:
                            - Cost of this interface for services in SLA mode (0 - 4294967295).
                        type: int
                    gateway:
                        description:
                            - The default gateway for this interface. Usually the default gateway of the Internet service provider that this interface is
                               connected to.
                        type: str
                    gateway6:
                        description:
                            - IPv6 gateway.
                        type: str
                    ingress_spillover_threshold:
                        description:
                            - Ingress spillover threshold for this interface (0 - 16776000 kbit/s). When this traffic volume threshold is reached, new
                               sessions spill over to other interfaces in the SD-WAN.
                        type: int
                    interface:
                        description:
                            - Interface name. Source system.interface.name.
                        type: str
                    priority:
                        description:
                            - Priority of the interface for IPv4 (1 - 65535). Used for SD-WAN rules or priority rules.
                        type: int
                    priority6:
                        description:
                            - Priority of the interface for IPv6 (1 - 65535). Used for SD-WAN rules or priority rules.
                        type: int
                    seq_num:
                        description:
                            - Sequence number(1-512).
                        type: int
                    source:
                        description:
                            - Source IP address used in the health-check packet to the server.
                        type: str
                    source6:
                        description:
                            - Source IPv6 address used in the health-check packet to the server.
                        type: str
                    spillover_threshold:
                        description:
                            - Egress spillover threshold for this interface (0 - 16776000 kbit/s). When this traffic volume threshold is reached, new sessions
                               spill over to other interfaces in the SD-WAN.
                        type: int
                    status:
                        description:
                            - Enable/disable this interface in the SD-WAN.
                        type: str
                        choices:
                            - disable
                            - enable
                    volume_ratio:
                        description:
                            - Measured volume ratio (this value / sum of all values = percentage of link volume, 1 - 255).
                        type: int
                    weight:
                        description:
                            - Weight of this interface for weighted load balancing. (1 - 255) More traffic is directed to interfaces with higher weights.
                        type: int
                    zone:
                        description:
                            - Zone name. Source system.sdwan.zone.name.
                        type: str
            neighbor:
                description:
                    - Create SD-WAN neighbor from BGP neighbor table to control route advertisements according to SLA status.
                type: list
                elements: dict
                suboptions:
                    health_check:
                        description:
                            - SD-WAN health-check name. Source system.sdwan.health-check.name.
                        type: str
                    ip:
                        description:
                            - IP/IPv6 address of neighbor. Source router.bgp.neighbor.ip.
                        type: str
                    member:
                        description:
                            - Member sequence number list. Source system.sdwan.members.seq-num.
                        type: int
                        suboptions:
                            seq_num:
                                description:
                                    - Member sequence number. Source system.sdwan.members.seq-num.
                                type: int
                    minimum_sla_meet_members:
                        description:
                            - Minimum number of members which meet SLA when the neighbor is preferred.
                        type: int
                    mode:
                        description:
                            - What metric to select the neighbor.
                        type: str
                        choices:
                            - sla
                            - speedtest
                    role:
                        description:
                            - Role of neighbor.
                        type: str
                        choices:
                            - standalone
                            - primary
                            - secondary
                    sla_id:
                        description:
                            - SLA ID.
                        type: int
            neighbor_hold_boot_time:
                description:
                    - Waiting period in seconds when switching from the primary neighbor to the secondary neighbor from the neighbor start. (0 - 10000000).
                type: int
            neighbor_hold_down:
                description:
                    - Enable/disable hold switching from the secondary neighbor to the primary neighbor.
                type: str
                choices:
                    - enable
                    - disable
            neighbor_hold_down_time:
                description:
                    - Waiting period in seconds when switching from the secondary neighbor to the primary neighbor when hold-down is disabled. (0 - 10000000).
                type: int
            service:
                description:
                    - Create SD-WAN rules (also called services) to control how sessions are distributed to interfaces in the SD-WAN.
                type: list
                elements: dict
                suboptions:
                    addr_mode:
                        description:
                            - Address mode (IPv4 or IPv6).
                        type: str
                        choices:
                            - ipv4
                            - ipv6
                    bandwidth_weight:
                        description:
                            - Coefficient of reciprocal of available bidirectional bandwidth in the formula of custom-profile-1.
                        type: int
                    default:
                        description:
                            - Enable/disable use of SD-WAN as default service.
                        type: str
                        choices:
                            - enable
                            - disable
                    dscp_forward:
                        description:
                            - Enable/disable forward traffic DSCP tag.
                        type: str
                        choices:
                            - enable
                            - disable
                    dscp_forward_tag:
                        description:
                            - Forward traffic DSCP tag.
                        type: str
                    dscp_reverse:
                        description:
                            - Enable/disable reverse traffic DSCP tag.
                        type: str
                        choices:
                            - enable
                            - disable
                    dscp_reverse_tag:
                        description:
                            - Reverse traffic DSCP tag.
                        type: str
                    dst:
                        description:
                            - Destination address name.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Address or address group name. Source firewall.address.name firewall.addrgrp.name.
                                type: str
                    dst_negate:
                        description:
                            - Enable/disable negation of destination address match.
                        type: str
                        choices:
                            - enable
                            - disable
                    dst6:
                        description:
                            - Destination address6 name.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Address6 or address6 group name. Source firewall.address6.name firewall.addrgrp6.name.
                                type: str
                    end_port:
                        description:
                            - End destination port number.
                        type: int
                    gateway:
                        description:
                            - Enable/disable SD-WAN service gateway.
                        type: str
                        choices:
                            - enable
                            - disable
                    groups:
                        description:
                            - User groups.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Group name. Source user.group.name.
                                type: str
                    hash_mode:
                        description:
                            - Hash algorithm for selected priority members for load balance mode.
                        type: str
                        choices:
                            - round-robin
                            - source-ip-based
                            - source-dest-ip-based
                            - inbandwidth
                            - outbandwidth
                            - bibandwidth
                    health_check:
                        description:
                            - Health check list.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Health check name. Source system.sdwan.health-check.name.
                                type: str
                    hold_down_time:
                        description:
                            - Waiting period in seconds when switching from the back-up member to the primary member (0 - 10000000).
                        type: int
                    id:
                        description:
                            - SD-WAN rule ID (1 - 4000).
                        type: int
                    input_device:
                        description:
                            - Source interface name.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Interface name. Source system.interface.name.
                                type: str
                    input_device_negate:
                        description:
                            - Enable/disable negation of input device match.
                        type: str
                        choices:
                            - enable
                            - disable
                    input_zone:
                        description:
                            - Source input-zone name.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Zone. Source system.sdwan.zone.name.
                                type: str
                    internet_service:
                        description:
                            - Enable/disable use of Internet service for application-based load balancing.
                        type: str
                        choices:
                            - enable
                            - disable
                    internet_service_app_ctrl:
                        description:
                            - Application control based Internet Service ID list.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - Application control based Internet Service ID.
                                type: int
                    internet_service_app_ctrl_category:
                        description:
                            - IDs of one or more application control categories.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - Application control category ID.
                                type: int
                    internet_service_app_ctrl_group:
                        description:
                            - Application control based Internet Service group list.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Application control based Internet Service group name. Source application.group.name.
                                type: str
                    internet_service_custom:
                        description:
                            - Custom Internet service name list.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Custom Internet service name. Source firewall.internet-service-custom.name.
                                type: str
                    internet_service_custom_group:
                        description:
                            - Custom Internet Service group list.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Custom Internet Service group name. Source firewall.internet-service-custom-group.name.
                                type: str
                    internet_service_group:
                        description:
                            - Internet Service group list.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Internet Service group name. Source firewall.internet-service-group.name.
                                type: str
                    internet_service_name:
                        description:
                            - Internet service name list.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Internet service name. Source firewall.internet-service-name.name.
                                type: str
                    jitter_weight:
                        description:
                            - Coefficient of jitter in the formula of custom-profile-1.
                        type: int
                    latency_weight:
                        description:
                            - Coefficient of latency in the formula of custom-profile-1.
                        type: int
                    link_cost_factor:
                        description:
                            - Link cost factor.
                        type: str
                        choices:
                            - latency
                            - jitter
                            - packet-loss
                            - inbandwidth
                            - outbandwidth
                            - bibandwidth
                            - custom-profile-1
                    link_cost_threshold:
                        description:
                            - Percentage threshold change of link cost values that will result in policy route regeneration (0 - 10000000).
                        type: int
                    minimum_sla_meet_members:
                        description:
                            - Minimum number of members which meet SLA.
                        type: int
                    mode:
                        description:
                            - Control how the SD-WAN rule sets the priority of interfaces in the SD-WAN.
                        type: str
                        choices:
                            - auto
                            - manual
                            - priority
                            - sla
                            - load-balance
                    name:
                        description:
                            - SD-WAN rule name.
                        type: str
                    packet_loss_weight:
                        description:
                            - Coefficient of packet-loss in the formula of custom-profile-1.
                        type: int
                    passive_measurement:
                        description:
                            - Enable/disable passive measurement based on the service criteria.
                        type: str
                        choices:
                            - enable
                            - disable
                    priority_members:
                        description:
                            - Member sequence number list.
                        type: list
                        elements: dict
                        suboptions:
                            seq_num:
                                description:
                                    - Member sequence number. Source system.sdwan.members.seq-num.
                                type: int
                    priority_zone:
                        description:
                            - Priority zone name list.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Priority zone name. Source system.sdwan.zone.name.
                                type: str
                    protocol:
                        description:
                            - Protocol number.
                        type: int
                    quality_link:
                        description:
                            - Quality grade.
                        type: int
                    role:
                        description:
                            - Service role to work with neighbor.
                        type: str
                        choices:
                            - standalone
                            - primary
                            - secondary
                    route_tag:
                        description:
                            - IPv4 route map route-tag.
                        type: int
                    sla:
                        description:
                            - Service level agreement (SLA).
                        type: list
                        elements: dict
                        suboptions:
                            health_check:
                                description:
                                    - SD-WAN health-check. Source system.sdwan.health-check.name.
                                type: str
                            id:
                                description:
                                    - SLA ID.
                                type: int
                    sla_compare_method:
                        description:
                            - Method to compare SLA value for SLA mode.
                        type: str
                        choices:
                            - order
                            - number
                    src:
                        description:
                            - Source address name.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Address or address group name. Source firewall.address.name firewall.addrgrp.name.
                                type: str
                    src_negate:
                        description:
                            - Enable/disable negation of source address match.
                        type: str
                        choices:
                            - enable
                            - disable
                    src6:
                        description:
                            - Source address6 name.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Address6 or address6 group name. Source firewall.address6.name firewall.addrgrp6.name.
                                type: str
                    standalone_action:
                        description:
                            - Enable/disable service when selected neighbor role is standalone while service role is not standalone.
                        type: str
                        choices:
                            - enable
                            - disable
                    start_port:
                        description:
                            - Start destination port number.
                        type: int
                    status:
                        description:
                            - Enable/disable SD-WAN service.
                        type: str
                        choices:
                            - enable
                            - disable
                    tie_break:
                        description:
                            - Method of selecting member if more than one meets the SLA.
                        type: str
                        choices:
                            - zone
                            - cfg-order
                            - fib-best-match
                            - input-device
                    tos:
                        description:
                            - Type of service bit pattern.
                        type: str
                    tos_mask:
                        description:
                            - Type of service evaluated bits.
                        type: str
                    use_shortcut_sla:
                        description:
                            - Enable/disable use of ADVPN shortcut for quality comparison.
                        type: str
                        choices:
                            - enable
                            - disable
                    users:
                        description:
                            - User name.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - User name. Source user.local.name.
                                type: str
            speedtest_bypass_routing:
                description:
                    - Enable/disable bypass routing when speedtest on a SD-WAN member.
                type: str
                choices:
                    - disable
                    - enable
            status:
                description:
                    - Enable/disable SD-WAN.
                type: str
                choices:
                    - disable
                    - enable
            zone:
                description:
                    - Configure SD-WAN zones.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Zone name.
                        type: str
                    service_sla_tie_break:
                        description:
                            - Method of selecting member if more than one meets the SLA.
                        type: str
                        choices:
                            - cfg-order
                            - fib-best-match
                            - input-device
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
  - name: Configure redundant Internet connections with multiple outbound links and health-check profiles.
    fortios_system_sdwan:
      vdom:  "{{ vdom }}"
      system_sdwan:
        duplication:
         -
            dstaddr:
             -
                name: "default_name_5 (source firewall.address.name firewall.addrgrp.name)"
            dstaddr6:
             -
                name: "default_name_7 (source firewall.address6.name firewall.addrgrp6.name)"
            dstintf:
             -
                name: "default_name_9 (source system.interface.name system.zone.name system.sdwan.zone.name)"
            id:  "10"
            packet_de_duplication: "enable"
            packet_duplication: "disable"
            service:
             -
                name: "default_name_14 (source firewall.service.custom.name firewall.service.group.name)"
            service_id:
             -
                id:  "16 (source system.sdwan.service.id)"
            sla_match_service: "enable"
            srcaddr:
             -
                name: "default_name_19 (source firewall.address.name firewall.addrgrp.name)"
            srcaddr6:
             -
                name: "default_name_21 (source firewall.address6.name firewall.addrgrp6.name)"
            srcintf:
             -
                name: "default_name_23 (source system.interface.name system.zone.name system.sdwan.zone.name)"
        duplication_max_num: "24"
        fail_alert_interfaces:
         -
            name: "default_name_26 (source system.interface.name)"
        fail_detect: "enable"
        health_check:
         -
            addr_mode: "ipv4"
            detect_mode: "active"
            diffservcode: "<your_own_value>"
            dns_match_ip: "<your_own_value>"
            dns_request_domain: "<your_own_value>"
            failtime: "34"
            ftp_file: "<your_own_value>"
            ftp_mode: "passive"
            ha_priority: "37"
            http_agent: "<your_own_value>"
            http_get: "<your_own_value>"
            http_match: "<your_own_value>"
            interval: "41"
            members:
             -
                seq_num: "43 (source system.sdwan.members.seq-num)"
            mos_codec: "g711"
            name: "default_name_45"
            packet_size: "46"
            password: "<your_own_value>"
            port: "48"
            probe_count: "49"
            probe_packets: "disable"
            probe_timeout: "51"
            protocol: "ping"
            quality_measured_method: "half-open"
            recoverytime: "54"
            security_mode: "none"
            server: "192.168.100.40"
            sla:
             -
                id:  "58"
                jitter_threshold: "59"
                latency_threshold: "60"
                link_cost_factor: "latency"
                mos_threshold: "<your_own_value>"
                packetloss_threshold: "63"
            sla_fail_log_period: "64"
            sla_pass_log_period: "65"
            source: "<your_own_value>"
            system_dns: "disable"
            threshold_alert_jitter: "68"
            threshold_alert_latency: "69"
            threshold_alert_packetloss: "70"
            threshold_warning_jitter: "71"
            threshold_warning_latency: "72"
            threshold_warning_packetloss: "73"
            update_cascade_interface: "enable"
            update_static_route: "enable"
            user: "<your_own_value>"
            vrf: "77"
        load_balance_mode: "source-ip-based"
        members:
         -
            comment: "Comments."
            cost: "81"
            gateway: "<your_own_value>"
            gateway6: "<your_own_value>"
            ingress_spillover_threshold: "84"
            interface: "<your_own_value> (source system.interface.name)"
            priority: "86"
            priority6: "87"
            seq_num: "88"
            source: "<your_own_value>"
            source6: "<your_own_value>"
            spillover_threshold: "91"
            status: "disable"
            volume_ratio: "93"
            weight: "94"
            zone: "<your_own_value> (source system.sdwan.zone.name)"
        neighbor:
         -
            health_check: "<your_own_value> (source system.sdwan.health-check.name)"
            ip: "<your_own_value> (source router.bgp.neighbor.ip)"
            member:
             -
                seq_num: "100 (source system.sdwan.members.seq-num)"
            minimum_sla_meet_members: "101"
            mode: "sla"
            role: "standalone"
            sla_id: "104"
        neighbor_hold_boot_time: "105"
        neighbor_hold_down: "enable"
        neighbor_hold_down_time: "107"
        service:
         -
            addr_mode: "ipv4"
            bandwidth_weight: "110"
            default: "enable"
            dscp_forward: "enable"
            dscp_forward_tag: "<your_own_value>"
            dscp_reverse: "enable"
            dscp_reverse_tag: "<your_own_value>"
            dst:
             -
                name: "default_name_117 (source firewall.address.name firewall.addrgrp.name)"
            dst_negate: "enable"
            dst6:
             -
                name: "default_name_120 (source firewall.address6.name firewall.addrgrp6.name)"
            end_port: "121"
            gateway: "enable"
            groups:
             -
                name: "default_name_124 (source user.group.name)"
            hash_mode: "round-robin"
            health_check:
             -
                name: "default_name_127 (source system.sdwan.health-check.name)"
            hold_down_time: "128"
            id:  "129"
            input_device:
             -
                name: "default_name_131 (source system.interface.name)"
            input_device_negate: "enable"
            input_zone:
             -
                name: "default_name_134 (source system.sdwan.zone.name)"
            internet_service: "enable"
            internet_service_app_ctrl:
             -
                id:  "137"
            internet_service_app_ctrl_category:
             -
                id:  "139"
            internet_service_app_ctrl_group:
             -
                name: "default_name_141 (source application.group.name)"
            internet_service_custom:
             -
                name: "default_name_143 (source firewall.internet-service-custom.name)"
            internet_service_custom_group:
             -
                name: "default_name_145 (source firewall.internet-service-custom-group.name)"
            internet_service_group:
             -
                name: "default_name_147 (source firewall.internet-service-group.name)"
            internet_service_name:
             -
                name: "default_name_149 (source firewall.internet-service-name.name)"
            jitter_weight: "150"
            latency_weight: "151"
            link_cost_factor: "latency"
            link_cost_threshold: "153"
            minimum_sla_meet_members: "154"
            mode: "auto"
            name: "default_name_156"
            packet_loss_weight: "157"
            passive_measurement: "enable"
            priority_members:
             -
                seq_num: "160 (source system.sdwan.members.seq-num)"
            priority_zone:
             -
                name: "default_name_162 (source system.sdwan.zone.name)"
            protocol: "163"
            quality_link: "164"
            role: "standalone"
            route_tag: "166"
            sla:
             -
                health_check: "<your_own_value> (source system.sdwan.health-check.name)"
                id:  "169"
            sla_compare_method: "order"
            src:
             -
                name: "default_name_172 (source firewall.address.name firewall.addrgrp.name)"
            src_negate: "enable"
            src6:
             -
                name: "default_name_175 (source firewall.address6.name firewall.addrgrp6.name)"
            standalone_action: "enable"
            start_port: "177"
            status: "enable"
            tie_break: "zone"
            tos: "<your_own_value>"
            tos_mask: "<your_own_value>"
            use_shortcut_sla: "enable"
            users:
             -
                name: "default_name_184 (source user.local.name)"
        speedtest_bypass_routing: "disable"
        status: "disable"
        zone:
         -
            name: "default_name_188"
            service_sla_tie_break: "cfg-order"

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


def filter_system_sdwan_data(json):
    option_list = [
        "duplication",
        "duplication_max_num",
        "fail_alert_interfaces",
        "fail_detect",
        "health_check",
        "load_balance_mode",
        "members",
        "neighbor",
        "neighbor_hold_boot_time",
        "neighbor_hold_down",
        "neighbor_hold_down_time",
        "service",
        "speedtest_bypass_routing",
        "status",
        "zone",
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
        ["health_check", "sla", "link_cost_factor"],
        ["health_check", "server"],
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


def system_sdwan(data, fos):
    vdom = data["vdom"]
    system_sdwan_data = data["system_sdwan"]
    system_sdwan_data = flatten_multilists_attributes(system_sdwan_data)
    filtered_data = underscore_to_hyphen(filter_system_sdwan_data(system_sdwan_data))

    return fos.set("system", "sdwan", data=filtered_data, vdom=vdom)


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


def fortios_system(data, fos):

    fos.do_member_operation("system", "sdwan")
    if data["system_sdwan"]:
        resp = system_sdwan(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_sdwan"))

    return (
        not is_successful_status(resp),
        is_successful_status(resp)
        and (resp["revision_changed"] if "revision_changed" in resp else True),
        resp,
        {},
    )


versioned_schema = {
    "type": "dict",
    "children": {
        "status": {
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
                "v6.4.0": True,
                "v6.4.1": True,
                "v7.2.0": True,
            },
        },
        "load_balance_mode": {
            "type": "string",
            "options": [
                {
                    "value": "source-ip-based",
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
                    "value": "weight-based",
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
                    "value": "usage-based",
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
                    "value": "source-dest-ip-based",
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
                    "value": "measured-volume-based",
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
                "v6.4.0": True,
                "v6.4.1": True,
                "v7.2.0": True,
            },
        },
        "fail_alert_interfaces": {
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
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
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
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": True,
                "v7.2.0": True,
            },
        },
        "service": {
            "elements": "dict",
            "type": "list",
            "children": {
                "jitter_weight": {
                    "type": "integer",
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
                "dscp_forward_tag": {
                    "type": "string",
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
                "protocol": {
                    "type": "integer",
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
                "link_cost_threshold": {
                    "type": "integer",
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
                "dscp_reverse_tag": {
                    "type": "string",
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
                "dst6": {
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
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
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
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "end_port": {
                    "type": "integer",
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
                "internet_service_app_ctrl": {
                    "elements": "dict",
                    "type": "list",
                    "children": {
                        "id": {
                            "type": "integer",
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
                        }
                    },
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
                "hold_down_time": {
                    "type": "integer",
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
                "minimum_sla_meet_members": {
                    "type": "integer",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": False,
                        "v7.2.0": True,
                    },
                },
                "src6": {
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
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
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
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "bandwidth_weight": {
                    "type": "integer",
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
                "internet_service_custom": {
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
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
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
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "input_device": {
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
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
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
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "link_cost_factor": {
                    "type": "string",
                    "options": [
                        {
                            "value": "latency",
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
                            "value": "jitter",
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
                            "value": "packet-loss",
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
                            "value": "inbandwidth",
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
                            "value": "outbandwidth",
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
                            "value": "bibandwidth",
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
                            "value": "custom-profile-1",
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "packet_loss_weight": {
                    "type": "integer",
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
                "id": {
                    "type": "integer",
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
                "priority_zone": {
                    "elements": "dict",
                    "type": "list",
                    "children": {
                        "name": {
                            "type": "string",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
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
                        "v7.0.0": False,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v7.2.0": True,
                    },
                },
                "route_tag": {
                    "type": "integer",
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
                "passive_measurement": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.2.0": True,
                                "v7.0.2": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.2.0": True,
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
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v7.2.0": True,
                    },
                },
                "addr_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "ipv4",
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
                            "value": "ipv6",
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "tos": {
                    "type": "string",
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
                "dst": {
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
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
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
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "input_device_negate": {
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
                                "v7.2.0": True,
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "gateway": {
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
                                "v7.2.0": True,
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "input_zone": {
                    "elements": "dict",
                    "type": "list",
                    "children": {
                        "name": {"type": "string", "revisions": {"v7.2.0": True}}
                    },
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
                        "v7.2.0": True,
                    },
                },
                "role": {
                    "type": "string",
                    "options": [
                        {
                            "value": "standalone",
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
                            "value": "primary",
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
                            "value": "secondary",
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "internet_service_custom_group": {
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
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
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
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "dscp_forward": {
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
                                "v7.2.0": True,
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "quality_link": {
                    "type": "integer",
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
                "mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "auto",
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
                            "value": "manual",
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
                            "value": "priority",
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
                            "value": "sla",
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
                            "value": "load-balance",
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "status": {
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
                                "v7.2.0": True,
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "health_check": {
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
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
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
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "start_port": {
                    "type": "integer",
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
                "users": {
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
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
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
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "src": {
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
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
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
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "dst_negate": {
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
                                "v7.2.0": True,
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "dscp_reverse": {
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
                                "v7.2.0": True,
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "latency_weight": {
                    "type": "integer",
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
                "tos_mask": {
                    "type": "string",
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
                "groups": {
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
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
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
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "standalone_action": {
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
                                "v7.2.0": True,
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "sla_compare_method": {
                    "type": "string",
                    "options": [
                        {
                            "value": "order",
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
                            "value": "number",
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "internet_service_app_ctrl_group": {
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
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
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
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "priority_members": {
                    "elements": "dict",
                    "type": "list",
                    "children": {
                        "seq_num": {
                            "type": "integer",
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
                        }
                    },
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "hash_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "round-robin",
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
                            "value": "source-ip-based",
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
                            "value": "source-dest-ip-based",
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
                            "value": "inbandwidth",
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
                            "value": "outbandwidth",
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
                            "value": "bibandwidth",
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
                        "v6.4.0": True,
                        "v6.4.1": False,
                        "v7.2.0": True,
                    },
                },
                "default": {
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
                                "v7.2.0": True,
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "internet_service_app_ctrl_category": {
                    "elements": "dict",
                    "type": "list",
                    "children": {
                        "id": {"type": "integer", "revisions": {"v7.2.0": True}}
                    },
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
                        "v7.2.0": True,
                    },
                },
                "src_negate": {
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
                                "v7.2.0": True,
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "internet_service_name": {
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
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
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
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "internet_service_group": {
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
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": True,
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
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "tie_break": {
                    "type": "string",
                    "options": [
                        {
                            "value": "zone",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "cfg-order",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "fib-best-match",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "input-device",
                            "revisions": {
                                "v7.0.3": False,
                                "v7.0.2": False,
                                "v7.0.1": False,
                                "v7.0.0": False,
                                "v7.0.5": False,
                                "v7.0.4": False,
                                "v6.4.4": False,
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
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v7.2.0": True,
                    },
                },
                "use_shortcut_sla": {
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
                                "v7.2.0": True,
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
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v7.2.0": True,
                    },
                },
                "sla": {
                    "elements": "dict",
                    "type": "list",
                    "children": {
                        "health_check": {
                            "type": "string",
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
                        "id": {
                            "type": "integer",
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
                    },
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
                "internet_service": {
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
                                "v7.2.0": True,
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
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
                "v6.4.0": True,
                "v6.4.1": True,
                "v7.2.0": True,
            },
        },
        "zone": {
            "elements": "dict",
            "type": "list",
            "children": {
                "service_sla_tie_break": {
                    "type": "string",
                    "options": [
                        {
                            "value": "cfg-order",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "fib-best-match",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "input-device",
                            "revisions": {
                                "v7.0.3": False,
                                "v7.0.2": False,
                                "v7.0.1": False,
                                "v7.0.0": False,
                                "v7.0.5": False,
                                "v7.0.4": False,
                                "v6.4.4": False,
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
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v7.2.0": True,
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
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
                "v6.4.0": True,
                "v6.4.1": True,
                "v7.2.0": True,
            },
        },
        "fail_detect": {
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
                        "v7.2.0": True,
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
                "v6.4.0": True,
                "v6.4.1": True,
                "v7.2.0": True,
            },
        },
        "neighbor_hold_down_time": {
            "type": "integer",
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
        "neighbor_hold_down": {
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
                        "v7.2.0": True,
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
                "v6.4.0": True,
                "v6.4.1": True,
                "v7.2.0": True,
            },
        },
        "neighbor": {
            "elements": "dict",
            "type": "list",
            "children": {
                "member": {
                    "elements": "dict",
                    "type": "list",
                    "children": {
                        "seq_num": {
                            "type": "integer",
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
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "health_check": {
                    "type": "string",
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
                "ip": {
                    "type": "string",
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
                "sla_id": {
                    "type": "integer",
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
                "minimum_sla_meet_members": {
                    "type": "integer",
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
                        "v7.2.0": True,
                    },
                },
                "role": {
                    "type": "string",
                    "options": [
                        {
                            "value": "standalone",
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
                            "value": "primary",
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
                            "value": "secondary",
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "sla",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "speedtest",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
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
                        "v7.0.0": False,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": False,
                        "v6.4.0": False,
                        "v6.4.1": False,
                        "v7.2.0": True,
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
                "v6.4.0": True,
                "v6.4.1": True,
                "v7.2.0": True,
            },
        },
        "speedtest_bypass_routing": {
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
                        "v7.2.0": True,
                    },
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
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
                "v7.0.0": False,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": False,
                "v7.2.0": True,
            },
        },
        "duplication_max_num": {
            "type": "integer",
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": False,
                "v7.2.0": True,
            },
        },
        "members": {
            "elements": "dict",
            "type": "list",
            "children": {
                "status": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "weight": {
                    "type": "integer",
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
                "zone": {
                    "type": "string",
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
                "spillover_threshold": {
                    "type": "integer",
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
                "seq_num": {
                    "type": "integer",
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
                "priority": {
                    "type": "integer",
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
                "source": {
                    "type": "string",
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
                "cost": {
                    "type": "integer",
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
                "source6": {
                    "type": "string",
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
                "gateway6": {
                    "type": "string",
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
                "priority6": {
                    "type": "integer",
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
                        "v7.2.0": True,
                    },
                },
                "interface": {
                    "type": "string",
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
                "volume_ratio": {
                    "type": "integer",
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
                "gateway": {
                    "type": "string",
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
                "ingress_spillover_threshold": {
                    "type": "integer",
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
            },
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
        "health_check": {
            "elements": "dict",
            "type": "list",
            "children": {
                "protocol": {
                    "type": "string",
                    "options": [
                        {
                            "value": "ping",
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
                            "value": "tcp-echo",
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
                            "value": "udp-echo",
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
                            "value": "http",
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
                            "value": "twamp",
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
                            "value": "dns",
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
                            "value": "tcp-connect",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": False,
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "ftp",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
                                "v6.4.0": True,
                                "v6.4.1": False,
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "ping6",
                            "revisions": {"v6.4.0": False, "v6.4.1": True},
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
                        "v7.2.0": True,
                    },
                },
                "system_dns": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "update_cascade_interface": {
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
                                "v7.2.0": True,
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "diffservcode": {
                    "type": "string",
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
                "threshold_alert_jitter": {
                    "type": "integer",
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
                "ha_priority": {
                    "type": "integer",
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
                "port": {
                    "type": "integer",
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
                "threshold_warning_packetloss": {
                    "type": "integer",
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
                "sla": {
                    "elements": "dict",
                    "type": "list",
                    "children": {
                        "jitter_threshold": {
                            "type": "integer",
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
                        "latency_threshold": {
                            "type": "integer",
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
                        "mos_threshold": {
                            "type": "string",
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
                                "v7.2.0": True,
                            },
                        },
                        "packetloss_threshold": {
                            "type": "integer",
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
                        "link_cost_factor": {
                            "multiple_values": True,
                            "elements": "str",
                            "type": "list",
                            "options": [
                                {
                                    "value": "latency",
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
                                    "value": "jitter",
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
                                    "value": "packet-loss",
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
                                    "value": "mos",
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
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v7.2.0": True,
                            },
                        },
                        "id": {
                            "type": "integer",
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
                    },
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
                "packet_size": {
                    "type": "integer",
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
                "source": {
                    "type": "string",
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
                        "v7.2.0": True,
                    },
                },
                "addr_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "ipv4",
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
                            "value": "ipv6",
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "update_static_route": {
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
                                "v7.2.0": True,
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "threshold_alert_latency": {
                    "type": "integer",
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
                "probe_timeout": {
                    "type": "integer",
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
                "ftp_file": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": False,
                        "v7.2.0": True,
                    },
                },
                "quality_measured_method": {
                    "type": "string",
                    "options": [
                        {
                            "value": "half-open",
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
                            "value": "half-close",
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
                        "v6.4.0": True,
                        "v6.4.1": False,
                        "v7.2.0": True,
                    },
                },
                "http_get": {
                    "type": "string",
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
                "failtime": {
                    "type": "integer",
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
                "http_agent": {
                    "type": "string",
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
                "ftp_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "passive",
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
                            "value": "port",
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
                        "v6.4.0": True,
                        "v6.4.1": False,
                        "v7.2.0": True,
                    },
                },
                "user": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": False,
                        "v7.2.0": True,
                    },
                },
                "members": {
                    "elements": "dict",
                    "type": "list",
                    "children": {
                        "seq_num": {
                            "type": "integer",
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
                        }
                    },
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
                "probe_count": {
                    "type": "integer",
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
                "password": {
                    "type": "string",
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
                "sla_fail_log_period": {
                    "type": "integer",
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
                "recoverytime": {
                    "type": "integer",
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
                "probe_packets": {
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "http_match": {
                    "type": "string",
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
                "security_mode": {
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
                                "v6.4.0": True,
                                "v6.4.1": True,
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "authentication",
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "vrf": {
                    "type": "integer",
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
                        "v7.2.0": True,
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
                        "v6.4.0": True,
                        "v6.4.1": True,
                        "v7.2.0": True,
                    },
                },
                "mos_codec": {
                    "type": "string",
                    "options": [
                        {"value": "g711", "revisions": {"v7.2.0": True}},
                        {"value": "g722", "revisions": {"v7.2.0": True}},
                        {"value": "g729", "revisions": {"v7.2.0": True}},
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
                        "v7.2.0": True,
                    },
                },
                "detect_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "active",
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
                            "value": "passive",
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
                            "value": "prefer-passive",
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
                        "v7.2.0": True,
                    },
                },
                "interval": {
                    "type": "integer",
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
                "server": {
                    "multiple_values": True,
                    "elements": "str",
                    "type": "list",
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
                "sla_pass_log_period": {
                    "type": "integer",
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
                "threshold_alert_packetloss": {
                    "type": "integer",
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
                "dns_request_domain": {
                    "type": "string",
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
                "threshold_warning_jitter": {
                    "type": "integer",
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
                "threshold_warning_latency": {
                    "type": "integer",
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
                "dns_match_ip": {
                    "type": "string",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": False,
                        "v7.2.0": True,
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
                "v6.4.0": True,
                "v6.4.1": True,
                "v7.2.0": True,
            },
        },
        "duplication": {
            "elements": "dict",
            "type": "list",
            "children": {
                "packet_de_duplication": {
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
                                "v7.2.0": True,
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
                        "v6.4.0": True,
                        "v7.2.0": True,
                    },
                },
                "dstaddr": {
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
                                "v6.4.4": True,
                                "v6.4.0": True,
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
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v7.2.0": True,
                    },
                },
                "service": {
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
                                "v6.4.4": True,
                                "v6.4.0": True,
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
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v7.2.0": True,
                    },
                },
                "dstaddr6": {
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
                                "v6.4.4": True,
                                "v6.4.0": True,
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
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v7.2.0": True,
                    },
                },
                "sla_match_service": {
                    "type": "string",
                    "options": [
                        {"value": "enable", "revisions": {"v7.2.0": True}},
                        {"value": "disable", "revisions": {"v7.2.0": True}},
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
                        "v7.2.0": True,
                    },
                },
                "srcaddr": {
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
                                "v6.4.4": True,
                                "v6.4.0": True,
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
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v7.2.0": True,
                    },
                },
                "packet_duplication": {
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
                                "v7.2.0": True,
                            },
                        },
                        {
                            "value": "force",
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
                            "value": "on-demand",
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
                        "v6.4.0": True,
                        "v7.2.0": True,
                    },
                },
                "dstintf": {
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
                                "v6.4.4": True,
                                "v6.4.0": True,
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
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v7.2.0": True,
                    },
                },
                "srcintf": {
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
                                "v6.4.4": True,
                                "v6.4.0": True,
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
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v7.2.0": True,
                    },
                },
                "service_id": {
                    "elements": "dict",
                    "type": "list",
                    "children": {
                        "id": {
                            "type": "integer",
                            "revisions": {
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v6.4.4": True,
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
                        "v6.4.4": True,
                        "v6.4.0": False,
                        "v7.2.0": True,
                    },
                },
                "srcaddr6": {
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
                                "v6.4.4": True,
                                "v6.4.0": True,
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
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v7.2.0": True,
                    },
                },
                "id": {
                    "type": "integer",
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
            },
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v6.4.4": True,
                "v6.4.0": True,
                "v6.4.1": False,
                "v7.2.0": True,
            },
        },
        "neighbor_hold_boot_time": {
            "type": "integer",
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
    },
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
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = None
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
        "system_sdwan": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_sdwan"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_sdwan"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_sdwan"
        )

        is_error, has_changed, result, diff = fortios_system(module.params, fos)

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
