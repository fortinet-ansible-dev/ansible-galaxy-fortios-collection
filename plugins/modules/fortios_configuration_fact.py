#!/usr/bin/python
from __future__ import absolute_import, division, print_function

# Copyright 2020-2021 Fortinet, Inc.
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

ANSIBLE_METADATA = {
    "status": ["preview"],
    "supported_by": "community",
    "metadata_version": "1.1",
}

DOCUMENTATION = """
---
module: fortios_configuration_fact
version_added: "2.0.0"
short_description: Retrieve Facts of FortiOS Configurable Objects.
description:
    - Collects facts from network devices running the fortios operating system.
      This module places the facts gathered in the fact tree keyed by the respective resource name.
      This facts module will only collect those facts which user specified in playbook.
author:
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@fshen01)
notes:
    - Different selector may have different parameters, users are expected to look up them for a specific selector.
    - For some selectors, the objects are global, no params are allowed to appear.
    - If params is empty a non-unique object, the whole object list is returned.
    - This module has support for all configuration API, excluding any monitor API.
    - The result of API request is stored in results as a list.
requirements:
    - install galaxy collection fortinet.fortios >= 2.0.0.
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
        required: false
    filters:
        description:
            - A list of expressions to filter the returned results.
            - The items of the list are combined as LOGICAL AND with operator ampersand.
            - One item itself could be concatenated with a comma as LOGICAL OR.
        type: list
        elements: str
        required: false
    sorters:
        description:
            - A list of expressions to sort the returned results.
            - The items of the list are in ascending order with operator ampersand.
            - One item itself could be in decending order with a comma inside.
        type: list
        elements: str
        required: false
    formatters:
        description:
            - A list of fields to display for returned results.
        type: list
        elements: str
        required: false
    selectors:
        description:
            - a list of selector for retrieving the fortigate facts
        type: list
        elements: dict
        required: false
        suboptions:
            filters:
                description:
                    - A list of expressions to filter the returned results.
                    - The items of the list are combined as LOGICAL AND with operator ampersand.
                    - One item itself could be concatenated with a comma as LOGICAL OR.
                type: list
                elements: str
                required: false
            sorters:
                description:
                    - A list of expressions to sort the returned results.
                    - The items of the list are in ascending order with operator ampersand.
                    - One item itself could be in decending order with a comma inside.
                type: list
                elements: str
                required: false
            formatters:
                description:
                    - A list of fields to display for returned results.
                type: list
                elements: str
                required: false
            params:
                description:
                    - the parameter for each selector, see definition in above list.
                type: dict
                required: false
            selector:
                description:
                    - selector for retrieving the fortigate facts
                type: str
                required: true
                choices:
                 - log_gui-display
                 - system_fortiguard-service
                 - router_route-map
                 - system_sso-admin
                 - wireless-controller_address
                 - vpn.ssl_monitor
                 - system.auto-update_status
                 - system_cmdb
                 - authentication_rule
                 - log.fortianalyzer_override-setting
                 - firewall.ssl_setting
                 - vpn.ipsec_phase2-interface
                 - router_key-chain
                 - system_ddns
                 - firewall_traffic-class
                 - system_replacemsg-group
                 - system_ftm-push
                 - system_sms-server
                 - firewall_central-snat-map
                 - firewall_multicast-address6
                 - dlp_fp-sensitivity
                 - system.replacemsg_sslvpn
                 - ips_view-map
                 - firewall_pfcp
                 - system_pppoe-interface
                 - webfilter_categories
                 - firewall_addrgrp6
                 - log.disk_filter
                 - system.session-info_full-stat
                 - firewall_proxy-address
                 - extender-controller_extender-profile
                 - emailfilter_block-allow-list
                 - router_bgp
                 - router_auth-path
                 - system_resource-limits
                 - system.replacemsg_auth
                 - system.autoupdate_schedule
                 - switch-controller.qos_ip-dscp-map
                 - firewall_local-in-policy6
                 - log.fortianalyzer2_override-setting
                 - wireless-controller.hotspot20_h2qp-osu-provider-nai
                 - log.fortianalyzer_override-filter
                 - system.replacemsg_icap
                 - system_object-tagging
                 - spamfilter_profile
                 - switch-controller_remote-log
                 - router_rip
                 - switch-controller.security-policy_local-access
                 - vpn.ipsec.stats_tunnel
                 - log.fortianalyzer-cloud_override-filter
                 - firewall.shaper_traffic
                 - system_smc-ntp
                 - user_adgrp
                 - system_auto-script
                 - switch-controller_quarantine
                 - firewall.service_category
                 - system_standalone-cluster
                 - system_link-monitor
                 - switch-controller_stp-settings
                 - user_security-exempt-list
                 - log.fortianalyzer-cloud_setting
                 - switch-controller.qos_qos-policy
                 - firewall_sniffer
                 - wireless-controller_ssid-policy
                 - wireless-controller_wag-profile
                 - firewall_internet-service-reputation
                 - switch-controller_vlan
                 - system.replacemsg_mm7
                 - system.replacemsg_mm4
                 - firewall_internet-service
                 - system.replacemsg_mm3
                 - system.replacemsg_mm1
                 - firewall.iprope.appctrl_status
                 - firewall_vipgrp46
                 - log.webtrends_filter
                 - application_name
                 - system_sso-forticloud-admin
                 - gtp_apngrp
                 - log_setting
                 - firewall_address6-template
                 - wireless-controller.hotspot20_anqp-3gpp-cellular
                 - wireless-controller.hotspot20_h2qp-wan-metric
                 - system_automation-action
                 - system.autoupdate_tunneling
                 - router_prefix-list6
                 - webfilter_ips-urlfilter-setting
                 - pfcp_message-filter
                 - switch-controller_network-monitor-settings
                 - system_alias
                 - file-filter_profile
                 - web-proxy_forward-server-group
                 - system_session-helper
                 - router_community-list
                 - wireless-controller_qos-profile
                 - extender_session-info
                 - firewall_dnstranslation
                 - vpn.ssl.web_portal
                 - firewall_internet-service-custom
                 - system.replacemsg_device-detection-portal
                 - wireless-controller_ble-profile
                 - firewall_internet-service-custom-group
                 - system.performance.firewall_statistics
                 - firewall_profile-group
                 - system_vxlan
                 - system.autoupdate_push-update
                 - firewall_address6
                 - system.performance_top
                 - wireless-controller_vap-status
                 - wireless-controller_wids-profile
                 - emailfilter_bword
                 - log.fortiguard_filter
                 - firewall_ipv6-eh-filter
                 - switch-controller.ptp_settings
                 - endpoint-control_fctems
                 - user_device-category
                 - firewall_identity-based-route
                 - system.session-helper-info_list
                 - system_console
                 - certificate_local
                 - system_ntp
                 - webfilter_ftgd-local-cat
                 - report_layout
                 - log.tacacs+accounting3_setting
                 - wireless-controller_timers
                 - wireless-controller.hotspot20_icon
                 - log.tacacs+accounting2_filter
                 - log.memory_global-setting
                 - router_multicast-flow
                 - ssh-filter_profile
                 - system_fortisandbox
                 - system_dns64
                 - system_virtual-wan-link
                 - ips_sensor
                 - firewall.wildcard-fqdn_custom
                 - router_static
                 - alertemail_setting
                 - user_peergrp
                 - user_fortitoken
                 - web-proxy_debug-url
                 - dlp_dictionary
                 - vpn.ike_gateway
                 - webfilter_override
                 - switch-controller_nac-device
                 - system_fsso-polling
                 - user_peer
                 - vpn.ssl.web_host-check-software
                 - gtp_message-filter-v0v1
                 - switch-controller_lldp-profile
                 - switch-controller_dynamic-port-policy
                 - vpn.ssl.web_realm
                 - system_stp
                 - log.tacacs+accounting_setting
                 - user_nac-policy
                 - wireless-controller_snmp
                 - emailfilter_fortishield
                 - switch-controller.security-policy_captive-portal
                 - firewall_shaping-policy
                 - wireless-controller_wlchanlistlic
                 - log_custom-field
                 - switch-controller_mac-policy
                 - firewall_address
                 - certificate_crl
                 - firewall.ssh_setting
                 - switch-controller.auto-config_policy
                 - system_nd-proxy
                 - log.memory_setting
                 - system_alarm
                 - system_ips-urlfilter-dns6
                 - wireless-controller_log
                 - extender_lte-carrier-by-mcc-mnc
                 - webfilter_ftgd-statistics
                 - hardware.npu.np6_ipsec-stats
                 - firewall_vendor-mac-summary
                 - system_cluster-sync
                 - wanopt_settings
                 - emailfilter_dnsbl
                 - endpoint-control_registered-forticlient
                 - system_dedicated-mgmt
                 - log.tacacs+accounting3_filter
                 - log.fortianalyzer-cloud_override-setting
                 - firewall_policy46
                 - system.source-ip_status
                 - system_modem
                 - certificate_remote
                 - firewall_decrypted-traffic-mirror
                 - antivirus_settings
                 - switch-controller_storm-control-policy
                 - switch-controller_802-1X-settings
                 - system_session-ttl
                 - system_storage
                 - system_isf-queue-profile
                 - log.memory_filter
                 - firewall_auth-portal
                 - antivirus_notification
                 - user_ldap
                 - ips_global
                 - wanopt_remote-storage
                 - system_speed-test-schedule
                 - wireless-controller.hotspot20_qos-map
                 - system.session-info_ttl
                 - vpn_l2tp
                 - monitoring_np6-ipsec-engine
                 - system_npu
                 - firewall_vip46
                 - authentication_setting
                 - vpn.certificate_ocsp-server
                 - antivirus_heuristic
                 - spamfilter_bword
                 - system_custom-language
                 - web-proxy_explicit
                 - vpn.ipsec_concentrator
                 - wireless-controller_wtp-group
                 - log.tacacs+accounting2_setting
                 - system_vdom-sflow
                 - switch-controller_igmp-snooping
                 - waf_signature
                 - log.null-device_setting
                 - gtp_tunnel-limit
                 - ips_rule-settings
                 - firewall_access-proxy
                 - system.session-info_expectation
                 - spamfilter_options
                 - switch-controller.security-policy_802-1X
                 - system_np6
                 - ips_decoder
                 - firewall_proute6
                 - user_setting
                 - system.performance_status
                 - system_geoip-override
                 - vpn.ipsec_phase1
                 - vpn.ipsec_phase2
                 - wireless-controller.hotspot20_anqp-network-auth-type
                 - webfilter_ips-urlfilter-cache-setting
                 - firewall.ipmacbinding_setting
                 - log.fortianalyzer2_filter
                 - system.ip-conflict_status
                 - application_rule-settings
                 - switch-controller_flow-tracking
                 - log.syslogd4_filter
                 - system_speed-test-server
                 - firewall_acl
                 - system_proxy-arp
                 - webfilter_ftgd-local-rating
                 - switch-controller_snmp-user
                 - nsxt_setting
                 - ips_custom
                 - switch-controller_switch-interface-tag
                 - router_policy6
                 - waf_sub-class
                 - web-proxy_forward-server
                 - log_eventfilter
                 - system_vdom-property
                 - switch-controller_traffic-sniffer
                 - firewall_security-policy
                 - system_external-resource
                 - user_exchange
                 - sctp-filter_profile
                 - system_ipv6-neighbor-cache
                 - vpn.ipsec.tunnel_details
                 - report_style
                 - log.syslogd2_override-filter
                 - wireless-controller_wtp
                 - wireless-controller_rf-analysis
                 - wanopt_peer
                 - system_saml
                 - system.dhcp6_server
                 - emailfilter_profile
                 - hardware.npu.np6_sse-stats
                 - log.fortianalyzer3_override-filter
                 - hardware_status
                 - firewall_multicast-policy
                 - vpn_ocvpn
                 - system.replacemsg_mms
                 - spamfilter_bwl
                 - switch-controller_fortilink-settings
                 - system_arp
                 - firewall_internet-service-addition
                 - webfilter_status
                 - system_ips
                 - emailfilter_bwl
                 - system_password-policy
                 - report_dataset
                 - switch-controller_virtual-port-pool
                 - wireless-controller_setting
                 - system.3g-modem_custom
                 - wireless-controller.hotspot20_anqp-ip-address-type
                 - firewall_vipgrp
                 - firewall_city
                 - web-proxy_profile
                 - system_switch-interface
                 - router_isis
                 - firewall_policy
                 - log.syslogd_override-setting
                 - hardware_memory
                 - router_info
                 - system.performance.firewall_packet-distribution
                 - switch-controller_mac-sync-settings
                 - webfilter_content
                 - firewall_vipgrp6
                 - switch-controller.initial-config_template
                 - spamfilter_mheader
                 - firewall.schedule_onetime
                 - vpn.status_pptp
                 - gtp_ie-allow-list
                 - log.fortianalyzer_setting
                 - videofilter_youtube-key
                 - vpn.ipsec.tunnel_name
                 - firewall_ippool6
                 - wireless-controller_status
                 - system_central-management
                 - system.replacemsg_http
                 - vpn.status.ssl_list
                 - vpn.ipsec.tunnel_summary
                 - hardware.npu.np6_session-stats
                 - cifs_domain-controller
                 - firewall_policy6
                 - system_zone
                 - system_vdom-dns
                 - firewall_multicast-address
                 - wireless-controller_wtp-profile
                 - vpn.ssl_settings
                 - router_ospf
                 - switch-controller.qos_queue-policy
                 - dpdk_cpus
                 - wireless-controller.hotspot20_h2qp-terms-and-conditions
                 - router_static6
                 - ftp-proxy_explicit
                 - hardware.npu.np6_port-list
                 - system_fortimanager
                 - system.lldp_network-policy
                 - vpn.certificate_crl
                 - system.replacemsg_admin
                 - router_multicast
                 - webfilter_profile
                 - switch-controller_storm-control
                 - firewall_ssl-ssh-profile
                 - vpn.ssl_client
                 - gtp_ie-white-list
                 - firewall_country
                 - user_certificate
                 - log.disk_setting
                 - nsxt_service-chain
                 - dlp_filepattern
                 - firewall_acl6
                 - firewall_ippool
                 - web-proxy_url-match
                 - vpn.status.ssl_hw-acceleration-status
                 - system_interface
                 - log.syslogd3_override-filter
                 - router_bfd
                 - switch-controller_custom-command
                 - dlp_data-type
                 - firewall_internet-service-extension
                 - system.replacemsg_webproxy
                 - user_password-policy
                 - wireless-controller_inter-controller
                 - system_fortindr
                 - log.syslogd4_setting
                 - log.fortianalyzer_filter
                 - hardware_cpu
                 - switch-controller_switch-group
                 - user_fsso
                 - emailfilter_mheader
                 - firewall_vipgrp64
                 - user_quarantine
                 - system_ips-urlfilter-dns
                 - wireless-controller_addrgrp
                 - system_fm
                 - wireless-controller_apcfg-profile
                 - system_global
                 - vpn.ipsec.stats_crypto
                 - wireless-controller.hotspot20_anqp-nai-realm
                 - system_physical-switch
                 - system_affinity-packet-redistribution
                 - system_status
                 - firewall_gtp
                 - log.fortiguard_override-setting
                 - firewall_proute
                 - videofilter_profile
                 - log.fortianalyzer3_setting
                 - system.auto-update_versions
                 - firewall_vip
                 - system_virtual-switch
                 - firewall_mms-profile
                 - wanopt_auth-group
                 - wanopt_webcache
                 - system.snmp_user
                 - firewall_ip-translation
                 - system_settings
                 - log.fortianalyzer2_setting
                 - wireless-controller_vap
                 - ipsec_tunnel
                 - wanopt_cache-service
                 - log.syslogd4_override-filter
                 - switch-controller_switch-log
                 - firewall_internet-service-group
                 - system.replacemsg_mail
                 - extender_modem-status
                 - system_replacemsg-image
                 - system_acme
                 - antivirus_quarantine
                 - log.fortianalyzer2_override-filter
                 - system.session-info_list
                 - vpn.certificate_ca
                 - endpoint-control_forticlient-registration-sync
                 - system_sdn-connector
                 - vpn.ssl.web_user-group-bookmark
                 - system_fortiguard-log-service
                 - endpoint-control_settings
                 - system_central-mgmt
                 - hardware_nic
                 - log.null-device_filter
                 - gtp_message-filter-v2
                 - firewall.shaper_per-ip-shaper
                 - wireless-controller_utm-profile
                 - icap_server-group
                 - router_aspath-list
                 - firewall.schedule_group
                 - system_ipam
                 - firewall_internet-service-list
                 - system_dscp-based-priority
                 - dlp_sensitivity
                 - icap_server
                 - vpn.ipsec_phase1-interface
                 - authentication_scheme
                 - firewall_access-proxy-virtual-host
                 - gtp_apn-shaper
                 - log.fortianalyzer3_filter
                 - system_email-server
                 - log.tacacs+accounting_filter
                 - dlp_sensor
                 - automation_setting
                 - application_list
                 - firewall_internet-service-append
                 - vpn.ssl.web_user-bookmark
                 - report_theme
                 - firewall.shaper_traffic-shaper
                 - switch-controller_traffic-policy
                 - system_csf
                 - dlp_settings
                 - log.syslogd_setting
                 - switch-controller.ptp_policy
                 - switch-controller_stp-instance
                 - wireless-controller.hotspot20_h2qp-advice-of-charge
                 - mgmt-data_status
                 - dnsfilter_profile
                 - user_device-access-list
                 - system_ha-monitor
                 - monitoring_npu-hpe
                 - system.replacemsg_nntp
                 - wireless-controller.hotspot20_anqp-venue-name
                 - system.snmp_sysinfo
                 - system_fortiai
                 - application_custom
                 - ips_session
                 - system_api-user
                 - system.info.admin_ssh
                 - ips_rule
                 - spamfilter_fortishield
                 - log.fortianalyzer-cloud_filter
                 - system_netflow
                 - vpn.ipsec_forticlient
                 - system_automation-trigger
                 - firewall_policy64
                 - wireless-controller.hotspot20_h2qp-osu-provider
                 - webfilter_ips-urlfilter-setting6
                 - switch-controller_sflow
                 - firewall.service_custom
                 - spamfilter_iptrust
                 - firewall_internet-service-botnet
                 - firewall_internet-service-definition
                 - gtp_rat-timeout-profile
                 - system_mobile-tunnel
                 - log.syslogd3_override-setting
                 - wireless-controller_nac-profile
                 - user_saml
                 - firewall_ttl-policy
                 - wireless-controller_client-info
                 - system_vne-tunnel
                 - system.snmp_mib-view
                 - webfilter_fortiguard
                 - gtp_apn
                 - vpn_pptp
                 - wireless-controller.hotspot20_hs-profile
                 - log.webtrends_setting
                 - firewall_local-in-policy
                 - extender-controller_dataplan
                 - system_gi-gk
                 - wireless-controller_region
                 - router_policy
                 - switch-controller_port-policy
                 - switch-controller.qos_dot1p-map
                 - firewall_multicast-policy6
                 - switch-controller.initial-config_vlans
                 - system_federated-upgrade
                 - wanopt_content-delivery-network-rule
                 - firewall_region
                 - system_dns-database
                 - vpn.ipsec_fec
                 - waf_main-class
                 - system.replacemsg_nac-quar
                 - system_vdom-radius-server
                 - system_vdom
                 - user_tacacs+
                 - system_ipip-tunnel
                 - log.syslogd3_setting
                 - extender_fexwan
                 - wireless-controller_mpsk-profile
                 - system_lte-modem
                 - router_multicast6
                 - vpn.certificate_remote
                 - extender_lte-carrier-list
                 - system_fips-cc
                 - switch-controller_snmp-community
                 - system_geneve
                 - system_ha
                 - log.syslogd3_filter
                 - user_radius
                 - firewall_DoS-policy6
                 - switch-controller.auto-config_default
                 - system_tos-based-priority
                 - vpn.certificate_local
                 - system_accprofile
                 - wireless-controller_global
                 - log.syslogd_filter
                 - vpn.status_l2tp
                 - system_ipsec-aggregate
                 - wireless-controller_ap-status
                 - switch-controller_poe
                 - log.syslogd2_filter
                 - log.syslogd2_setting
                 - system_password-policy-guest-admin
                 - user_pop3
                 - switch-controller_vlan-policy
                 - system_geoip-country
                 - switch-controller_system
                 - videofilter_youtube-channel-filter
                 - voip_profile
                 - vpn.ipsec_manualkey-interface
                 - emailfilter_options
                 - system.info.admin_status
                 - switch-controller_snmp-sysinfo
                 - firewall_internet-service-sld
                 - system_vdom-netflow
                 - firewall.ipmacbinding_table
                 - system_automation-destination
                 - dlp_fp-doc-source
                 - firewall_ldb-monitor
                 - firewall.ssh_host-key
                 - system_vdom-link
                 - spamfilter_dnsbl
                 - system_fortianalyzer-connectivity
                 - router_ospf6
                 - user_device
                 - log.fortiguard_setting
                 - system.snmp_community
                 - wireless-controller_arrp-profile
                 - ips_settings
                 - firewall_internet-service-ipbl-vendor
                 - system_vdom-exception
                 - system_wccp
                 - antivirus_mms-checksum
                 - router_info6
                 - system_ha-nonsync-csum
                 - system_automation-stitch
                 - system_mem-mgr
                 - firewall_profile-protocol-options
                 - router_prefix-list
                 - wireless-controller.hotspot20_anqp-venue-url
                 - firewall.ssh_local-key
                 - system_mgmt-csum
                 - endpoint-control_profile
                 - firewall_vip64
                 - dlp_profile
                 - web-proxy_wisp
                 - switch-controller_switch-profile
                 - system.checksum_status
                 - endpoint-control_forticlient-ems
                 - system_dns-server
                 - system.replacemsg_alertmail
                 - log.fortiguard_override-filter
                 - endpoint-control_client
                 - firewall_access-proxy-ssh-client-cert
                 - system_fortiguard
                 - web-proxy_global
                 - extender_datachannel-info
                 - wanopt_profile
                 - system_management-tunnel
                 - wireless-controller_scan
                 - system.replacemsg_ec
                 - report_setting
                 - firewall.service_group
                 - switch-controller_snmp-trap-threshold
                 - webfilter_search-engine
                 - system_ipv6-tunnel
                 - firewall.iprope.appctrl_list
                 - user_device-group
                 - user_fsso-polling
                 - system.dhcp_server
                 - report_chart
                 - vpn.certificate_setting
                 - router_bfd6
                 - router_access-list
                 - system.session-info_statistics
                 - firewall_proxy-policy
                 - system_dns
                 - icap_profile
                 - firewall_internet-service-ipbl-reason
                 - webfilter_override-usr
                 - system_session
                 - dnsfilter_domain-filter
                 - report.sql_status
                 - switch-controller.auto-config_custom
                 - wireless-controller_vap-group
                 - emailfilter_iptrust
                 - antivirus_profile
                 - system_startup-error-log
                 - firewall_internet-service-name
                 - system_affinity-interrupt
                 - firewall_shaping-profile
                 - log.syslogd4_override-setting
                 - firewall_interface-policy6
                 - vpn.ipsec_manualkey
                 - firewall.shaper_per-ip
                 - firewall_vendor-mac
                 - switch-controller_global
                 - router_setting
                 - user_local
                 - firewall.schedule_recurring
                 - system_sit-tunnel
                 - system_arp-table
                 - firewall_carrier-endpoint-bwl
                 - switch-controller_lldp-settings
                 - webfilter_content-header
                 - system_auto-install
                 - log.fortianalyzer3_override-setting
                 - user_domain-controller
                 - wireless-controller_wtp-status
                 - firewall_ssl-server
                 - system.replacemsg_traffic-quota
                 - system_virtual-wire-pair
                 - system_mac-address-table
                 - system.replacemsg_automation
                 - firewall_internet-service-owner
                 - system_network-visibility
                 - log.syslogd_override-filter
                 - switch-controller_nac-settings
                 - firewall_interface-policy
                 - extender_extender-info
                 - system.replacemsg_fortiguard-wf
                 - system_nat64
                 - wireless-controller_bonjour-profile
                 - system_sdwan
                 - webfilter_urlfilter
                 - wireless-controller_spectral-info
                 - credential-store_domain-controller
                 - hardware.npu.np6_synproxy-stats
                 - system_probe-response
                 - wireless-controller.hotspot20_h2qp-operator-name
                 - wireless-controller_access-control-list
                 - cifs_profile
                 - system.replacemsg_utm
                 - extender_sys-info
                 - wireless-controller.hotspot20_anqp-roaming-consortium
                 - firewall_DoS-policy
                 - firewall_proxy-addrgrp
                 - firewall_addrgrp
                 - system_sflow
                 - router_ripng
                 - firewall_vip6
                 - wireless-controller_syslog-profile
                 - system.replacemsg_spam
                 - certificate_ca
                 - firewall.ssh_local-ca
                 - system_admin
                 - wireless-controller.hotspot20_h2qp-conn-capability
                 - switch-controller_location
                 - firewall.consolidated_policy
                 - router_access-list6
                 - hardware.npu.np6_dce
                 - waf_profile
                 - firewall.wildcard-fqdn_group
                 - system_gre-tunnel
                 - user_group
                 - log.syslogd2_override-setting
                 - user_krb-keytab
                 - firewall.iprope_list
                 - system_ptp
                 - dpdk_global
                 - application_group
                 - system.replacemsg_ftp
                 - log_threat-weight
                 - extender-controller_extender
                 - firewall_access-proxy6
                 - system_session6
                 - switch-controller_managed-switch
                 - system_ike

    selector:
        description:
            - selector for retrieving the fortigate facts
        type: str
        required: false
        choices:
         - log_gui-display
         - system_fortiguard-service
         - router_route-map
         - system_sso-admin
         - wireless-controller_address
         - vpn.ssl_monitor
         - system.auto-update_status
         - system_cmdb
         - authentication_rule
         - log.fortianalyzer_override-setting
         - firewall.ssl_setting
         - vpn.ipsec_phase2-interface
         - router_key-chain
         - system_ddns
         - firewall_traffic-class
         - system_replacemsg-group
         - system_ftm-push
         - system_sms-server
         - firewall_central-snat-map
         - firewall_multicast-address6
         - dlp_fp-sensitivity
         - system.replacemsg_sslvpn
         - ips_view-map
         - firewall_pfcp
         - system_pppoe-interface
         - webfilter_categories
         - firewall_addrgrp6
         - log.disk_filter
         - system.session-info_full-stat
         - firewall_proxy-address
         - extender-controller_extender-profile
         - emailfilter_block-allow-list
         - router_bgp
         - router_auth-path
         - system_resource-limits
         - system.replacemsg_auth
         - system.autoupdate_schedule
         - switch-controller.qos_ip-dscp-map
         - firewall_local-in-policy6
         - log.fortianalyzer2_override-setting
         - wireless-controller.hotspot20_h2qp-osu-provider-nai
         - log.fortianalyzer_override-filter
         - system.replacemsg_icap
         - system_object-tagging
         - spamfilter_profile
         - switch-controller_remote-log
         - router_rip
         - switch-controller.security-policy_local-access
         - vpn.ipsec.stats_tunnel
         - log.fortianalyzer-cloud_override-filter
         - firewall.shaper_traffic
         - system_smc-ntp
         - user_adgrp
         - system_auto-script
         - switch-controller_quarantine
         - firewall.service_category
         - system_standalone-cluster
         - system_link-monitor
         - switch-controller_stp-settings
         - user_security-exempt-list
         - log.fortianalyzer-cloud_setting
         - switch-controller.qos_qos-policy
         - firewall_sniffer
         - wireless-controller_ssid-policy
         - wireless-controller_wag-profile
         - firewall_internet-service-reputation
         - switch-controller_vlan
         - system.replacemsg_mm7
         - system.replacemsg_mm4
         - firewall_internet-service
         - system.replacemsg_mm3
         - system.replacemsg_mm1
         - firewall.iprope.appctrl_status
         - firewall_vipgrp46
         - log.webtrends_filter
         - application_name
         - system_sso-forticloud-admin
         - gtp_apngrp
         - log_setting
         - firewall_address6-template
         - wireless-controller.hotspot20_anqp-3gpp-cellular
         - wireless-controller.hotspot20_h2qp-wan-metric
         - system_automation-action
         - system.autoupdate_tunneling
         - router_prefix-list6
         - webfilter_ips-urlfilter-setting
         - pfcp_message-filter
         - switch-controller_network-monitor-settings
         - system_alias
         - file-filter_profile
         - web-proxy_forward-server-group
         - system_session-helper
         - router_community-list
         - wireless-controller_qos-profile
         - extender_session-info
         - firewall_dnstranslation
         - vpn.ssl.web_portal
         - firewall_internet-service-custom
         - system.replacemsg_device-detection-portal
         - wireless-controller_ble-profile
         - firewall_internet-service-custom-group
         - system.performance.firewall_statistics
         - firewall_profile-group
         - system_vxlan
         - system.autoupdate_push-update
         - firewall_address6
         - system.performance_top
         - wireless-controller_vap-status
         - wireless-controller_wids-profile
         - emailfilter_bword
         - log.fortiguard_filter
         - firewall_ipv6-eh-filter
         - switch-controller.ptp_settings
         - endpoint-control_fctems
         - user_device-category
         - firewall_identity-based-route
         - system.session-helper-info_list
         - system_console
         - certificate_local
         - system_ntp
         - webfilter_ftgd-local-cat
         - report_layout
         - log.tacacs+accounting3_setting
         - wireless-controller_timers
         - wireless-controller.hotspot20_icon
         - log.tacacs+accounting2_filter
         - log.memory_global-setting
         - router_multicast-flow
         - ssh-filter_profile
         - system_fortisandbox
         - system_dns64
         - system_virtual-wan-link
         - ips_sensor
         - firewall.wildcard-fqdn_custom
         - router_static
         - alertemail_setting
         - user_peergrp
         - user_fortitoken
         - web-proxy_debug-url
         - dlp_dictionary
         - vpn.ike_gateway
         - webfilter_override
         - switch-controller_nac-device
         - system_fsso-polling
         - user_peer
         - vpn.ssl.web_host-check-software
         - gtp_message-filter-v0v1
         - switch-controller_lldp-profile
         - switch-controller_dynamic-port-policy
         - vpn.ssl.web_realm
         - system_stp
         - log.tacacs+accounting_setting
         - user_nac-policy
         - wireless-controller_snmp
         - emailfilter_fortishield
         - switch-controller.security-policy_captive-portal
         - firewall_shaping-policy
         - wireless-controller_wlchanlistlic
         - log_custom-field
         - switch-controller_mac-policy
         - firewall_address
         - certificate_crl
         - firewall.ssh_setting
         - switch-controller.auto-config_policy
         - system_nd-proxy
         - log.memory_setting
         - system_alarm
         - system_ips-urlfilter-dns6
         - wireless-controller_log
         - extender_lte-carrier-by-mcc-mnc
         - webfilter_ftgd-statistics
         - hardware.npu.np6_ipsec-stats
         - firewall_vendor-mac-summary
         - system_cluster-sync
         - wanopt_settings
         - emailfilter_dnsbl
         - endpoint-control_registered-forticlient
         - system_dedicated-mgmt
         - log.tacacs+accounting3_filter
         - log.fortianalyzer-cloud_override-setting
         - firewall_policy46
         - system.source-ip_status
         - system_modem
         - certificate_remote
         - firewall_decrypted-traffic-mirror
         - antivirus_settings
         - switch-controller_storm-control-policy
         - switch-controller_802-1X-settings
         - system_session-ttl
         - system_storage
         - system_isf-queue-profile
         - log.memory_filter
         - firewall_auth-portal
         - antivirus_notification
         - user_ldap
         - ips_global
         - wanopt_remote-storage
         - system_speed-test-schedule
         - wireless-controller.hotspot20_qos-map
         - system.session-info_ttl
         - vpn_l2tp
         - monitoring_np6-ipsec-engine
         - system_npu
         - firewall_vip46
         - authentication_setting
         - vpn.certificate_ocsp-server
         - antivirus_heuristic
         - spamfilter_bword
         - system_custom-language
         - web-proxy_explicit
         - vpn.ipsec_concentrator
         - wireless-controller_wtp-group
         - log.tacacs+accounting2_setting
         - system_vdom-sflow
         - switch-controller_igmp-snooping
         - waf_signature
         - log.null-device_setting
         - gtp_tunnel-limit
         - ips_rule-settings
         - firewall_access-proxy
         - system.session-info_expectation
         - spamfilter_options
         - switch-controller.security-policy_802-1X
         - system_np6
         - ips_decoder
         - firewall_proute6
         - user_setting
         - system.performance_status
         - system_geoip-override
         - vpn.ipsec_phase1
         - vpn.ipsec_phase2
         - wireless-controller.hotspot20_anqp-network-auth-type
         - webfilter_ips-urlfilter-cache-setting
         - firewall.ipmacbinding_setting
         - log.fortianalyzer2_filter
         - system.ip-conflict_status
         - application_rule-settings
         - switch-controller_flow-tracking
         - log.syslogd4_filter
         - system_speed-test-server
         - firewall_acl
         - system_proxy-arp
         - webfilter_ftgd-local-rating
         - switch-controller_snmp-user
         - nsxt_setting
         - ips_custom
         - switch-controller_switch-interface-tag
         - router_policy6
         - waf_sub-class
         - web-proxy_forward-server
         - log_eventfilter
         - system_vdom-property
         - switch-controller_traffic-sniffer
         - firewall_security-policy
         - system_external-resource
         - user_exchange
         - sctp-filter_profile
         - system_ipv6-neighbor-cache
         - vpn.ipsec.tunnel_details
         - report_style
         - log.syslogd2_override-filter
         - wireless-controller_wtp
         - wireless-controller_rf-analysis
         - wanopt_peer
         - system_saml
         - system.dhcp6_server
         - emailfilter_profile
         - hardware.npu.np6_sse-stats
         - log.fortianalyzer3_override-filter
         - hardware_status
         - firewall_multicast-policy
         - vpn_ocvpn
         - system.replacemsg_mms
         - spamfilter_bwl
         - switch-controller_fortilink-settings
         - system_arp
         - firewall_internet-service-addition
         - webfilter_status
         - system_ips
         - emailfilter_bwl
         - system_password-policy
         - report_dataset
         - switch-controller_virtual-port-pool
         - wireless-controller_setting
         - system.3g-modem_custom
         - wireless-controller.hotspot20_anqp-ip-address-type
         - firewall_vipgrp
         - firewall_city
         - web-proxy_profile
         - system_switch-interface
         - router_isis
         - firewall_policy
         - log.syslogd_override-setting
         - hardware_memory
         - router_info
         - system.performance.firewall_packet-distribution
         - switch-controller_mac-sync-settings
         - webfilter_content
         - firewall_vipgrp6
         - switch-controller.initial-config_template
         - spamfilter_mheader
         - firewall.schedule_onetime
         - vpn.status_pptp
         - gtp_ie-allow-list
         - log.fortianalyzer_setting
         - videofilter_youtube-key
         - vpn.ipsec.tunnel_name
         - firewall_ippool6
         - wireless-controller_status
         - system_central-management
         - system.replacemsg_http
         - vpn.status.ssl_list
         - vpn.ipsec.tunnel_summary
         - hardware.npu.np6_session-stats
         - cifs_domain-controller
         - firewall_policy6
         - system_zone
         - system_vdom-dns
         - firewall_multicast-address
         - wireless-controller_wtp-profile
         - vpn.ssl_settings
         - router_ospf
         - switch-controller.qos_queue-policy
         - dpdk_cpus
         - wireless-controller.hotspot20_h2qp-terms-and-conditions
         - router_static6
         - ftp-proxy_explicit
         - hardware.npu.np6_port-list
         - system_fortimanager
         - system.lldp_network-policy
         - vpn.certificate_crl
         - system.replacemsg_admin
         - router_multicast
         - webfilter_profile
         - switch-controller_storm-control
         - firewall_ssl-ssh-profile
         - vpn.ssl_client
         - gtp_ie-white-list
         - firewall_country
         - user_certificate
         - log.disk_setting
         - nsxt_service-chain
         - dlp_filepattern
         - firewall_acl6
         - firewall_ippool
         - web-proxy_url-match
         - vpn.status.ssl_hw-acceleration-status
         - system_interface
         - log.syslogd3_override-filter
         - router_bfd
         - switch-controller_custom-command
         - dlp_data-type
         - firewall_internet-service-extension
         - system.replacemsg_webproxy
         - user_password-policy
         - wireless-controller_inter-controller
         - system_fortindr
         - log.syslogd4_setting
         - log.fortianalyzer_filter
         - hardware_cpu
         - switch-controller_switch-group
         - user_fsso
         - emailfilter_mheader
         - firewall_vipgrp64
         - user_quarantine
         - system_ips-urlfilter-dns
         - wireless-controller_addrgrp
         - system_fm
         - wireless-controller_apcfg-profile
         - system_global
         - vpn.ipsec.stats_crypto
         - wireless-controller.hotspot20_anqp-nai-realm
         - system_physical-switch
         - system_affinity-packet-redistribution
         - system_status
         - firewall_gtp
         - log.fortiguard_override-setting
         - firewall_proute
         - videofilter_profile
         - log.fortianalyzer3_setting
         - system.auto-update_versions
         - firewall_vip
         - system_virtual-switch
         - firewall_mms-profile
         - wanopt_auth-group
         - wanopt_webcache
         - system.snmp_user
         - firewall_ip-translation
         - system_settings
         - log.fortianalyzer2_setting
         - wireless-controller_vap
         - ipsec_tunnel
         - wanopt_cache-service
         - log.syslogd4_override-filter
         - switch-controller_switch-log
         - firewall_internet-service-group
         - system.replacemsg_mail
         - extender_modem-status
         - system_replacemsg-image
         - system_acme
         - antivirus_quarantine
         - log.fortianalyzer2_override-filter
         - system.session-info_list
         - vpn.certificate_ca
         - endpoint-control_forticlient-registration-sync
         - system_sdn-connector
         - vpn.ssl.web_user-group-bookmark
         - system_fortiguard-log-service
         - endpoint-control_settings
         - system_central-mgmt
         - hardware_nic
         - log.null-device_filter
         - gtp_message-filter-v2
         - firewall.shaper_per-ip-shaper
         - wireless-controller_utm-profile
         - icap_server-group
         - router_aspath-list
         - firewall.schedule_group
         - system_ipam
         - firewall_internet-service-list
         - system_dscp-based-priority
         - dlp_sensitivity
         - icap_server
         - vpn.ipsec_phase1-interface
         - authentication_scheme
         - firewall_access-proxy-virtual-host
         - gtp_apn-shaper
         - log.fortianalyzer3_filter
         - system_email-server
         - log.tacacs+accounting_filter
         - dlp_sensor
         - automation_setting
         - application_list
         - firewall_internet-service-append
         - vpn.ssl.web_user-bookmark
         - report_theme
         - firewall.shaper_traffic-shaper
         - switch-controller_traffic-policy
         - system_csf
         - dlp_settings
         - log.syslogd_setting
         - switch-controller.ptp_policy
         - switch-controller_stp-instance
         - wireless-controller.hotspot20_h2qp-advice-of-charge
         - mgmt-data_status
         - dnsfilter_profile
         - user_device-access-list
         - system_ha-monitor
         - monitoring_npu-hpe
         - system.replacemsg_nntp
         - wireless-controller.hotspot20_anqp-venue-name
         - system.snmp_sysinfo
         - system_fortiai
         - application_custom
         - ips_session
         - system_api-user
         - system.info.admin_ssh
         - ips_rule
         - spamfilter_fortishield
         - log.fortianalyzer-cloud_filter
         - system_netflow
         - vpn.ipsec_forticlient
         - system_automation-trigger
         - firewall_policy64
         - wireless-controller.hotspot20_h2qp-osu-provider
         - webfilter_ips-urlfilter-setting6
         - switch-controller_sflow
         - firewall.service_custom
         - spamfilter_iptrust
         - firewall_internet-service-botnet
         - firewall_internet-service-definition
         - gtp_rat-timeout-profile
         - system_mobile-tunnel
         - log.syslogd3_override-setting
         - wireless-controller_nac-profile
         - user_saml
         - firewall_ttl-policy
         - wireless-controller_client-info
         - system_vne-tunnel
         - system.snmp_mib-view
         - webfilter_fortiguard
         - gtp_apn
         - vpn_pptp
         - wireless-controller.hotspot20_hs-profile
         - log.webtrends_setting
         - firewall_local-in-policy
         - extender-controller_dataplan
         - system_gi-gk
         - wireless-controller_region
         - router_policy
         - switch-controller_port-policy
         - switch-controller.qos_dot1p-map
         - firewall_multicast-policy6
         - switch-controller.initial-config_vlans
         - system_federated-upgrade
         - wanopt_content-delivery-network-rule
         - firewall_region
         - system_dns-database
         - vpn.ipsec_fec
         - waf_main-class
         - system.replacemsg_nac-quar
         - system_vdom-radius-server
         - system_vdom
         - user_tacacs+
         - system_ipip-tunnel
         - log.syslogd3_setting
         - extender_fexwan
         - wireless-controller_mpsk-profile
         - system_lte-modem
         - router_multicast6
         - vpn.certificate_remote
         - extender_lte-carrier-list
         - system_fips-cc
         - switch-controller_snmp-community
         - system_geneve
         - system_ha
         - log.syslogd3_filter
         - user_radius
         - firewall_DoS-policy6
         - switch-controller.auto-config_default
         - system_tos-based-priority
         - vpn.certificate_local
         - system_accprofile
         - wireless-controller_global
         - log.syslogd_filter
         - vpn.status_l2tp
         - system_ipsec-aggregate
         - wireless-controller_ap-status
         - switch-controller_poe
         - log.syslogd2_filter
         - log.syslogd2_setting
         - system_password-policy-guest-admin
         - user_pop3
         - switch-controller_vlan-policy
         - system_geoip-country
         - switch-controller_system
         - videofilter_youtube-channel-filter
         - voip_profile
         - vpn.ipsec_manualkey-interface
         - emailfilter_options
         - system.info.admin_status
         - switch-controller_snmp-sysinfo
         - firewall_internet-service-sld
         - system_vdom-netflow
         - firewall.ipmacbinding_table
         - system_automation-destination
         - dlp_fp-doc-source
         - firewall_ldb-monitor
         - firewall.ssh_host-key
         - system_vdom-link
         - spamfilter_dnsbl
         - system_fortianalyzer-connectivity
         - router_ospf6
         - user_device
         - log.fortiguard_setting
         - system.snmp_community
         - wireless-controller_arrp-profile
         - ips_settings
         - firewall_internet-service-ipbl-vendor
         - system_vdom-exception
         - system_wccp
         - antivirus_mms-checksum
         - router_info6
         - system_ha-nonsync-csum
         - system_automation-stitch
         - system_mem-mgr
         - firewall_profile-protocol-options
         - router_prefix-list
         - wireless-controller.hotspot20_anqp-venue-url
         - firewall.ssh_local-key
         - system_mgmt-csum
         - endpoint-control_profile
         - firewall_vip64
         - dlp_profile
         - web-proxy_wisp
         - switch-controller_switch-profile
         - system.checksum_status
         - endpoint-control_forticlient-ems
         - system_dns-server
         - system.replacemsg_alertmail
         - log.fortiguard_override-filter
         - endpoint-control_client
         - firewall_access-proxy-ssh-client-cert
         - system_fortiguard
         - web-proxy_global
         - extender_datachannel-info
         - wanopt_profile
         - system_management-tunnel
         - wireless-controller_scan
         - system.replacemsg_ec
         - report_setting
         - firewall.service_group
         - switch-controller_snmp-trap-threshold
         - webfilter_search-engine
         - system_ipv6-tunnel
         - firewall.iprope.appctrl_list
         - user_device-group
         - user_fsso-polling
         - system.dhcp_server
         - report_chart
         - vpn.certificate_setting
         - router_bfd6
         - router_access-list
         - system.session-info_statistics
         - firewall_proxy-policy
         - system_dns
         - icap_profile
         - firewall_internet-service-ipbl-reason
         - webfilter_override-usr
         - system_session
         - dnsfilter_domain-filter
         - report.sql_status
         - switch-controller.auto-config_custom
         - wireless-controller_vap-group
         - emailfilter_iptrust
         - antivirus_profile
         - system_startup-error-log
         - firewall_internet-service-name
         - system_affinity-interrupt
         - firewall_shaping-profile
         - log.syslogd4_override-setting
         - firewall_interface-policy6
         - vpn.ipsec_manualkey
         - firewall.shaper_per-ip
         - firewall_vendor-mac
         - switch-controller_global
         - router_setting
         - user_local
         - firewall.schedule_recurring
         - system_sit-tunnel
         - system_arp-table
         - firewall_carrier-endpoint-bwl
         - switch-controller_lldp-settings
         - webfilter_content-header
         - system_auto-install
         - log.fortianalyzer3_override-setting
         - user_domain-controller
         - wireless-controller_wtp-status
         - firewall_ssl-server
         - system.replacemsg_traffic-quota
         - system_virtual-wire-pair
         - system_mac-address-table
         - system.replacemsg_automation
         - firewall_internet-service-owner
         - system_network-visibility
         - log.syslogd_override-filter
         - switch-controller_nac-settings
         - firewall_interface-policy
         - extender_extender-info
         - system.replacemsg_fortiguard-wf
         - system_nat64
         - wireless-controller_bonjour-profile
         - system_sdwan
         - webfilter_urlfilter
         - wireless-controller_spectral-info
         - credential-store_domain-controller
         - hardware.npu.np6_synproxy-stats
         - system_probe-response
         - wireless-controller.hotspot20_h2qp-operator-name
         - wireless-controller_access-control-list
         - cifs_profile
         - system.replacemsg_utm
         - extender_sys-info
         - wireless-controller.hotspot20_anqp-roaming-consortium
         - firewall_DoS-policy
         - firewall_proxy-addrgrp
         - firewall_addrgrp
         - system_sflow
         - router_ripng
         - firewall_vip6
         - wireless-controller_syslog-profile
         - system.replacemsg_spam
         - certificate_ca
         - firewall.ssh_local-ca
         - system_admin
         - wireless-controller.hotspot20_h2qp-conn-capability
         - switch-controller_location
         - firewall.consolidated_policy
         - router_access-list6
         - hardware.npu.np6_dce
         - waf_profile
         - firewall.wildcard-fqdn_group
         - system_gre-tunnel
         - user_group
         - log.syslogd2_override-setting
         - user_krb-keytab
         - firewall.iprope_list
         - system_ptp
         - dpdk_global
         - application_group
         - system.replacemsg_ftp
         - log_threat-weight
         - extender-controller_extender
         - firewall_access-proxy6
         - system_session6
         - switch-controller_managed-switch
         - system_ike

    params:
        description:
            - the parameter for each selector, see definition in above list.
        type: dict
        required: false
"""

EXAMPLES = """
- hosts: fortigateslab
  connection: httpapi
  collections:
    - fortinet.fortios
  vars:
    ansible_httpapi_use_ssl: yes
    ansible_httpapi_validate_certs: no
    ansible_httpapi_port: 443
    vdom: "root"
  tasks:
  - name: Get multiple selectors info concurrently
    fortios_configuration_fact:
      selectors:
        - selector: firewall_address
          params:
            name: "gmail.com"
        - selector: system_interface
        - selector: log_eventfilter
          params: {}

  - name: fact gathering
    fortios_configuration_fact:
        vdom: ""
        filters:
            - name==port1
            - vlanid==0
        sorters:
            - name,vlanid
            - management-ip
        formatters:
         - name
         - management-ip
         - vlanid
        selector: 'system_interface'

  - name: get all
    fortios_configuration_fact:
      vdom: ""
      access_token: ""
      selector: log_custom-field

  - name: get single
    fortios_configuration_fact:
      vdom: ""
      access_token: ""
      selector: log_custom-field
      #optionally list or single get
      params:
        id: "3"

  - name: fetch one firewall address
    fortios_configuration_fact:
      selector: firewall_address
      params:
        name: "login.microsoft.com"

  - name: fetch all firewall addresses
    fortios_configuration_fact:
      selector: firewall_address
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
  sample: 'GET'
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: str
  sample: "firmware"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "system"
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
ansible_facts:
  description: The list of fact subsets collected from the device
  returned: always
  type: dict

"""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    FortiOSHandler,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_legacy_fortiosapi,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import (
    FAIL_SOCKET_MSG,
)

MODULE_MKEY_DEFINITONS = {
    "log_gui-display": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_fortiguard-service": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_route-map": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_sso-admin": {
        "mkey_type": str,
        "mkey": "name",
    },
    "wireless-controller_address": {
        "mkey_type": str,
        "mkey": "id",
    },
    "vpn.ssl_monitor": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.auto-update_status": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_cmdb": {
        "mkey_type": None,
        "mkey": "None",
    },
    "authentication_rule": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.fortianalyzer_override-setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall.ssl_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "vpn.ipsec_phase2-interface": {
        "mkey_type": str,
        "mkey": "name",
    },
    "router_key-chain": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_ddns": {
        "mkey_type": int,
        "mkey": "ddnsid",
    },
    "firewall_traffic-class": {
        "mkey_type": int,
        "mkey": "class_id",
    },
    "system_replacemsg-group": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_ftm-push": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_sms-server": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_central-snat-map": {
        "mkey_type": int,
        "mkey": "policyid",
    },
    "firewall_multicast-address6": {
        "mkey_type": str,
        "mkey": "name",
    },
    "dlp_fp-sensitivity": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.replacemsg_sslvpn": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "ips_view-map": {
        "mkey_type": int,
        "mkey": "id",
    },
    "firewall_pfcp": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_pppoe-interface": {
        "mkey_type": str,
        "mkey": "name",
    },
    "webfilter_categories": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_addrgrp6": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.disk_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.session-info_full-stat": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_proxy-address": {
        "mkey_type": str,
        "mkey": "name",
    },
    "extender-controller_extender-profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "emailfilter_block-allow-list": {
        "mkey_type": int,
        "mkey": "id",
    },
    "router_bgp": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_auth-path": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_resource-limits": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.replacemsg_auth": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "system.autoupdate_schedule": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch-controller.qos_ip-dscp-map": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_local-in-policy6": {
        "mkey_type": int,
        "mkey": "policyid",
    },
    "log.fortianalyzer2_override-setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wireless-controller.hotspot20_h2qp-osu-provider-nai": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.fortianalyzer_override-filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.replacemsg_icap": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "system_object-tagging": {
        "mkey_type": str,
        "mkey": "category",
    },
    "spamfilter_profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch-controller_remote-log": {
        "mkey_type": str,
        "mkey": "name",
    },
    "router_rip": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch-controller.security-policy_local-access": {
        "mkey_type": str,
        "mkey": "name",
    },
    "vpn.ipsec.stats_tunnel": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.fortianalyzer-cloud_override-filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall.shaper_traffic": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_smc-ntp": {
        "mkey_type": None,
        "mkey": "None",
    },
    "user_adgrp": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_auto-script": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch-controller_quarantine": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall.service_category": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_standalone-cluster": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_link-monitor": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch-controller_stp-settings": {
        "mkey_type": None,
        "mkey": "None",
    },
    "user_security-exempt-list": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.fortianalyzer-cloud_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch-controller.qos_qos-policy": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_sniffer": {
        "mkey_type": int,
        "mkey": "id",
    },
    "wireless-controller_ssid-policy": {
        "mkey_type": str,
        "mkey": "name",
    },
    "wireless-controller_wag-profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_internet-service-reputation": {
        "mkey_type": int,
        "mkey": "id",
    },
    "switch-controller_vlan": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.replacemsg_mm7": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "system.replacemsg_mm4": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "firewall_internet-service": {
        "mkey_type": int,
        "mkey": "id",
    },
    "system.replacemsg_mm3": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "system.replacemsg_mm1": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "firewall.iprope.appctrl_status": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_vipgrp46": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.webtrends_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "application_name": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_sso-forticloud-admin": {
        "mkey_type": str,
        "mkey": "name",
    },
    "gtp_apngrp": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_address6-template": {
        "mkey_type": str,
        "mkey": "name",
    },
    "wireless-controller.hotspot20_anqp-3gpp-cellular": {
        "mkey_type": str,
        "mkey": "name",
    },
    "wireless-controller.hotspot20_h2qp-wan-metric": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_automation-action": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.autoupdate_tunneling": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_prefix-list6": {
        "mkey_type": str,
        "mkey": "name",
    },
    "webfilter_ips-urlfilter-setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "pfcp_message-filter": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch-controller_network-monitor-settings": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_alias": {
        "mkey_type": str,
        "mkey": "name",
    },
    "file-filter_profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "web-proxy_forward-server-group": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_session-helper": {
        "mkey_type": int,
        "mkey": "id",
    },
    "router_community-list": {
        "mkey_type": str,
        "mkey": "name",
    },
    "wireless-controller_qos-profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "extender_session-info": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_dnstranslation": {
        "mkey_type": int,
        "mkey": "id",
    },
    "vpn.ssl.web_portal": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_internet-service-custom": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.replacemsg_device-detection-portal": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "wireless-controller_ble-profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_internet-service-custom-group": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.performance.firewall_statistics": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_profile-group": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_vxlan": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.autoupdate_push-update": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_address6": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.performance_top": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wireless-controller_vap-status": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wireless-controller_wids-profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "emailfilter_bword": {
        "mkey_type": int,
        "mkey": "id",
    },
    "log.fortiguard_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_ipv6-eh-filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch-controller.ptp_settings": {
        "mkey_type": None,
        "mkey": "None",
    },
    "endpoint-control_fctems": {
        "mkey_type": str,
        "mkey": "name",
    },
    "user_device-category": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_identity-based-route": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.session-helper-info_list": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_console": {
        "mkey_type": None,
        "mkey": "None",
    },
    "certificate_local": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_ntp": {
        "mkey_type": None,
        "mkey": "None",
    },
    "webfilter_ftgd-local-cat": {
        "mkey_type": str,
        "mkey": "desc",
    },
    "report_layout": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.tacacs+accounting3_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wireless-controller_timers": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wireless-controller.hotspot20_icon": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.tacacs+accounting2_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.memory_global-setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_multicast-flow": {
        "mkey_type": str,
        "mkey": "name",
    },
    "ssh-filter_profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_fortisandbox": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_dns64": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_virtual-wan-link": {
        "mkey_type": None,
        "mkey": "None",
    },
    "ips_sensor": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall.wildcard-fqdn_custom": {
        "mkey_type": str,
        "mkey": "name",
    },
    "router_static": {
        "mkey_type": int,
        "mkey": "seq_num",
    },
    "alertemail_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "user_peergrp": {
        "mkey_type": str,
        "mkey": "name",
    },
    "user_fortitoken": {
        "mkey_type": str,
        "mkey": "serial_number",
    },
    "web-proxy_debug-url": {
        "mkey_type": str,
        "mkey": "name",
    },
    "dlp_dictionary": {
        "mkey_type": str,
        "mkey": "name",
    },
    "vpn.ike_gateway": {
        "mkey_type": None,
        "mkey": "None",
    },
    "webfilter_override": {
        "mkey_type": int,
        "mkey": "id",
    },
    "switch-controller_nac-device": {
        "mkey_type": int,
        "mkey": "id",
    },
    "system_fsso-polling": {
        "mkey_type": None,
        "mkey": "None",
    },
    "user_peer": {
        "mkey_type": str,
        "mkey": "name",
    },
    "vpn.ssl.web_host-check-software": {
        "mkey_type": str,
        "mkey": "name",
    },
    "gtp_message-filter-v0v1": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch-controller_lldp-profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch-controller_dynamic-port-policy": {
        "mkey_type": str,
        "mkey": "name",
    },
    "vpn.ssl.web_realm": {
        "mkey_type": str,
        "mkey": "url_path",
    },
    "system_stp": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.tacacs+accounting_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "user_nac-policy": {
        "mkey_type": str,
        "mkey": "name",
    },
    "wireless-controller_snmp": {
        "mkey_type": None,
        "mkey": "None",
    },
    "emailfilter_fortishield": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch-controller.security-policy_captive-portal": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_shaping-policy": {
        "mkey_type": int,
        "mkey": "id",
    },
    "wireless-controller_wlchanlistlic": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log_custom-field": {
        "mkey_type": str,
        "mkey": "id",
    },
    "switch-controller_mac-policy": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_address": {
        "mkey_type": str,
        "mkey": "name",
    },
    "certificate_crl": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall.ssh_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch-controller.auto-config_policy": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_nd-proxy": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.memory_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_alarm": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_ips-urlfilter-dns6": {
        "mkey_type": str,
        "mkey": "address6",
    },
    "wireless-controller_log": {
        "mkey_type": None,
        "mkey": "None",
    },
    "extender_lte-carrier-by-mcc-mnc": {
        "mkey_type": None,
        "mkey": "None",
    },
    "webfilter_ftgd-statistics": {
        "mkey_type": None,
        "mkey": "None",
    },
    "hardware.npu.np6_ipsec-stats": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_vendor-mac-summary": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_cluster-sync": {
        "mkey_type": int,
        "mkey": "sync_id",
    },
    "wanopt_settings": {
        "mkey_type": None,
        "mkey": "None",
    },
    "emailfilter_dnsbl": {
        "mkey_type": int,
        "mkey": "id",
    },
    "endpoint-control_registered-forticlient": {
        "mkey_type": str,
        "mkey": "uid",
    },
    "system_dedicated-mgmt": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.tacacs+accounting3_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.fortianalyzer-cloud_override-setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_policy46": {
        "mkey_type": int,
        "mkey": "policyid",
    },
    "system.source-ip_status": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_modem": {
        "mkey_type": None,
        "mkey": "None",
    },
    "certificate_remote": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_decrypted-traffic-mirror": {
        "mkey_type": str,
        "mkey": "name",
    },
    "antivirus_settings": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch-controller_storm-control-policy": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch-controller_802-1X-settings": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_session-ttl": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_storage": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_isf-queue-profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.memory_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_auth-portal": {
        "mkey_type": None,
        "mkey": "None",
    },
    "antivirus_notification": {
        "mkey_type": int,
        "mkey": "id",
    },
    "user_ldap": {
        "mkey_type": str,
        "mkey": "name",
    },
    "ips_global": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wanopt_remote-storage": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_speed-test-schedule": {
        "mkey_type": str,
        "mkey": "interface",
    },
    "wireless-controller.hotspot20_qos-map": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.session-info_ttl": {
        "mkey_type": None,
        "mkey": "None",
    },
    "vpn_l2tp": {
        "mkey_type": None,
        "mkey": "None",
    },
    "monitoring_np6-ipsec-engine": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_npu": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_vip46": {
        "mkey_type": str,
        "mkey": "name",
    },
    "authentication_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "vpn.certificate_ocsp-server": {
        "mkey_type": str,
        "mkey": "name",
    },
    "antivirus_heuristic": {
        "mkey_type": None,
        "mkey": "None",
    },
    "spamfilter_bword": {
        "mkey_type": int,
        "mkey": "id",
    },
    "system_custom-language": {
        "mkey_type": str,
        "mkey": "name",
    },
    "web-proxy_explicit": {
        "mkey_type": None,
        "mkey": "None",
    },
    "vpn.ipsec_concentrator": {
        "mkey_type": int,
        "mkey": "id",
    },
    "wireless-controller_wtp-group": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.tacacs+accounting2_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_vdom-sflow": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch-controller_igmp-snooping": {
        "mkey_type": None,
        "mkey": "None",
    },
    "waf_signature": {
        "mkey_type": int,
        "mkey": "id",
    },
    "log.null-device_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "gtp_tunnel-limit": {
        "mkey_type": str,
        "mkey": "name",
    },
    "ips_rule-settings": {
        "mkey_type": int,
        "mkey": "id",
    },
    "firewall_access-proxy": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.session-info_expectation": {
        "mkey_type": None,
        "mkey": "None",
    },
    "spamfilter_options": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch-controller.security-policy_802-1X": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_np6": {
        "mkey_type": str,
        "mkey": "name",
    },
    "ips_decoder": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_proute6": {
        "mkey_type": None,
        "mkey": "None",
    },
    "user_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.performance_status": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_geoip-override": {
        "mkey_type": str,
        "mkey": "name",
    },
    "vpn.ipsec_phase1": {
        "mkey_type": str,
        "mkey": "name",
    },
    "vpn.ipsec_phase2": {
        "mkey_type": str,
        "mkey": "name",
    },
    "wireless-controller.hotspot20_anqp-network-auth-type": {
        "mkey_type": str,
        "mkey": "name",
    },
    "webfilter_ips-urlfilter-cache-setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall.ipmacbinding_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.fortianalyzer2_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.ip-conflict_status": {
        "mkey_type": None,
        "mkey": "None",
    },
    "application_rule-settings": {
        "mkey_type": int,
        "mkey": "id",
    },
    "switch-controller_flow-tracking": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.syslogd4_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_speed-test-server": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_acl": {
        "mkey_type": int,
        "mkey": "policyid",
    },
    "system_proxy-arp": {
        "mkey_type": int,
        "mkey": "id",
    },
    "webfilter_ftgd-local-rating": {
        "mkey_type": str,
        "mkey": "url",
    },
    "switch-controller_snmp-user": {
        "mkey_type": str,
        "mkey": "name",
    },
    "nsxt_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "ips_custom": {
        "mkey_type": str,
        "mkey": "tag",
    },
    "switch-controller_switch-interface-tag": {
        "mkey_type": str,
        "mkey": "name",
    },
    "router_policy6": {
        "mkey_type": int,
        "mkey": "seq_num",
    },
    "waf_sub-class": {
        "mkey_type": int,
        "mkey": "id",
    },
    "web-proxy_forward-server": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log_eventfilter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_vdom-property": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch-controller_traffic-sniffer": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_security-policy": {
        "mkey_type": int,
        "mkey": "policyid",
    },
    "system_external-resource": {
        "mkey_type": str,
        "mkey": "name",
    },
    "user_exchange": {
        "mkey_type": str,
        "mkey": "name",
    },
    "sctp-filter_profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_ipv6-neighbor-cache": {
        "mkey_type": int,
        "mkey": "id",
    },
    "vpn.ipsec.tunnel_details": {
        "mkey_type": None,
        "mkey": "None",
    },
    "report_style": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.syslogd2_override-filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wireless-controller_wtp": {
        "mkey_type": str,
        "mkey": "wtp_id",
    },
    "wireless-controller_rf-analysis": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wanopt_peer": {
        "mkey_type": str,
        "mkey": "peer_host_id",
    },
    "system_saml": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.dhcp6_server": {
        "mkey_type": int,
        "mkey": "id",
    },
    "emailfilter_profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "hardware.npu.np6_sse-stats": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.fortianalyzer3_override-filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "hardware_status": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_multicast-policy": {
        "mkey_type": int,
        "mkey": "id",
    },
    "vpn_ocvpn": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.replacemsg_mms": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "spamfilter_bwl": {
        "mkey_type": int,
        "mkey": "id",
    },
    "switch-controller_fortilink-settings": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_arp": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_internet-service-addition": {
        "mkey_type": int,
        "mkey": "id",
    },
    "webfilter_status": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_ips": {
        "mkey_type": None,
        "mkey": "None",
    },
    "emailfilter_bwl": {
        "mkey_type": int,
        "mkey": "id",
    },
    "system_password-policy": {
        "mkey_type": None,
        "mkey": "None",
    },
    "report_dataset": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch-controller_virtual-port-pool": {
        "mkey_type": str,
        "mkey": "name",
    },
    "wireless-controller_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.3g-modem_custom": {
        "mkey_type": int,
        "mkey": "id",
    },
    "wireless-controller.hotspot20_anqp-ip-address-type": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_vipgrp": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_city": {
        "mkey_type": int,
        "mkey": "id",
    },
    "web-proxy_profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_switch-interface": {
        "mkey_type": str,
        "mkey": "name",
    },
    "router_isis": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_policy": {
        "mkey_type": int,
        "mkey": "policyid",
    },
    "log.syslogd_override-setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "hardware_memory": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_info": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.performance.firewall_packet-distribution": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch-controller_mac-sync-settings": {
        "mkey_type": None,
        "mkey": "None",
    },
    "webfilter_content": {
        "mkey_type": int,
        "mkey": "id",
    },
    "firewall_vipgrp6": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch-controller.initial-config_template": {
        "mkey_type": str,
        "mkey": "name",
    },
    "spamfilter_mheader": {
        "mkey_type": int,
        "mkey": "id",
    },
    "firewall.schedule_onetime": {
        "mkey_type": str,
        "mkey": "name",
    },
    "vpn.status_pptp": {
        "mkey_type": None,
        "mkey": "None",
    },
    "gtp_ie-allow-list": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.fortianalyzer_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "videofilter_youtube-key": {
        "mkey_type": int,
        "mkey": "id",
    },
    "vpn.ipsec.tunnel_name": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_ippool6": {
        "mkey_type": str,
        "mkey": "name",
    },
    "wireless-controller_status": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_central-management": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.replacemsg_http": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "vpn.status.ssl_list": {
        "mkey_type": None,
        "mkey": "None",
    },
    "vpn.ipsec.tunnel_summary": {
        "mkey_type": None,
        "mkey": "None",
    },
    "hardware.npu.np6_session-stats": {
        "mkey_type": None,
        "mkey": "None",
    },
    "cifs_domain-controller": {
        "mkey_type": str,
        "mkey": "server_name",
    },
    "firewall_policy6": {
        "mkey_type": int,
        "mkey": "policyid",
    },
    "system_zone": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_vdom-dns": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_multicast-address": {
        "mkey_type": str,
        "mkey": "name",
    },
    "wireless-controller_wtp-profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "vpn.ssl_settings": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_ospf": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch-controller.qos_queue-policy": {
        "mkey_type": str,
        "mkey": "name",
    },
    "dpdk_cpus": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wireless-controller.hotspot20_h2qp-terms-and-conditions": {
        "mkey_type": str,
        "mkey": "name",
    },
    "router_static6": {
        "mkey_type": int,
        "mkey": "seq_num",
    },
    "ftp-proxy_explicit": {
        "mkey_type": None,
        "mkey": "None",
    },
    "hardware.npu.np6_port-list": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_fortimanager": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.lldp_network-policy": {
        "mkey_type": str,
        "mkey": "name",
    },
    "vpn.certificate_crl": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.replacemsg_admin": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "router_multicast": {
        "mkey_type": None,
        "mkey": "None",
    },
    "webfilter_profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch-controller_storm-control": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_ssl-ssh-profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "vpn.ssl_client": {
        "mkey_type": str,
        "mkey": "name",
    },
    "gtp_ie-white-list": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_country": {
        "mkey_type": int,
        "mkey": "id",
    },
    "user_certificate": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.disk_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "nsxt_service-chain": {
        "mkey_type": int,
        "mkey": "id",
    },
    "dlp_filepattern": {
        "mkey_type": int,
        "mkey": "id",
    },
    "firewall_acl6": {
        "mkey_type": int,
        "mkey": "policyid",
    },
    "firewall_ippool": {
        "mkey_type": str,
        "mkey": "name",
    },
    "web-proxy_url-match": {
        "mkey_type": str,
        "mkey": "name",
    },
    "vpn.status.ssl_hw-acceleration-status": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_interface": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.syslogd3_override-filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_bfd": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch-controller_custom-command": {
        "mkey_type": str,
        "mkey": "command_name",
    },
    "dlp_data-type": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_internet-service-extension": {
        "mkey_type": int,
        "mkey": "id",
    },
    "system.replacemsg_webproxy": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "user_password-policy": {
        "mkey_type": str,
        "mkey": "name",
    },
    "wireless-controller_inter-controller": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_fortindr": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.syslogd4_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.fortianalyzer_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "hardware_cpu": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch-controller_switch-group": {
        "mkey_type": str,
        "mkey": "name",
    },
    "user_fsso": {
        "mkey_type": str,
        "mkey": "name",
    },
    "emailfilter_mheader": {
        "mkey_type": int,
        "mkey": "id",
    },
    "firewall_vipgrp64": {
        "mkey_type": str,
        "mkey": "name",
    },
    "user_quarantine": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_ips-urlfilter-dns": {
        "mkey_type": str,
        "mkey": "address",
    },
    "wireless-controller_addrgrp": {
        "mkey_type": str,
        "mkey": "id",
    },
    "system_fm": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wireless-controller_apcfg-profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_global": {
        "mkey_type": None,
        "mkey": "None",
    },
    "vpn.ipsec.stats_crypto": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wireless-controller.hotspot20_anqp-nai-realm": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_physical-switch": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_affinity-packet-redistribution": {
        "mkey_type": int,
        "mkey": "id",
    },
    "system_status": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_gtp": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.fortiguard_override-setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_proute": {
        "mkey_type": None,
        "mkey": "None",
    },
    "videofilter_profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.fortianalyzer3_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.auto-update_versions": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_vip": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_virtual-switch": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_mms-profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "wanopt_auth-group": {
        "mkey_type": str,
        "mkey": "name",
    },
    "wanopt_webcache": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.snmp_user": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_ip-translation": {
        "mkey_type": int,
        "mkey": "transid",
    },
    "system_settings": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.fortianalyzer2_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wireless-controller_vap": {
        "mkey_type": str,
        "mkey": "name",
    },
    "ipsec_tunnel": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wanopt_cache-service": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.syslogd4_override-filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch-controller_switch-log": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_internet-service-group": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.replacemsg_mail": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "extender_modem-status": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_replacemsg-image": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_acme": {
        "mkey_type": None,
        "mkey": "None",
    },
    "antivirus_quarantine": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.fortianalyzer2_override-filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.session-info_list": {
        "mkey_type": None,
        "mkey": "None",
    },
    "vpn.certificate_ca": {
        "mkey_type": str,
        "mkey": "name",
    },
    "endpoint-control_forticlient-registration-sync": {
        "mkey_type": str,
        "mkey": "peer_name",
    },
    "system_sdn-connector": {
        "mkey_type": str,
        "mkey": "name",
    },
    "vpn.ssl.web_user-group-bookmark": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_fortiguard-log-service": {
        "mkey_type": None,
        "mkey": "None",
    },
    "endpoint-control_settings": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_central-mgmt": {
        "mkey_type": None,
        "mkey": "None",
    },
    "hardware_nic": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.null-device_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "gtp_message-filter-v2": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall.shaper_per-ip-shaper": {
        "mkey_type": str,
        "mkey": "name",
    },
    "wireless-controller_utm-profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "icap_server-group": {
        "mkey_type": str,
        "mkey": "name",
    },
    "router_aspath-list": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall.schedule_group": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_ipam": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_internet-service-list": {
        "mkey_type": int,
        "mkey": "id",
    },
    "system_dscp-based-priority": {
        "mkey_type": int,
        "mkey": "id",
    },
    "dlp_sensitivity": {
        "mkey_type": str,
        "mkey": "name",
    },
    "icap_server": {
        "mkey_type": str,
        "mkey": "name",
    },
    "vpn.ipsec_phase1-interface": {
        "mkey_type": str,
        "mkey": "name",
    },
    "authentication_scheme": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_access-proxy-virtual-host": {
        "mkey_type": str,
        "mkey": "name",
    },
    "gtp_apn-shaper": {
        "mkey_type": int,
        "mkey": "id",
    },
    "log.fortianalyzer3_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_email-server": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.tacacs+accounting_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "dlp_sensor": {
        "mkey_type": str,
        "mkey": "name",
    },
    "automation_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "application_list": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_internet-service-append": {
        "mkey_type": None,
        "mkey": "None",
    },
    "vpn.ssl.web_user-bookmark": {
        "mkey_type": str,
        "mkey": "name",
    },
    "report_theme": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall.shaper_traffic-shaper": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch-controller_traffic-policy": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_csf": {
        "mkey_type": None,
        "mkey": "None",
    },
    "dlp_settings": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.syslogd_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch-controller.ptp_policy": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch-controller_stp-instance": {
        "mkey_type": str,
        "mkey": "id",
    },
    "wireless-controller.hotspot20_h2qp-advice-of-charge": {
        "mkey_type": str,
        "mkey": "name",
    },
    "mgmt-data_status": {
        "mkey_type": None,
        "mkey": "None",
    },
    "dnsfilter_profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "user_device-access-list": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_ha-monitor": {
        "mkey_type": None,
        "mkey": "None",
    },
    "monitoring_npu-hpe": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.replacemsg_nntp": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "wireless-controller.hotspot20_anqp-venue-name": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.snmp_sysinfo": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_fortiai": {
        "mkey_type": None,
        "mkey": "None",
    },
    "application_custom": {
        "mkey_type": str,
        "mkey": "tag",
    },
    "ips_session": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_api-user": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.info.admin_ssh": {
        "mkey_type": None,
        "mkey": "None",
    },
    "ips_rule": {
        "mkey_type": str,
        "mkey": "name",
    },
    "spamfilter_fortishield": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.fortianalyzer-cloud_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_netflow": {
        "mkey_type": None,
        "mkey": "None",
    },
    "vpn.ipsec_forticlient": {
        "mkey_type": str,
        "mkey": "realm",
    },
    "system_automation-trigger": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_policy64": {
        "mkey_type": int,
        "mkey": "policyid",
    },
    "wireless-controller.hotspot20_h2qp-osu-provider": {
        "mkey_type": str,
        "mkey": "name",
    },
    "webfilter_ips-urlfilter-setting6": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch-controller_sflow": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall.service_custom": {
        "mkey_type": str,
        "mkey": "name",
    },
    "spamfilter_iptrust": {
        "mkey_type": int,
        "mkey": "id",
    },
    "firewall_internet-service-botnet": {
        "mkey_type": int,
        "mkey": "id",
    },
    "firewall_internet-service-definition": {
        "mkey_type": int,
        "mkey": "id",
    },
    "gtp_rat-timeout-profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_mobile-tunnel": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.syslogd3_override-setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wireless-controller_nac-profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "user_saml": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_ttl-policy": {
        "mkey_type": int,
        "mkey": "id",
    },
    "wireless-controller_client-info": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_vne-tunnel": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.snmp_mib-view": {
        "mkey_type": str,
        "mkey": "name",
    },
    "webfilter_fortiguard": {
        "mkey_type": None,
        "mkey": "None",
    },
    "gtp_apn": {
        "mkey_type": str,
        "mkey": "name",
    },
    "vpn_pptp": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wireless-controller.hotspot20_hs-profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.webtrends_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_local-in-policy": {
        "mkey_type": int,
        "mkey": "policyid",
    },
    "extender-controller_dataplan": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_gi-gk": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wireless-controller_region": {
        "mkey_type": str,
        "mkey": "name",
    },
    "router_policy": {
        "mkey_type": int,
        "mkey": "seq_num",
    },
    "switch-controller_port-policy": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch-controller.qos_dot1p-map": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_multicast-policy6": {
        "mkey_type": int,
        "mkey": "id",
    },
    "switch-controller.initial-config_vlans": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_federated-upgrade": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wanopt_content-delivery-network-rule": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_region": {
        "mkey_type": int,
        "mkey": "id",
    },
    "system_dns-database": {
        "mkey_type": str,
        "mkey": "name",
    },
    "vpn.ipsec_fec": {
        "mkey_type": str,
        "mkey": "name",
    },
    "waf_main-class": {
        "mkey_type": int,
        "mkey": "id",
    },
    "system.replacemsg_nac-quar": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "system_vdom-radius-server": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_vdom": {
        "mkey_type": str,
        "mkey": "name",
    },
    "user_tacacs+": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_ipip-tunnel": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.syslogd3_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "extender_fexwan": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wireless-controller_mpsk-profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_lte-modem": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_multicast6": {
        "mkey_type": None,
        "mkey": "None",
    },
    "vpn.certificate_remote": {
        "mkey_type": str,
        "mkey": "name",
    },
    "extender_lte-carrier-list": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_fips-cc": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch-controller_snmp-community": {
        "mkey_type": int,
        "mkey": "id",
    },
    "system_geneve": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_ha": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.syslogd3_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "user_radius": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_DoS-policy6": {
        "mkey_type": int,
        "mkey": "policyid",
    },
    "switch-controller.auto-config_default": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_tos-based-priority": {
        "mkey_type": int,
        "mkey": "id",
    },
    "vpn.certificate_local": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_accprofile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "wireless-controller_global": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.syslogd_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "vpn.status_l2tp": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_ipsec-aggregate": {
        "mkey_type": str,
        "mkey": "name",
    },
    "wireless-controller_ap-status": {
        "mkey_type": int,
        "mkey": "id",
    },
    "switch-controller_poe": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.syslogd2_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.syslogd2_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_password-policy-guest-admin": {
        "mkey_type": None,
        "mkey": "None",
    },
    "user_pop3": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch-controller_vlan-policy": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_geoip-country": {
        "mkey_type": str,
        "mkey": "id",
    },
    "switch-controller_system": {
        "mkey_type": None,
        "mkey": "None",
    },
    "videofilter_youtube-channel-filter": {
        "mkey_type": int,
        "mkey": "id",
    },
    "voip_profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "vpn.ipsec_manualkey-interface": {
        "mkey_type": str,
        "mkey": "name",
    },
    "emailfilter_options": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.info.admin_status": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch-controller_snmp-sysinfo": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_internet-service-sld": {
        "mkey_type": int,
        "mkey": "id",
    },
    "system_vdom-netflow": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall.ipmacbinding_table": {
        "mkey_type": int,
        "mkey": "seq_num",
    },
    "system_automation-destination": {
        "mkey_type": str,
        "mkey": "name",
    },
    "dlp_fp-doc-source": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_ldb-monitor": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall.ssh_host-key": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_vdom-link": {
        "mkey_type": str,
        "mkey": "name",
    },
    "spamfilter_dnsbl": {
        "mkey_type": int,
        "mkey": "id",
    },
    "system_fortianalyzer-connectivity": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_ospf6": {
        "mkey_type": None,
        "mkey": "None",
    },
    "user_device": {
        "mkey_type": str,
        "mkey": "alias",
    },
    "log.fortiguard_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.snmp_community": {
        "mkey_type": int,
        "mkey": "id",
    },
    "wireless-controller_arrp-profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "ips_settings": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_internet-service-ipbl-vendor": {
        "mkey_type": int,
        "mkey": "id",
    },
    "system_vdom-exception": {
        "mkey_type": int,
        "mkey": "id",
    },
    "system_wccp": {
        "mkey_type": str,
        "mkey": "service_id",
    },
    "antivirus_mms-checksum": {
        "mkey_type": int,
        "mkey": "id",
    },
    "router_info6": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_ha-nonsync-csum": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_automation-stitch": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_mem-mgr": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_profile-protocol-options": {
        "mkey_type": str,
        "mkey": "name",
    },
    "router_prefix-list": {
        "mkey_type": str,
        "mkey": "name",
    },
    "wireless-controller.hotspot20_anqp-venue-url": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall.ssh_local-key": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_mgmt-csum": {
        "mkey_type": None,
        "mkey": "None",
    },
    "endpoint-control_profile": {
        "mkey_type": str,
        "mkey": "profile_name",
    },
    "firewall_vip64": {
        "mkey_type": str,
        "mkey": "name",
    },
    "dlp_profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "web-proxy_wisp": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch-controller_switch-profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.checksum_status": {
        "mkey_type": None,
        "mkey": "None",
    },
    "endpoint-control_forticlient-ems": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_dns-server": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.replacemsg_alertmail": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "log.fortiguard_override-filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "endpoint-control_client": {
        "mkey_type": int,
        "mkey": "id",
    },
    "firewall_access-proxy-ssh-client-cert": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_fortiguard": {
        "mkey_type": None,
        "mkey": "None",
    },
    "web-proxy_global": {
        "mkey_type": None,
        "mkey": "None",
    },
    "extender_datachannel-info": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wanopt_profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_management-tunnel": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wireless-controller_scan": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.replacemsg_ec": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "report_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall.service_group": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch-controller_snmp-trap-threshold": {
        "mkey_type": None,
        "mkey": "None",
    },
    "webfilter_search-engine": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_ipv6-tunnel": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall.iprope.appctrl_list": {
        "mkey_type": None,
        "mkey": "None",
    },
    "user_device-group": {
        "mkey_type": str,
        "mkey": "name",
    },
    "user_fsso-polling": {
        "mkey_type": int,
        "mkey": "id",
    },
    "system.dhcp_server": {
        "mkey_type": int,
        "mkey": "id",
    },
    "report_chart": {
        "mkey_type": str,
        "mkey": "name",
    },
    "vpn.certificate_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_bfd6": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_access-list": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.session-info_statistics": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_proxy-policy": {
        "mkey_type": int,
        "mkey": "policyid",
    },
    "system_dns": {
        "mkey_type": None,
        "mkey": "None",
    },
    "icap_profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_internet-service-ipbl-reason": {
        "mkey_type": int,
        "mkey": "id",
    },
    "webfilter_override-usr": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_session": {
        "mkey_type": None,
        "mkey": "None",
    },
    "dnsfilter_domain-filter": {
        "mkey_type": int,
        "mkey": "id",
    },
    "report.sql_status": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch-controller.auto-config_custom": {
        "mkey_type": str,
        "mkey": "name",
    },
    "wireless-controller_vap-group": {
        "mkey_type": str,
        "mkey": "name",
    },
    "emailfilter_iptrust": {
        "mkey_type": int,
        "mkey": "id",
    },
    "antivirus_profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_startup-error-log": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_internet-service-name": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_affinity-interrupt": {
        "mkey_type": int,
        "mkey": "id",
    },
    "firewall_shaping-profile": {
        "mkey_type": str,
        "mkey": "profile_name",
    },
    "log.syslogd4_override-setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_interface-policy6": {
        "mkey_type": int,
        "mkey": "policyid",
    },
    "vpn.ipsec_manualkey": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall.shaper_per-ip": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_vendor-mac": {
        "mkey_type": int,
        "mkey": "id",
    },
    "switch-controller_global": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "user_local": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall.schedule_recurring": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_sit-tunnel": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_arp-table": {
        "mkey_type": int,
        "mkey": "id",
    },
    "firewall_carrier-endpoint-bwl": {
        "mkey_type": int,
        "mkey": "id",
    },
    "switch-controller_lldp-settings": {
        "mkey_type": None,
        "mkey": "None",
    },
    "webfilter_content-header": {
        "mkey_type": int,
        "mkey": "id",
    },
    "system_auto-install": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.fortianalyzer3_override-setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "user_domain-controller": {
        "mkey_type": str,
        "mkey": "name",
    },
    "wireless-controller_wtp-status": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_ssl-server": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.replacemsg_traffic-quota": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "system_virtual-wire-pair": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_mac-address-table": {
        "mkey_type": str,
        "mkey": "mac",
    },
    "system.replacemsg_automation": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "firewall_internet-service-owner": {
        "mkey_type": int,
        "mkey": "id",
    },
    "system_network-visibility": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.syslogd_override-filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch-controller_nac-settings": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_interface-policy": {
        "mkey_type": int,
        "mkey": "policyid",
    },
    "extender_extender-info": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.replacemsg_fortiguard-wf": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "system_nat64": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wireless-controller_bonjour-profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_sdwan": {
        "mkey_type": None,
        "mkey": "None",
    },
    "webfilter_urlfilter": {
        "mkey_type": int,
        "mkey": "id",
    },
    "wireless-controller_spectral-info": {
        "mkey_type": None,
        "mkey": "None",
    },
    "credential-store_domain-controller": {
        "mkey_type": str,
        "mkey": "server_name",
    },
    "hardware.npu.np6_synproxy-stats": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_probe-response": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wireless-controller.hotspot20_h2qp-operator-name": {
        "mkey_type": str,
        "mkey": "name",
    },
    "wireless-controller_access-control-list": {
        "mkey_type": str,
        "mkey": "name",
    },
    "cifs_profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.replacemsg_utm": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "extender_sys-info": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wireless-controller.hotspot20_anqp-roaming-consortium": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_DoS-policy": {
        "mkey_type": int,
        "mkey": "policyid",
    },
    "firewall_proxy-addrgrp": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_addrgrp": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_sflow": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_ripng": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_vip6": {
        "mkey_type": str,
        "mkey": "name",
    },
    "wireless-controller_syslog-profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.replacemsg_spam": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "certificate_ca": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall.ssh_local-ca": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_admin": {
        "mkey_type": str,
        "mkey": "name",
    },
    "wireless-controller.hotspot20_h2qp-conn-capability": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch-controller_location": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall.consolidated_policy": {
        "mkey_type": int,
        "mkey": "policyid",
    },
    "router_access-list6": {
        "mkey_type": str,
        "mkey": "name",
    },
    "hardware.npu.np6_dce": {
        "mkey_type": None,
        "mkey": "None",
    },
    "waf_profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall.wildcard-fqdn_group": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_gre-tunnel": {
        "mkey_type": str,
        "mkey": "name",
    },
    "user_group": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.syslogd2_override-setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "user_krb-keytab": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall.iprope_list": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_ptp": {
        "mkey_type": None,
        "mkey": "None",
    },
    "dpdk_global": {
        "mkey_type": None,
        "mkey": "None",
    },
    "application_group": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.replacemsg_ftp": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "log_threat-weight": {
        "mkey_type": None,
        "mkey": "None",
    },
    "extender-controller_extender": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_access-proxy6": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_session6": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch-controller_managed-switch": {
        "mkey_type": str,
        "mkey": "switch_id",
    },
    "system_ike": {
        "mkey_type": None,
        "mkey": "None",
    },
}


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


def validate_mkey(params):
    selector = params["selector"]
    selector_params = params.get("params", {})

    if selector not in MODULE_MKEY_DEFINITONS:
        return False, {"message": "unknown selector: " + selector}

    definition = MODULE_MKEY_DEFINITONS.get(selector, {})

    if not selector_params or len(selector_params) == 0 or len(definition) == 0:
        return True, {}

    mkey = definition["mkey"]
    mkey_type = definition["mkey_type"]
    if mkey_type is None:
        return False, {"message": "params are not allowed for " + selector}
    mkey_value = selector_params.get(mkey)

    if not mkey_value:
        return False, {"message": "param '" + mkey + "' is required"}
    if not isinstance(mkey_value, mkey_type):
        return False, {
            "message": "param '"
            + mkey
            + "' does not match, "
            + str(mkey_type)
            + " required"
        }

    return True, {}


def fortios_configuration_fact(params, fos):
    isValid, result = validate_mkey(params)
    if not isValid:
        return True, False, result

    selector = params["selector"]
    selector_params = params["params"]
    mkey_name = MODULE_MKEY_DEFINITONS[selector]["mkey"]
    mkey_value = selector_params.get(mkey_name) if selector_params else None

    [path, name] = selector.split("_")
    # XXX: The plugin level do not accept duplicated url keys, so we make only keep one key here.
    url_params = dict()
    if params["filters"] and len(params["filters"]):
        filter_body = params["filters"][0]
        for filter_item in params["filters"][1:]:
            filter_body = "%s&filter=%s" % (filter_body, filter_item)
        url_params["filter"] = filter_body

    if params["sorters"] and len(params["sorters"]):
        sorter_body = params["sorters"][0]
        for sorter_item in params["sorters"][1:]:
            sorter_body = "%s&sort=%s" % (sorter_body, sorter_item)
        url_params["sort"] = sorter_body

    if params["formatters"] and len(params["formatters"]):
        formatter_body = params["formatters"][0]
        for formatter_item in params["formatters"][1:]:
            formatter_body = "%s|%s" % (formatter_body, formatter_item)
        url_params["format"] = formatter_body

    fact = None
    if mkey_value:
        fact = fos.get(
            path, name, vdom=params["vdom"], mkey=mkey_value, parameters=url_params
        )
    else:
        fact = fos.get(path, name, vdom=params["vdom"], parameters=url_params)

    return not is_successful_status(fact), False, fact


def main():
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "enable_log": {"required": False, "type": "bool", "default": False},
        "filters": {"required": False, "type": "list", "elements": "str"},
        "sorters": {"required": False, "type": "list", "elements": "str"},
        "formatters": {"required": False, "type": "list", "elements": "str"},
        "params": {"required": False, "type": "dict"},
        "selector": {
            "required": False,
            "type": "str",
            "choices": [
                "log_gui-display",
                "system_fortiguard-service",
                "router_route-map",
                "system_sso-admin",
                "wireless-controller_address",
                "vpn.ssl_monitor",
                "system.auto-update_status",
                "system_cmdb",
                "authentication_rule",
                "log.fortianalyzer_override-setting",
                "firewall.ssl_setting",
                "vpn.ipsec_phase2-interface",
                "router_key-chain",
                "system_ddns",
                "firewall_traffic-class",
                "system_replacemsg-group",
                "system_ftm-push",
                "system_sms-server",
                "firewall_central-snat-map",
                "firewall_multicast-address6",
                "dlp_fp-sensitivity",
                "system.replacemsg_sslvpn",
                "ips_view-map",
                "firewall_pfcp",
                "system_pppoe-interface",
                "webfilter_categories",
                "firewall_addrgrp6",
                "log.disk_filter",
                "system.session-info_full-stat",
                "firewall_proxy-address",
                "extender-controller_extender-profile",
                "emailfilter_block-allow-list",
                "router_bgp",
                "router_auth-path",
                "system_resource-limits",
                "system.replacemsg_auth",
                "system.autoupdate_schedule",
                "switch-controller.qos_ip-dscp-map",
                "firewall_local-in-policy6",
                "log.fortianalyzer2_override-setting",
                "wireless-controller.hotspot20_h2qp-osu-provider-nai",
                "log.fortianalyzer_override-filter",
                "system.replacemsg_icap",
                "system_object-tagging",
                "spamfilter_profile",
                "switch-controller_remote-log",
                "router_rip",
                "switch-controller.security-policy_local-access",
                "vpn.ipsec.stats_tunnel",
                "log.fortianalyzer-cloud_override-filter",
                "firewall.shaper_traffic",
                "system_smc-ntp",
                "user_adgrp",
                "system_auto-script",
                "switch-controller_quarantine",
                "firewall.service_category",
                "system_standalone-cluster",
                "system_link-monitor",
                "switch-controller_stp-settings",
                "user_security-exempt-list",
                "log.fortianalyzer-cloud_setting",
                "switch-controller.qos_qos-policy",
                "firewall_sniffer",
                "wireless-controller_ssid-policy",
                "wireless-controller_wag-profile",
                "firewall_internet-service-reputation",
                "switch-controller_vlan",
                "system.replacemsg_mm7",
                "system.replacemsg_mm4",
                "firewall_internet-service",
                "system.replacemsg_mm3",
                "system.replacemsg_mm1",
                "firewall.iprope.appctrl_status",
                "firewall_vipgrp46",
                "log.webtrends_filter",
                "application_name",
                "system_sso-forticloud-admin",
                "gtp_apngrp",
                "log_setting",
                "firewall_address6-template",
                "wireless-controller.hotspot20_anqp-3gpp-cellular",
                "wireless-controller.hotspot20_h2qp-wan-metric",
                "system_automation-action",
                "system.autoupdate_tunneling",
                "router_prefix-list6",
                "webfilter_ips-urlfilter-setting",
                "pfcp_message-filter",
                "switch-controller_network-monitor-settings",
                "system_alias",
                "file-filter_profile",
                "web-proxy_forward-server-group",
                "system_session-helper",
                "router_community-list",
                "wireless-controller_qos-profile",
                "extender_session-info",
                "firewall_dnstranslation",
                "vpn.ssl.web_portal",
                "firewall_internet-service-custom",
                "system.replacemsg_device-detection-portal",
                "wireless-controller_ble-profile",
                "firewall_internet-service-custom-group",
                "system.performance.firewall_statistics",
                "firewall_profile-group",
                "system_vxlan",
                "system.autoupdate_push-update",
                "firewall_address6",
                "system.performance_top",
                "wireless-controller_vap-status",
                "wireless-controller_wids-profile",
                "emailfilter_bword",
                "log.fortiguard_filter",
                "firewall_ipv6-eh-filter",
                "switch-controller.ptp_settings",
                "endpoint-control_fctems",
                "user_device-category",
                "firewall_identity-based-route",
                "system.session-helper-info_list",
                "system_console",
                "certificate_local",
                "system_ntp",
                "webfilter_ftgd-local-cat",
                "report_layout",
                "log.tacacs+accounting3_setting",
                "wireless-controller_timers",
                "wireless-controller.hotspot20_icon",
                "log.tacacs+accounting2_filter",
                "log.memory_global-setting",
                "router_multicast-flow",
                "ssh-filter_profile",
                "system_fortisandbox",
                "system_dns64",
                "system_virtual-wan-link",
                "ips_sensor",
                "firewall.wildcard-fqdn_custom",
                "router_static",
                "alertemail_setting",
                "user_peergrp",
                "user_fortitoken",
                "web-proxy_debug-url",
                "dlp_dictionary",
                "vpn.ike_gateway",
                "webfilter_override",
                "switch-controller_nac-device",
                "system_fsso-polling",
                "user_peer",
                "vpn.ssl.web_host-check-software",
                "gtp_message-filter-v0v1",
                "switch-controller_lldp-profile",
                "switch-controller_dynamic-port-policy",
                "vpn.ssl.web_realm",
                "system_stp",
                "log.tacacs+accounting_setting",
                "user_nac-policy",
                "wireless-controller_snmp",
                "emailfilter_fortishield",
                "switch-controller.security-policy_captive-portal",
                "firewall_shaping-policy",
                "wireless-controller_wlchanlistlic",
                "log_custom-field",
                "switch-controller_mac-policy",
                "firewall_address",
                "certificate_crl",
                "firewall.ssh_setting",
                "switch-controller.auto-config_policy",
                "system_nd-proxy",
                "log.memory_setting",
                "system_alarm",
                "system_ips-urlfilter-dns6",
                "wireless-controller_log",
                "extender_lte-carrier-by-mcc-mnc",
                "webfilter_ftgd-statistics",
                "hardware.npu.np6_ipsec-stats",
                "firewall_vendor-mac-summary",
                "system_cluster-sync",
                "wanopt_settings",
                "emailfilter_dnsbl",
                "endpoint-control_registered-forticlient",
                "system_dedicated-mgmt",
                "log.tacacs+accounting3_filter",
                "log.fortianalyzer-cloud_override-setting",
                "firewall_policy46",
                "system.source-ip_status",
                "system_modem",
                "certificate_remote",
                "firewall_decrypted-traffic-mirror",
                "antivirus_settings",
                "switch-controller_storm-control-policy",
                "switch-controller_802-1X-settings",
                "system_session-ttl",
                "system_storage",
                "system_isf-queue-profile",
                "log.memory_filter",
                "firewall_auth-portal",
                "antivirus_notification",
                "user_ldap",
                "ips_global",
                "wanopt_remote-storage",
                "system_speed-test-schedule",
                "wireless-controller.hotspot20_qos-map",
                "system.session-info_ttl",
                "vpn_l2tp",
                "monitoring_np6-ipsec-engine",
                "system_npu",
                "firewall_vip46",
                "authentication_setting",
                "vpn.certificate_ocsp-server",
                "antivirus_heuristic",
                "spamfilter_bword",
                "system_custom-language",
                "web-proxy_explicit",
                "vpn.ipsec_concentrator",
                "wireless-controller_wtp-group",
                "log.tacacs+accounting2_setting",
                "system_vdom-sflow",
                "switch-controller_igmp-snooping",
                "waf_signature",
                "log.null-device_setting",
                "gtp_tunnel-limit",
                "ips_rule-settings",
                "firewall_access-proxy",
                "system.session-info_expectation",
                "spamfilter_options",
                "switch-controller.security-policy_802-1X",
                "system_np6",
                "ips_decoder",
                "firewall_proute6",
                "user_setting",
                "system.performance_status",
                "system_geoip-override",
                "vpn.ipsec_phase1",
                "vpn.ipsec_phase2",
                "wireless-controller.hotspot20_anqp-network-auth-type",
                "webfilter_ips-urlfilter-cache-setting",
                "firewall.ipmacbinding_setting",
                "log.fortianalyzer2_filter",
                "system.ip-conflict_status",
                "application_rule-settings",
                "switch-controller_flow-tracking",
                "log.syslogd4_filter",
                "system_speed-test-server",
                "firewall_acl",
                "system_proxy-arp",
                "webfilter_ftgd-local-rating",
                "switch-controller_snmp-user",
                "nsxt_setting",
                "ips_custom",
                "switch-controller_switch-interface-tag",
                "router_policy6",
                "waf_sub-class",
                "web-proxy_forward-server",
                "log_eventfilter",
                "system_vdom-property",
                "switch-controller_traffic-sniffer",
                "firewall_security-policy",
                "system_external-resource",
                "user_exchange",
                "sctp-filter_profile",
                "system_ipv6-neighbor-cache",
                "vpn.ipsec.tunnel_details",
                "report_style",
                "log.syslogd2_override-filter",
                "wireless-controller_wtp",
                "wireless-controller_rf-analysis",
                "wanopt_peer",
                "system_saml",
                "system.dhcp6_server",
                "emailfilter_profile",
                "hardware.npu.np6_sse-stats",
                "log.fortianalyzer3_override-filter",
                "hardware_status",
                "firewall_multicast-policy",
                "vpn_ocvpn",
                "system.replacemsg_mms",
                "spamfilter_bwl",
                "switch-controller_fortilink-settings",
                "system_arp",
                "firewall_internet-service-addition",
                "webfilter_status",
                "system_ips",
                "emailfilter_bwl",
                "system_password-policy",
                "report_dataset",
                "switch-controller_virtual-port-pool",
                "wireless-controller_setting",
                "system.3g-modem_custom",
                "wireless-controller.hotspot20_anqp-ip-address-type",
                "firewall_vipgrp",
                "firewall_city",
                "web-proxy_profile",
                "system_switch-interface",
                "router_isis",
                "firewall_policy",
                "log.syslogd_override-setting",
                "hardware_memory",
                "router_info",
                "system.performance.firewall_packet-distribution",
                "switch-controller_mac-sync-settings",
                "webfilter_content",
                "firewall_vipgrp6",
                "switch-controller.initial-config_template",
                "spamfilter_mheader",
                "firewall.schedule_onetime",
                "vpn.status_pptp",
                "gtp_ie-allow-list",
                "log.fortianalyzer_setting",
                "videofilter_youtube-key",
                "vpn.ipsec.tunnel_name",
                "firewall_ippool6",
                "wireless-controller_status",
                "system_central-management",
                "system.replacemsg_http",
                "vpn.status.ssl_list",
                "vpn.ipsec.tunnel_summary",
                "hardware.npu.np6_session-stats",
                "cifs_domain-controller",
                "firewall_policy6",
                "system_zone",
                "system_vdom-dns",
                "firewall_multicast-address",
                "wireless-controller_wtp-profile",
                "vpn.ssl_settings",
                "router_ospf",
                "switch-controller.qos_queue-policy",
                "dpdk_cpus",
                "wireless-controller.hotspot20_h2qp-terms-and-conditions",
                "router_static6",
                "ftp-proxy_explicit",
                "hardware.npu.np6_port-list",
                "system_fortimanager",
                "system.lldp_network-policy",
                "vpn.certificate_crl",
                "system.replacemsg_admin",
                "router_multicast",
                "webfilter_profile",
                "switch-controller_storm-control",
                "firewall_ssl-ssh-profile",
                "vpn.ssl_client",
                "gtp_ie-white-list",
                "firewall_country",
                "user_certificate",
                "log.disk_setting",
                "nsxt_service-chain",
                "dlp_filepattern",
                "firewall_acl6",
                "firewall_ippool",
                "web-proxy_url-match",
                "vpn.status.ssl_hw-acceleration-status",
                "system_interface",
                "log.syslogd3_override-filter",
                "router_bfd",
                "switch-controller_custom-command",
                "dlp_data-type",
                "firewall_internet-service-extension",
                "system.replacemsg_webproxy",
                "user_password-policy",
                "wireless-controller_inter-controller",
                "system_fortindr",
                "log.syslogd4_setting",
                "log.fortianalyzer_filter",
                "hardware_cpu",
                "switch-controller_switch-group",
                "user_fsso",
                "emailfilter_mheader",
                "firewall_vipgrp64",
                "user_quarantine",
                "system_ips-urlfilter-dns",
                "wireless-controller_addrgrp",
                "system_fm",
                "wireless-controller_apcfg-profile",
                "system_global",
                "vpn.ipsec.stats_crypto",
                "wireless-controller.hotspot20_anqp-nai-realm",
                "system_physical-switch",
                "system_affinity-packet-redistribution",
                "system_status",
                "firewall_gtp",
                "log.fortiguard_override-setting",
                "firewall_proute",
                "videofilter_profile",
                "log.fortianalyzer3_setting",
                "system.auto-update_versions",
                "firewall_vip",
                "system_virtual-switch",
                "firewall_mms-profile",
                "wanopt_auth-group",
                "wanopt_webcache",
                "system.snmp_user",
                "firewall_ip-translation",
                "system_settings",
                "log.fortianalyzer2_setting",
                "wireless-controller_vap",
                "ipsec_tunnel",
                "wanopt_cache-service",
                "log.syslogd4_override-filter",
                "switch-controller_switch-log",
                "firewall_internet-service-group",
                "system.replacemsg_mail",
                "extender_modem-status",
                "system_replacemsg-image",
                "system_acme",
                "antivirus_quarantine",
                "log.fortianalyzer2_override-filter",
                "system.session-info_list",
                "vpn.certificate_ca",
                "endpoint-control_forticlient-registration-sync",
                "system_sdn-connector",
                "vpn.ssl.web_user-group-bookmark",
                "system_fortiguard-log-service",
                "endpoint-control_settings",
                "system_central-mgmt",
                "hardware_nic",
                "log.null-device_filter",
                "gtp_message-filter-v2",
                "firewall.shaper_per-ip-shaper",
                "wireless-controller_utm-profile",
                "icap_server-group",
                "router_aspath-list",
                "firewall.schedule_group",
                "system_ipam",
                "firewall_internet-service-list",
                "system_dscp-based-priority",
                "dlp_sensitivity",
                "icap_server",
                "vpn.ipsec_phase1-interface",
                "authentication_scheme",
                "firewall_access-proxy-virtual-host",
                "gtp_apn-shaper",
                "log.fortianalyzer3_filter",
                "system_email-server",
                "log.tacacs+accounting_filter",
                "dlp_sensor",
                "automation_setting",
                "application_list",
                "firewall_internet-service-append",
                "vpn.ssl.web_user-bookmark",
                "report_theme",
                "firewall.shaper_traffic-shaper",
                "switch-controller_traffic-policy",
                "system_csf",
                "dlp_settings",
                "log.syslogd_setting",
                "switch-controller.ptp_policy",
                "switch-controller_stp-instance",
                "wireless-controller.hotspot20_h2qp-advice-of-charge",
                "mgmt-data_status",
                "dnsfilter_profile",
                "user_device-access-list",
                "system_ha-monitor",
                "monitoring_npu-hpe",
                "system.replacemsg_nntp",
                "wireless-controller.hotspot20_anqp-venue-name",
                "system.snmp_sysinfo",
                "system_fortiai",
                "application_custom",
                "ips_session",
                "system_api-user",
                "system.info.admin_ssh",
                "ips_rule",
                "spamfilter_fortishield",
                "log.fortianalyzer-cloud_filter",
                "system_netflow",
                "vpn.ipsec_forticlient",
                "system_automation-trigger",
                "firewall_policy64",
                "wireless-controller.hotspot20_h2qp-osu-provider",
                "webfilter_ips-urlfilter-setting6",
                "switch-controller_sflow",
                "firewall.service_custom",
                "spamfilter_iptrust",
                "firewall_internet-service-botnet",
                "firewall_internet-service-definition",
                "gtp_rat-timeout-profile",
                "system_mobile-tunnel",
                "log.syslogd3_override-setting",
                "wireless-controller_nac-profile",
                "user_saml",
                "firewall_ttl-policy",
                "wireless-controller_client-info",
                "system_vne-tunnel",
                "system.snmp_mib-view",
                "webfilter_fortiguard",
                "gtp_apn",
                "vpn_pptp",
                "wireless-controller.hotspot20_hs-profile",
                "log.webtrends_setting",
                "firewall_local-in-policy",
                "extender-controller_dataplan",
                "system_gi-gk",
                "wireless-controller_region",
                "router_policy",
                "switch-controller_port-policy",
                "switch-controller.qos_dot1p-map",
                "firewall_multicast-policy6",
                "switch-controller.initial-config_vlans",
                "system_federated-upgrade",
                "wanopt_content-delivery-network-rule",
                "firewall_region",
                "system_dns-database",
                "vpn.ipsec_fec",
                "waf_main-class",
                "system.replacemsg_nac-quar",
                "system_vdom-radius-server",
                "system_vdom",
                "user_tacacs+",
                "system_ipip-tunnel",
                "log.syslogd3_setting",
                "extender_fexwan",
                "wireless-controller_mpsk-profile",
                "system_lte-modem",
                "router_multicast6",
                "vpn.certificate_remote",
                "extender_lte-carrier-list",
                "system_fips-cc",
                "switch-controller_snmp-community",
                "system_geneve",
                "system_ha",
                "log.syslogd3_filter",
                "user_radius",
                "firewall_DoS-policy6",
                "switch-controller.auto-config_default",
                "system_tos-based-priority",
                "vpn.certificate_local",
                "system_accprofile",
                "wireless-controller_global",
                "log.syslogd_filter",
                "vpn.status_l2tp",
                "system_ipsec-aggregate",
                "wireless-controller_ap-status",
                "switch-controller_poe",
                "log.syslogd2_filter",
                "log.syslogd2_setting",
                "system_password-policy-guest-admin",
                "user_pop3",
                "switch-controller_vlan-policy",
                "system_geoip-country",
                "switch-controller_system",
                "videofilter_youtube-channel-filter",
                "voip_profile",
                "vpn.ipsec_manualkey-interface",
                "emailfilter_options",
                "system.info.admin_status",
                "switch-controller_snmp-sysinfo",
                "firewall_internet-service-sld",
                "system_vdom-netflow",
                "firewall.ipmacbinding_table",
                "system_automation-destination",
                "dlp_fp-doc-source",
                "firewall_ldb-monitor",
                "firewall.ssh_host-key",
                "system_vdom-link",
                "spamfilter_dnsbl",
                "system_fortianalyzer-connectivity",
                "router_ospf6",
                "user_device",
                "log.fortiguard_setting",
                "system.snmp_community",
                "wireless-controller_arrp-profile",
                "ips_settings",
                "firewall_internet-service-ipbl-vendor",
                "system_vdom-exception",
                "system_wccp",
                "antivirus_mms-checksum",
                "router_info6",
                "system_ha-nonsync-csum",
                "system_automation-stitch",
                "system_mem-mgr",
                "firewall_profile-protocol-options",
                "router_prefix-list",
                "wireless-controller.hotspot20_anqp-venue-url",
                "firewall.ssh_local-key",
                "system_mgmt-csum",
                "endpoint-control_profile",
                "firewall_vip64",
                "dlp_profile",
                "web-proxy_wisp",
                "switch-controller_switch-profile",
                "system.checksum_status",
                "endpoint-control_forticlient-ems",
                "system_dns-server",
                "system.replacemsg_alertmail",
                "log.fortiguard_override-filter",
                "endpoint-control_client",
                "firewall_access-proxy-ssh-client-cert",
                "system_fortiguard",
                "web-proxy_global",
                "extender_datachannel-info",
                "wanopt_profile",
                "system_management-tunnel",
                "wireless-controller_scan",
                "system.replacemsg_ec",
                "report_setting",
                "firewall.service_group",
                "switch-controller_snmp-trap-threshold",
                "webfilter_search-engine",
                "system_ipv6-tunnel",
                "firewall.iprope.appctrl_list",
                "user_device-group",
                "user_fsso-polling",
                "system.dhcp_server",
                "report_chart",
                "vpn.certificate_setting",
                "router_bfd6",
                "router_access-list",
                "system.session-info_statistics",
                "firewall_proxy-policy",
                "system_dns",
                "icap_profile",
                "firewall_internet-service-ipbl-reason",
                "webfilter_override-usr",
                "system_session",
                "dnsfilter_domain-filter",
                "report.sql_status",
                "switch-controller.auto-config_custom",
                "wireless-controller_vap-group",
                "emailfilter_iptrust",
                "antivirus_profile",
                "system_startup-error-log",
                "firewall_internet-service-name",
                "system_affinity-interrupt",
                "firewall_shaping-profile",
                "log.syslogd4_override-setting",
                "firewall_interface-policy6",
                "vpn.ipsec_manualkey",
                "firewall.shaper_per-ip",
                "firewall_vendor-mac",
                "switch-controller_global",
                "router_setting",
                "user_local",
                "firewall.schedule_recurring",
                "system_sit-tunnel",
                "system_arp-table",
                "firewall_carrier-endpoint-bwl",
                "switch-controller_lldp-settings",
                "webfilter_content-header",
                "system_auto-install",
                "log.fortianalyzer3_override-setting",
                "user_domain-controller",
                "wireless-controller_wtp-status",
                "firewall_ssl-server",
                "system.replacemsg_traffic-quota",
                "system_virtual-wire-pair",
                "system_mac-address-table",
                "system.replacemsg_automation",
                "firewall_internet-service-owner",
                "system_network-visibility",
                "log.syslogd_override-filter",
                "switch-controller_nac-settings",
                "firewall_interface-policy",
                "extender_extender-info",
                "system.replacemsg_fortiguard-wf",
                "system_nat64",
                "wireless-controller_bonjour-profile",
                "system_sdwan",
                "webfilter_urlfilter",
                "wireless-controller_spectral-info",
                "credential-store_domain-controller",
                "hardware.npu.np6_synproxy-stats",
                "system_probe-response",
                "wireless-controller.hotspot20_h2qp-operator-name",
                "wireless-controller_access-control-list",
                "cifs_profile",
                "system.replacemsg_utm",
                "extender_sys-info",
                "wireless-controller.hotspot20_anqp-roaming-consortium",
                "firewall_DoS-policy",
                "firewall_proxy-addrgrp",
                "firewall_addrgrp",
                "system_sflow",
                "router_ripng",
                "firewall_vip6",
                "wireless-controller_syslog-profile",
                "system.replacemsg_spam",
                "certificate_ca",
                "firewall.ssh_local-ca",
                "system_admin",
                "wireless-controller.hotspot20_h2qp-conn-capability",
                "switch-controller_location",
                "firewall.consolidated_policy",
                "router_access-list6",
                "hardware.npu.np6_dce",
                "waf_profile",
                "firewall.wildcard-fqdn_group",
                "system_gre-tunnel",
                "user_group",
                "log.syslogd2_override-setting",
                "user_krb-keytab",
                "firewall.iprope_list",
                "system_ptp",
                "dpdk_global",
                "application_group",
                "system.replacemsg_ftp",
                "log_threat-weight",
                "extender-controller_extender",
                "firewall_access-proxy6",
                "system_session6",
                "switch-controller_managed-switch",
                "system_ike",
            ],
        },
        "selectors": {
            "required": False,
            "type": "list",
            "elements": "dict",
            "options": {
                "filters": {"required": False, "type": "list", "elements": "str"},
                "sorters": {"required": False, "type": "list", "elements": "str"},
                "formatters": {"required": False, "type": "list", "elements": "str"},
                "params": {"required": False, "type": "dict"},
                "selector": {
                    "required": True,
                    "type": "str",
                    "choices": [
                        "log_gui-display",
                        "system_fortiguard-service",
                        "router_route-map",
                        "system_sso-admin",
                        "wireless-controller_address",
                        "vpn.ssl_monitor",
                        "system.auto-update_status",
                        "system_cmdb",
                        "authentication_rule",
                        "log.fortianalyzer_override-setting",
                        "firewall.ssl_setting",
                        "vpn.ipsec_phase2-interface",
                        "router_key-chain",
                        "system_ddns",
                        "firewall_traffic-class",
                        "system_replacemsg-group",
                        "system_ftm-push",
                        "system_sms-server",
                        "firewall_central-snat-map",
                        "firewall_multicast-address6",
                        "dlp_fp-sensitivity",
                        "system.replacemsg_sslvpn",
                        "ips_view-map",
                        "firewall_pfcp",
                        "system_pppoe-interface",
                        "webfilter_categories",
                        "firewall_addrgrp6",
                        "log.disk_filter",
                        "system.session-info_full-stat",
                        "firewall_proxy-address",
                        "extender-controller_extender-profile",
                        "emailfilter_block-allow-list",
                        "router_bgp",
                        "router_auth-path",
                        "system_resource-limits",
                        "system.replacemsg_auth",
                        "system.autoupdate_schedule",
                        "switch-controller.qos_ip-dscp-map",
                        "firewall_local-in-policy6",
                        "log.fortianalyzer2_override-setting",
                        "wireless-controller.hotspot20_h2qp-osu-provider-nai",
                        "log.fortianalyzer_override-filter",
                        "system.replacemsg_icap",
                        "system_object-tagging",
                        "spamfilter_profile",
                        "switch-controller_remote-log",
                        "router_rip",
                        "switch-controller.security-policy_local-access",
                        "vpn.ipsec.stats_tunnel",
                        "log.fortianalyzer-cloud_override-filter",
                        "firewall.shaper_traffic",
                        "system_smc-ntp",
                        "user_adgrp",
                        "system_auto-script",
                        "switch-controller_quarantine",
                        "firewall.service_category",
                        "system_standalone-cluster",
                        "system_link-monitor",
                        "switch-controller_stp-settings",
                        "user_security-exempt-list",
                        "log.fortianalyzer-cloud_setting",
                        "switch-controller.qos_qos-policy",
                        "firewall_sniffer",
                        "wireless-controller_ssid-policy",
                        "wireless-controller_wag-profile",
                        "firewall_internet-service-reputation",
                        "switch-controller_vlan",
                        "system.replacemsg_mm7",
                        "system.replacemsg_mm4",
                        "firewall_internet-service",
                        "system.replacemsg_mm3",
                        "system.replacemsg_mm1",
                        "firewall.iprope.appctrl_status",
                        "firewall_vipgrp46",
                        "log.webtrends_filter",
                        "application_name",
                        "system_sso-forticloud-admin",
                        "gtp_apngrp",
                        "log_setting",
                        "firewall_address6-template",
                        "wireless-controller.hotspot20_anqp-3gpp-cellular",
                        "wireless-controller.hotspot20_h2qp-wan-metric",
                        "system_automation-action",
                        "system.autoupdate_tunneling",
                        "router_prefix-list6",
                        "webfilter_ips-urlfilter-setting",
                        "pfcp_message-filter",
                        "switch-controller_network-monitor-settings",
                        "system_alias",
                        "file-filter_profile",
                        "web-proxy_forward-server-group",
                        "system_session-helper",
                        "router_community-list",
                        "wireless-controller_qos-profile",
                        "extender_session-info",
                        "firewall_dnstranslation",
                        "vpn.ssl.web_portal",
                        "firewall_internet-service-custom",
                        "system.replacemsg_device-detection-portal",
                        "wireless-controller_ble-profile",
                        "firewall_internet-service-custom-group",
                        "system.performance.firewall_statistics",
                        "firewall_profile-group",
                        "system_vxlan",
                        "system.autoupdate_push-update",
                        "firewall_address6",
                        "system.performance_top",
                        "wireless-controller_vap-status",
                        "wireless-controller_wids-profile",
                        "emailfilter_bword",
                        "log.fortiguard_filter",
                        "firewall_ipv6-eh-filter",
                        "switch-controller.ptp_settings",
                        "endpoint-control_fctems",
                        "user_device-category",
                        "firewall_identity-based-route",
                        "system.session-helper-info_list",
                        "system_console",
                        "certificate_local",
                        "system_ntp",
                        "webfilter_ftgd-local-cat",
                        "report_layout",
                        "log.tacacs+accounting3_setting",
                        "wireless-controller_timers",
                        "wireless-controller.hotspot20_icon",
                        "log.tacacs+accounting2_filter",
                        "log.memory_global-setting",
                        "router_multicast-flow",
                        "ssh-filter_profile",
                        "system_fortisandbox",
                        "system_dns64",
                        "system_virtual-wan-link",
                        "ips_sensor",
                        "firewall.wildcard-fqdn_custom",
                        "router_static",
                        "alertemail_setting",
                        "user_peergrp",
                        "user_fortitoken",
                        "web-proxy_debug-url",
                        "dlp_dictionary",
                        "vpn.ike_gateway",
                        "webfilter_override",
                        "switch-controller_nac-device",
                        "system_fsso-polling",
                        "user_peer",
                        "vpn.ssl.web_host-check-software",
                        "gtp_message-filter-v0v1",
                        "switch-controller_lldp-profile",
                        "switch-controller_dynamic-port-policy",
                        "vpn.ssl.web_realm",
                        "system_stp",
                        "log.tacacs+accounting_setting",
                        "user_nac-policy",
                        "wireless-controller_snmp",
                        "emailfilter_fortishield",
                        "switch-controller.security-policy_captive-portal",
                        "firewall_shaping-policy",
                        "wireless-controller_wlchanlistlic",
                        "log_custom-field",
                        "switch-controller_mac-policy",
                        "firewall_address",
                        "certificate_crl",
                        "firewall.ssh_setting",
                        "switch-controller.auto-config_policy",
                        "system_nd-proxy",
                        "log.memory_setting",
                        "system_alarm",
                        "system_ips-urlfilter-dns6",
                        "wireless-controller_log",
                        "extender_lte-carrier-by-mcc-mnc",
                        "webfilter_ftgd-statistics",
                        "hardware.npu.np6_ipsec-stats",
                        "firewall_vendor-mac-summary",
                        "system_cluster-sync",
                        "wanopt_settings",
                        "emailfilter_dnsbl",
                        "endpoint-control_registered-forticlient",
                        "system_dedicated-mgmt",
                        "log.tacacs+accounting3_filter",
                        "log.fortianalyzer-cloud_override-setting",
                        "firewall_policy46",
                        "system.source-ip_status",
                        "system_modem",
                        "certificate_remote",
                        "firewall_decrypted-traffic-mirror",
                        "antivirus_settings",
                        "switch-controller_storm-control-policy",
                        "switch-controller_802-1X-settings",
                        "system_session-ttl",
                        "system_storage",
                        "system_isf-queue-profile",
                        "log.memory_filter",
                        "firewall_auth-portal",
                        "antivirus_notification",
                        "user_ldap",
                        "ips_global",
                        "wanopt_remote-storage",
                        "system_speed-test-schedule",
                        "wireless-controller.hotspot20_qos-map",
                        "system.session-info_ttl",
                        "vpn_l2tp",
                        "monitoring_np6-ipsec-engine",
                        "system_npu",
                        "firewall_vip46",
                        "authentication_setting",
                        "vpn.certificate_ocsp-server",
                        "antivirus_heuristic",
                        "spamfilter_bword",
                        "system_custom-language",
                        "web-proxy_explicit",
                        "vpn.ipsec_concentrator",
                        "wireless-controller_wtp-group",
                        "log.tacacs+accounting2_setting",
                        "system_vdom-sflow",
                        "switch-controller_igmp-snooping",
                        "waf_signature",
                        "log.null-device_setting",
                        "gtp_tunnel-limit",
                        "ips_rule-settings",
                        "firewall_access-proxy",
                        "system.session-info_expectation",
                        "spamfilter_options",
                        "switch-controller.security-policy_802-1X",
                        "system_np6",
                        "ips_decoder",
                        "firewall_proute6",
                        "user_setting",
                        "system.performance_status",
                        "system_geoip-override",
                        "vpn.ipsec_phase1",
                        "vpn.ipsec_phase2",
                        "wireless-controller.hotspot20_anqp-network-auth-type",
                        "webfilter_ips-urlfilter-cache-setting",
                        "firewall.ipmacbinding_setting",
                        "log.fortianalyzer2_filter",
                        "system.ip-conflict_status",
                        "application_rule-settings",
                        "switch-controller_flow-tracking",
                        "log.syslogd4_filter",
                        "system_speed-test-server",
                        "firewall_acl",
                        "system_proxy-arp",
                        "webfilter_ftgd-local-rating",
                        "switch-controller_snmp-user",
                        "nsxt_setting",
                        "ips_custom",
                        "switch-controller_switch-interface-tag",
                        "router_policy6",
                        "waf_sub-class",
                        "web-proxy_forward-server",
                        "log_eventfilter",
                        "system_vdom-property",
                        "switch-controller_traffic-sniffer",
                        "firewall_security-policy",
                        "system_external-resource",
                        "user_exchange",
                        "sctp-filter_profile",
                        "system_ipv6-neighbor-cache",
                        "vpn.ipsec.tunnel_details",
                        "report_style",
                        "log.syslogd2_override-filter",
                        "wireless-controller_wtp",
                        "wireless-controller_rf-analysis",
                        "wanopt_peer",
                        "system_saml",
                        "system.dhcp6_server",
                        "emailfilter_profile",
                        "hardware.npu.np6_sse-stats",
                        "log.fortianalyzer3_override-filter",
                        "hardware_status",
                        "firewall_multicast-policy",
                        "vpn_ocvpn",
                        "system.replacemsg_mms",
                        "spamfilter_bwl",
                        "switch-controller_fortilink-settings",
                        "system_arp",
                        "firewall_internet-service-addition",
                        "webfilter_status",
                        "system_ips",
                        "emailfilter_bwl",
                        "system_password-policy",
                        "report_dataset",
                        "switch-controller_virtual-port-pool",
                        "wireless-controller_setting",
                        "system.3g-modem_custom",
                        "wireless-controller.hotspot20_anqp-ip-address-type",
                        "firewall_vipgrp",
                        "firewall_city",
                        "web-proxy_profile",
                        "system_switch-interface",
                        "router_isis",
                        "firewall_policy",
                        "log.syslogd_override-setting",
                        "hardware_memory",
                        "router_info",
                        "system.performance.firewall_packet-distribution",
                        "switch-controller_mac-sync-settings",
                        "webfilter_content",
                        "firewall_vipgrp6",
                        "switch-controller.initial-config_template",
                        "spamfilter_mheader",
                        "firewall.schedule_onetime",
                        "vpn.status_pptp",
                        "gtp_ie-allow-list",
                        "log.fortianalyzer_setting",
                        "videofilter_youtube-key",
                        "vpn.ipsec.tunnel_name",
                        "firewall_ippool6",
                        "wireless-controller_status",
                        "system_central-management",
                        "system.replacemsg_http",
                        "vpn.status.ssl_list",
                        "vpn.ipsec.tunnel_summary",
                        "hardware.npu.np6_session-stats",
                        "cifs_domain-controller",
                        "firewall_policy6",
                        "system_zone",
                        "system_vdom-dns",
                        "firewall_multicast-address",
                        "wireless-controller_wtp-profile",
                        "vpn.ssl_settings",
                        "router_ospf",
                        "switch-controller.qos_queue-policy",
                        "dpdk_cpus",
                        "wireless-controller.hotspot20_h2qp-terms-and-conditions",
                        "router_static6",
                        "ftp-proxy_explicit",
                        "hardware.npu.np6_port-list",
                        "system_fortimanager",
                        "system.lldp_network-policy",
                        "vpn.certificate_crl",
                        "system.replacemsg_admin",
                        "router_multicast",
                        "webfilter_profile",
                        "switch-controller_storm-control",
                        "firewall_ssl-ssh-profile",
                        "vpn.ssl_client",
                        "gtp_ie-white-list",
                        "firewall_country",
                        "user_certificate",
                        "log.disk_setting",
                        "nsxt_service-chain",
                        "dlp_filepattern",
                        "firewall_acl6",
                        "firewall_ippool",
                        "web-proxy_url-match",
                        "vpn.status.ssl_hw-acceleration-status",
                        "system_interface",
                        "log.syslogd3_override-filter",
                        "router_bfd",
                        "switch-controller_custom-command",
                        "dlp_data-type",
                        "firewall_internet-service-extension",
                        "system.replacemsg_webproxy",
                        "user_password-policy",
                        "wireless-controller_inter-controller",
                        "system_fortindr",
                        "log.syslogd4_setting",
                        "log.fortianalyzer_filter",
                        "hardware_cpu",
                        "switch-controller_switch-group",
                        "user_fsso",
                        "emailfilter_mheader",
                        "firewall_vipgrp64",
                        "user_quarantine",
                        "system_ips-urlfilter-dns",
                        "wireless-controller_addrgrp",
                        "system_fm",
                        "wireless-controller_apcfg-profile",
                        "system_global",
                        "vpn.ipsec.stats_crypto",
                        "wireless-controller.hotspot20_anqp-nai-realm",
                        "system_physical-switch",
                        "system_affinity-packet-redistribution",
                        "system_status",
                        "firewall_gtp",
                        "log.fortiguard_override-setting",
                        "firewall_proute",
                        "videofilter_profile",
                        "log.fortianalyzer3_setting",
                        "system.auto-update_versions",
                        "firewall_vip",
                        "system_virtual-switch",
                        "firewall_mms-profile",
                        "wanopt_auth-group",
                        "wanopt_webcache",
                        "system.snmp_user",
                        "firewall_ip-translation",
                        "system_settings",
                        "log.fortianalyzer2_setting",
                        "wireless-controller_vap",
                        "ipsec_tunnel",
                        "wanopt_cache-service",
                        "log.syslogd4_override-filter",
                        "switch-controller_switch-log",
                        "firewall_internet-service-group",
                        "system.replacemsg_mail",
                        "extender_modem-status",
                        "system_replacemsg-image",
                        "system_acme",
                        "antivirus_quarantine",
                        "log.fortianalyzer2_override-filter",
                        "system.session-info_list",
                        "vpn.certificate_ca",
                        "endpoint-control_forticlient-registration-sync",
                        "system_sdn-connector",
                        "vpn.ssl.web_user-group-bookmark",
                        "system_fortiguard-log-service",
                        "endpoint-control_settings",
                        "system_central-mgmt",
                        "hardware_nic",
                        "log.null-device_filter",
                        "gtp_message-filter-v2",
                        "firewall.shaper_per-ip-shaper",
                        "wireless-controller_utm-profile",
                        "icap_server-group",
                        "router_aspath-list",
                        "firewall.schedule_group",
                        "system_ipam",
                        "firewall_internet-service-list",
                        "system_dscp-based-priority",
                        "dlp_sensitivity",
                        "icap_server",
                        "vpn.ipsec_phase1-interface",
                        "authentication_scheme",
                        "firewall_access-proxy-virtual-host",
                        "gtp_apn-shaper",
                        "log.fortianalyzer3_filter",
                        "system_email-server",
                        "log.tacacs+accounting_filter",
                        "dlp_sensor",
                        "automation_setting",
                        "application_list",
                        "firewall_internet-service-append",
                        "vpn.ssl.web_user-bookmark",
                        "report_theme",
                        "firewall.shaper_traffic-shaper",
                        "switch-controller_traffic-policy",
                        "system_csf",
                        "dlp_settings",
                        "log.syslogd_setting",
                        "switch-controller.ptp_policy",
                        "switch-controller_stp-instance",
                        "wireless-controller.hotspot20_h2qp-advice-of-charge",
                        "mgmt-data_status",
                        "dnsfilter_profile",
                        "user_device-access-list",
                        "system_ha-monitor",
                        "monitoring_npu-hpe",
                        "system.replacemsg_nntp",
                        "wireless-controller.hotspot20_anqp-venue-name",
                        "system.snmp_sysinfo",
                        "system_fortiai",
                        "application_custom",
                        "ips_session",
                        "system_api-user",
                        "system.info.admin_ssh",
                        "ips_rule",
                        "spamfilter_fortishield",
                        "log.fortianalyzer-cloud_filter",
                        "system_netflow",
                        "vpn.ipsec_forticlient",
                        "system_automation-trigger",
                        "firewall_policy64",
                        "wireless-controller.hotspot20_h2qp-osu-provider",
                        "webfilter_ips-urlfilter-setting6",
                        "switch-controller_sflow",
                        "firewall.service_custom",
                        "spamfilter_iptrust",
                        "firewall_internet-service-botnet",
                        "firewall_internet-service-definition",
                        "gtp_rat-timeout-profile",
                        "system_mobile-tunnel",
                        "log.syslogd3_override-setting",
                        "wireless-controller_nac-profile",
                        "user_saml",
                        "firewall_ttl-policy",
                        "wireless-controller_client-info",
                        "system_vne-tunnel",
                        "system.snmp_mib-view",
                        "webfilter_fortiguard",
                        "gtp_apn",
                        "vpn_pptp",
                        "wireless-controller.hotspot20_hs-profile",
                        "log.webtrends_setting",
                        "firewall_local-in-policy",
                        "extender-controller_dataplan",
                        "system_gi-gk",
                        "wireless-controller_region",
                        "router_policy",
                        "switch-controller_port-policy",
                        "switch-controller.qos_dot1p-map",
                        "firewall_multicast-policy6",
                        "switch-controller.initial-config_vlans",
                        "system_federated-upgrade",
                        "wanopt_content-delivery-network-rule",
                        "firewall_region",
                        "system_dns-database",
                        "vpn.ipsec_fec",
                        "waf_main-class",
                        "system.replacemsg_nac-quar",
                        "system_vdom-radius-server",
                        "system_vdom",
                        "user_tacacs+",
                        "system_ipip-tunnel",
                        "log.syslogd3_setting",
                        "extender_fexwan",
                        "wireless-controller_mpsk-profile",
                        "system_lte-modem",
                        "router_multicast6",
                        "vpn.certificate_remote",
                        "extender_lte-carrier-list",
                        "system_fips-cc",
                        "switch-controller_snmp-community",
                        "system_geneve",
                        "system_ha",
                        "log.syslogd3_filter",
                        "user_radius",
                        "firewall_DoS-policy6",
                        "switch-controller.auto-config_default",
                        "system_tos-based-priority",
                        "vpn.certificate_local",
                        "system_accprofile",
                        "wireless-controller_global",
                        "log.syslogd_filter",
                        "vpn.status_l2tp",
                        "system_ipsec-aggregate",
                        "wireless-controller_ap-status",
                        "switch-controller_poe",
                        "log.syslogd2_filter",
                        "log.syslogd2_setting",
                        "system_password-policy-guest-admin",
                        "user_pop3",
                        "switch-controller_vlan-policy",
                        "system_geoip-country",
                        "switch-controller_system",
                        "videofilter_youtube-channel-filter",
                        "voip_profile",
                        "vpn.ipsec_manualkey-interface",
                        "emailfilter_options",
                        "system.info.admin_status",
                        "switch-controller_snmp-sysinfo",
                        "firewall_internet-service-sld",
                        "system_vdom-netflow",
                        "firewall.ipmacbinding_table",
                        "system_automation-destination",
                        "dlp_fp-doc-source",
                        "firewall_ldb-monitor",
                        "firewall.ssh_host-key",
                        "system_vdom-link",
                        "spamfilter_dnsbl",
                        "system_fortianalyzer-connectivity",
                        "router_ospf6",
                        "user_device",
                        "log.fortiguard_setting",
                        "system.snmp_community",
                        "wireless-controller_arrp-profile",
                        "ips_settings",
                        "firewall_internet-service-ipbl-vendor",
                        "system_vdom-exception",
                        "system_wccp",
                        "antivirus_mms-checksum",
                        "router_info6",
                        "system_ha-nonsync-csum",
                        "system_automation-stitch",
                        "system_mem-mgr",
                        "firewall_profile-protocol-options",
                        "router_prefix-list",
                        "wireless-controller.hotspot20_anqp-venue-url",
                        "firewall.ssh_local-key",
                        "system_mgmt-csum",
                        "endpoint-control_profile",
                        "firewall_vip64",
                        "dlp_profile",
                        "web-proxy_wisp",
                        "switch-controller_switch-profile",
                        "system.checksum_status",
                        "endpoint-control_forticlient-ems",
                        "system_dns-server",
                        "system.replacemsg_alertmail",
                        "log.fortiguard_override-filter",
                        "endpoint-control_client",
                        "firewall_access-proxy-ssh-client-cert",
                        "system_fortiguard",
                        "web-proxy_global",
                        "extender_datachannel-info",
                        "wanopt_profile",
                        "system_management-tunnel",
                        "wireless-controller_scan",
                        "system.replacemsg_ec",
                        "report_setting",
                        "firewall.service_group",
                        "switch-controller_snmp-trap-threshold",
                        "webfilter_search-engine",
                        "system_ipv6-tunnel",
                        "firewall.iprope.appctrl_list",
                        "user_device-group",
                        "user_fsso-polling",
                        "system.dhcp_server",
                        "report_chart",
                        "vpn.certificate_setting",
                        "router_bfd6",
                        "router_access-list",
                        "system.session-info_statistics",
                        "firewall_proxy-policy",
                        "system_dns",
                        "icap_profile",
                        "firewall_internet-service-ipbl-reason",
                        "webfilter_override-usr",
                        "system_session",
                        "dnsfilter_domain-filter",
                        "report.sql_status",
                        "switch-controller.auto-config_custom",
                        "wireless-controller_vap-group",
                        "emailfilter_iptrust",
                        "antivirus_profile",
                        "system_startup-error-log",
                        "firewall_internet-service-name",
                        "system_affinity-interrupt",
                        "firewall_shaping-profile",
                        "log.syslogd4_override-setting",
                        "firewall_interface-policy6",
                        "vpn.ipsec_manualkey",
                        "firewall.shaper_per-ip",
                        "firewall_vendor-mac",
                        "switch-controller_global",
                        "router_setting",
                        "user_local",
                        "firewall.schedule_recurring",
                        "system_sit-tunnel",
                        "system_arp-table",
                        "firewall_carrier-endpoint-bwl",
                        "switch-controller_lldp-settings",
                        "webfilter_content-header",
                        "system_auto-install",
                        "log.fortianalyzer3_override-setting",
                        "user_domain-controller",
                        "wireless-controller_wtp-status",
                        "firewall_ssl-server",
                        "system.replacemsg_traffic-quota",
                        "system_virtual-wire-pair",
                        "system_mac-address-table",
                        "system.replacemsg_automation",
                        "firewall_internet-service-owner",
                        "system_network-visibility",
                        "log.syslogd_override-filter",
                        "switch-controller_nac-settings",
                        "firewall_interface-policy",
                        "extender_extender-info",
                        "system.replacemsg_fortiguard-wf",
                        "system_nat64",
                        "wireless-controller_bonjour-profile",
                        "system_sdwan",
                        "webfilter_urlfilter",
                        "wireless-controller_spectral-info",
                        "credential-store_domain-controller",
                        "hardware.npu.np6_synproxy-stats",
                        "system_probe-response",
                        "wireless-controller.hotspot20_h2qp-operator-name",
                        "wireless-controller_access-control-list",
                        "cifs_profile",
                        "system.replacemsg_utm",
                        "extender_sys-info",
                        "wireless-controller.hotspot20_anqp-roaming-consortium",
                        "firewall_DoS-policy",
                        "firewall_proxy-addrgrp",
                        "firewall_addrgrp",
                        "system_sflow",
                        "router_ripng",
                        "firewall_vip6",
                        "wireless-controller_syslog-profile",
                        "system.replacemsg_spam",
                        "certificate_ca",
                        "firewall.ssh_local-ca",
                        "system_admin",
                        "wireless-controller.hotspot20_h2qp-conn-capability",
                        "switch-controller_location",
                        "firewall.consolidated_policy",
                        "router_access-list6",
                        "hardware.npu.np6_dce",
                        "waf_profile",
                        "firewall.wildcard-fqdn_group",
                        "system_gre-tunnel",
                        "user_group",
                        "log.syslogd2_override-setting",
                        "user_krb-keytab",
                        "firewall.iprope_list",
                        "system_ptp",
                        "dpdk_global",
                        "application_group",
                        "system.replacemsg_ftp",
                        "log_threat-weight",
                        "extender-controller_extender",
                        "firewall_access-proxy6",
                        "system_session6",
                        "switch-controller_managed-switch",
                        "system_ike",
                    ],
                },
            },
        },
    }

    module = AnsibleModule(argument_spec=fields, supports_check_mode=False)
    check_legacy_fortiosapi(module)

    # Only selector or selectors is provided.
    if (
        module.params["selector"]
        and module.params["selectors"]
        or not module.params["selector"]
        and not module.params["selectors"]
    ):
        module.fail_json(msg="please use selector or selectors in a task.")

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if "access_token" in module.params:
            connection.set_option("access_token", module.params["access_token"])
        if "enable_log" in module.params:
            connection.set_option("enable_log", module.params["enable_log"])
        else:
            connection.set_option("enable_log", False)

        fos = FortiOSHandler(connection, module)

        if module.params["selector"]:
            is_error, has_changed, result = fortios_configuration_fact(
                module.params, fos
            )
        else:
            params = module.params
            selectors = params["selectors"]
            is_error = False
            has_changed = False
            result = []
            for selector_obj in selectors:
                per_selector = {
                    "vdom": params.get("vdom"),
                    # **selector_obj,
                }
                per_selector.update(selector_obj)
                (
                    is_error_local,
                    has_changed_local,
                    result_local,
                ) = fortios_configuration_fact(per_selector, fos)

                is_error = is_error or is_error_local
                has_changed = has_changed or has_changed_local
                result.append(result_local)
    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result["matched"] is False:
        module.warn(
            "Ansible has detected version mismatch between FortOS system and galaxy, see more details by specifying option -vvv"
        )

    if not is_error:
        if versions_check_result and versions_check_result["matched"] is False:
            module.exit_json(
                changed=has_changed,
                version_check_warning=versions_check_result,
                meta=result,
            )
        else:
            module.exit_json(changed=has_changed, meta=result)
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
