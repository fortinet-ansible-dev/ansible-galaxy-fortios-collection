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
                 - 'system_vdom'
                 - 'system_global'
                 - 'system_accprofile'
                 - 'system_vdom-link'
                 - 'system_switch-interface'
                 - 'system_object-tagging'
                 - 'system_interface'
                 - 'system_password-policy'
                 - 'system_password-policy-guest-admin'
                 - 'system_sms-server'
                 - 'system_custom-language'
                 - 'system_admin'
                 - 'system_api-user'
                 - 'system_sso-admin'
                 - 'system_sso-forticloud-admin'
                 - 'system_sso-fortigate-cloud-admin'
                 - 'system_settings'
                 - 'system_sit-tunnel'
                 - 'system_fsso-polling'
                 - 'system_ha'
                 - 'system_ha-monitor'
                 - 'system_storage'
                 - 'system_dedicated-mgmt'
                 - 'system_arp-table'
                 - 'system_ipv6-neighbor-cache'
                 - 'system_dns'
                 - 'system_ddns'
                 - 'system_sflow'
                 - 'system_vdom-sflow'
                 - 'system_netflow'
                 - 'system_vdom-netflow'
                 - 'system_vdom-dns'
                 - 'system_replacemsg-image'
                 - 'system_replacemsg-group'
                 - 'system.snmp_sysinfo'
                 - 'system.snmp_mib-view'
                 - 'system.snmp_community'
                 - 'system.snmp_user'
                 - 'system.autoupdate_schedule'
                 - 'system.autoupdate_tunneling'
                 - 'system_session-ttl'
                 - 'system.dhcp_server'
                 - 'system.dhcp6_server'
                 - 'system_alias'
                 - 'system_auto-script'
                 - 'system_management-tunnel'
                 - 'system_central-management'
                 - 'system_zone'
                 - 'system_sdn-proxy'
                 - 'system_sdn-connector'
                 - 'system_ipv6-tunnel'
                 - 'system_external-resource'
                 - 'system_ips-urlfilter-dns'
                 - 'system_ips-urlfilter-dns6'
                 - 'system_network-visibility'
                 - 'system_sdwan'
                 - 'system_evpn'
                 - 'system_gre-tunnel'
                 - 'system_ipsec-aggregate'
                 - 'system_ipip-tunnel'
                 - 'system_mobile-tunnel'
                 - 'system_pppoe-interface'
                 - 'system_vxlan'
                 - 'system_geneve'
                 - 'system_virtual-wire-pair'
                 - 'system_dns-database'
                 - 'system_dns-server'
                 - 'system_resource-limits'
                 - 'system_vdom-property'
                 - 'system_speed-test-server'
                 - 'system.lldp_network-policy'
                 - 'system_pcp-server'
                 - 'system_speed-test-schedule'
                 - 'system_speed-test-setting'
                 - 'system_standalone-cluster'
                 - 'system_fortiguard'
                 - 'system_ips'
                 - 'system_email-server'
                 - 'system_alarm'
                 - 'system_mac-address-table'
                 - 'system_session-helper'
                 - 'system_proxy-arp'
                 - 'system_fips-cc'
                 - 'system_tos-based-priority'
                 - 'system_dscp-based-priority'
                 - 'system_probe-response'
                 - 'system_link-monitor'
                 - 'system_auto-install'
                 - 'system_console'
                 - 'system_ntp'
                 - 'system_ptp'
                 - 'system_wccp'
                 - 'system_dns64'
                 - 'system_vdom-radius-server'
                 - 'system_ftm-push'
                 - 'system_geoip-override'
                 - 'system_fortisandbox'
                 - 'system_fortindr'
                 - 'system_affinity-interrupt'
                 - 'system_affinity-packet-redistribution'
                 - 'system_vdom-exception'
                 - 'system_csf'
                 - 'system_automation-trigger'
                 - 'system_automation-action'
                 - 'system_automation-destination'
                 - 'system_automation-stitch'
                 - 'system_nd-proxy'
                 - 'system_saml'
                 - 'system_federated-upgrade'
                 - 'system_device-upgrade'
                 - 'system_vne-tunnel'
                 - 'system_ike'
                 - 'system_acme'
                 - 'system_ipam'
                 - 'system_fabric-vpn'
                 - 'system_ssh-config'
                 - 'wireless-controller_inter-controller'
                 - 'wireless-controller_global'
                 - 'wireless-controller.hotspot20_anqp-venue-name'
                 - 'wireless-controller.hotspot20_anqp-venue-url'
                 - 'wireless-controller.hotspot20_anqp-network-auth-type'
                 - 'wireless-controller.hotspot20_anqp-roaming-consortium'
                 - 'wireless-controller.hotspot20_anqp-nai-realm'
                 - 'wireless-controller.hotspot20_anqp-3gpp-cellular'
                 - 'wireless-controller.hotspot20_anqp-ip-address-type'
                 - 'wireless-controller.hotspot20_h2qp-operator-name'
                 - 'wireless-controller.hotspot20_h2qp-wan-metric'
                 - 'wireless-controller.hotspot20_h2qp-conn-capability'
                 - 'wireless-controller.hotspot20_icon'
                 - 'wireless-controller.hotspot20_h2qp-osu-provider'
                 - 'wireless-controller.hotspot20_qos-map'
                 - 'wireless-controller.hotspot20_h2qp-advice-of-charge'
                 - 'wireless-controller.hotspot20_h2qp-osu-provider-nai'
                 - 'wireless-controller.hotspot20_h2qp-terms-and-conditions'
                 - 'wireless-controller.hotspot20_hs-profile'
                 - 'wireless-controller_vap'
                 - 'wireless-controller_timers'
                 - 'wireless-controller_setting'
                 - 'wireless-controller_log'
                 - 'wireless-controller_apcfg-profile'
                 - 'wireless-controller_bonjour-profile'
                 - 'wireless-controller_arrp-profile'
                 - 'wireless-controller_region'
                 - 'wireless-controller_vap-group'
                 - 'wireless-controller_wids-profile'
                 - 'wireless-controller_ble-profile'
                 - 'wireless-controller_syslog-profile'
                 - 'wireless-controller_wtp-profile'
                 - 'wireless-controller_wtp'
                 - 'wireless-controller_wtp-group'
                 - 'wireless-controller_qos-profile'
                 - 'wireless-controller_wag-profile'
                 - 'wireless-controller_utm-profile'
                 - 'wireless-controller_snmp'
                 - 'wireless-controller_mpsk-profile'
                 - 'wireless-controller_nac-profile'
                 - 'wireless-controller_ssid-policy'
                 - 'wireless-controller_access-control-list'
                 - 'wireless-controller_ap-status'
                 - 'switch-controller_traffic-policy'
                 - 'switch-controller_fortilink-settings'
                 - 'switch-controller_switch-interface-tag'
                 - 'switch-controller_802-1X-settings'
                 - 'switch-controller.security-policy_802-1X'
                 - 'switch-controller.security-policy_local-access'
                 - 'switch-controller_location'
                 - 'switch-controller_lldp-settings'
                 - 'switch-controller_lldp-profile'
                 - 'switch-controller.qos_dot1p-map'
                 - 'switch-controller.qos_ip-dscp-map'
                 - 'switch-controller.qos_queue-policy'
                 - 'switch-controller.qos_qos-policy'
                 - 'switch-controller_storm-control-policy'
                 - 'switch-controller.auto-config_policy'
                 - 'switch-controller.auto-config_default'
                 - 'switch-controller.auto-config_custom'
                 - 'switch-controller.initial-config_template'
                 - 'switch-controller.initial-config_vlans'
                 - 'switch-controller_switch-profile'
                 - 'switch-controller_custom-command'
                 - 'switch-controller_virtual-port-pool'
                 - 'switch-controller.ptp_profile'
                 - 'switch-controller.ptp_interface-policy'
                 - 'switch-controller_vlan-policy'
                 - 'switch-controller.acl_ingress'
                 - 'switch-controller.acl_group'
                 - 'switch-controller_dynamic-port-policy'
                 - 'switch-controller_managed-switch'
                 - 'switch-controller_switch-group'
                 - 'switch-controller_stp-settings'
                 - 'switch-controller_stp-instance'
                 - 'switch-controller_storm-control'
                 - 'switch-controller_global'
                 - 'switch-controller_system'
                 - 'switch-controller_switch-log'
                 - 'switch-controller_igmp-snooping'
                 - 'switch-controller_sflow'
                 - 'switch-controller_quarantine'
                 - 'switch-controller_network-monitor-settings'
                 - 'switch-controller_flow-tracking'
                 - 'switch-controller_snmp-sysinfo'
                 - 'switch-controller_snmp-trap-threshold'
                 - 'switch-controller_snmp-community'
                 - 'switch-controller_snmp-user'
                 - 'switch-controller_traffic-sniffer'
                 - 'switch-controller_remote-log'
                 - 'switch-controller_mac-policy'
                 - 'firewall_address'
                 - 'firewall_multicast-address'
                 - 'firewall_address6-template'
                 - 'firewall_address6'
                 - 'firewall_multicast-address6'
                 - 'firewall_addrgrp'
                 - 'firewall_addrgrp6'
                 - 'firewall.wildcard-fqdn_custom'
                 - 'firewall.wildcard-fqdn_group'
                 - 'firewall_traffic-class'
                 - 'firewall.service_category'
                 - 'firewall.service_custom'
                 - 'firewall.service_group'
                 - 'firewall_internet-service-name'
                 - 'firewall_internet-service-group'
                 - 'firewall_internet-service-extension'
                 - 'firewall_internet-service-custom'
                 - 'firewall_internet-service-addition'
                 - 'firewall_internet-service-append'
                 - 'firewall_internet-service-custom-group'
                 - 'firewall_internet-service-definition'
                 - 'firewall_network-service-dynamic'
                 - 'firewall.shaper_traffic-shaper'
                 - 'firewall.shaper_per-ip-shaper'
                 - 'firewall_proxy-address'
                 - 'firewall_proxy-addrgrp'
                 - 'firewall.schedule_onetime'
                 - 'firewall.schedule_recurring'
                 - 'firewall.schedule_group'
                 - 'firewall_ippool'
                 - 'firewall_ippool6'
                 - 'firewall_ldb-monitor'
                 - 'firewall_vip'
                 - 'firewall_vip6'
                 - 'firewall_vipgrp'
                 - 'firewall_vipgrp6'
                 - 'firewall.ssh_local-key'
                 - 'firewall.ssh_local-ca'
                 - 'firewall.ssh_setting'
                 - 'firewall.ssh_host-key'
                 - 'firewall_decrypted-traffic-mirror'
                 - 'firewall_access-proxy-virtual-host'
                 - 'firewall_access-proxy-ssh-client-cert'
                 - 'firewall_access-proxy'
                 - 'firewall_access-proxy6'
                 - 'firewall.ipmacbinding_setting'
                 - 'firewall.ipmacbinding_table'
                 - 'firewall_profile-protocol-options'
                 - 'firewall_ssl-ssh-profile'
                 - 'firewall_ssl-server'
                 - 'firewall_profile-group'
                 - 'firewall_identity-based-route'
                 - 'firewall_auth-portal'
                 - 'firewall_security-policy'
                 - 'firewall_policy'
                 - 'firewall_shaping-policy'
                 - 'firewall_shaping-profile'
                 - 'firewall_local-in-policy'
                 - 'firewall_local-in-policy6'
                 - 'firewall_ttl-policy'
                 - 'firewall_proxy-policy'
                 - 'firewall_dnstranslation'
                 - 'firewall_multicast-policy'
                 - 'firewall_multicast-policy6'
                 - 'firewall_interface-policy'
                 - 'firewall_interface-policy6'
                 - 'firewall_DoS-policy'
                 - 'firewall_DoS-policy6'
                 - 'firewall_sniffer'
                 - 'firewall_on-demand-sniffer'
                 - 'firewall_central-snat-map'
                 - 'firewall.ssl_setting'
                 - 'firewall_ip-translation'
                 - 'firewall_ipv6-eh-filter'
                 - 'firewall_global'
                 - 'vpn.certificate_ca'
                 - 'vpn.certificate_remote'
                 - 'vpn.certificate_local'
                 - 'vpn.certificate_crl'
                 - 'vpn.certificate_ocsp-server'
                 - 'vpn.certificate_setting'
                 - 'vpn_qkd'
                 - 'vpn.ssl.web_realm'
                 - 'vpn.ssl.web_host-check-software'
                 - 'vpn.ssl.web_portal'
                 - 'vpn.ssl.web_user-group-bookmark'
                 - 'vpn.ssl.web_user-bookmark'
                 - 'vpn.ssl_settings'
                 - 'vpn.ssl_client'
                 - 'vpn.ipsec_fec'
                 - 'vpn.ipsec_phase1'
                 - 'vpn.ipsec_phase2'
                 - 'vpn.ipsec_manualkey'
                 - 'vpn.ipsec_concentrator'
                 - 'vpn.ipsec_phase1-interface'
                 - 'vpn.ipsec_phase2-interface'
                 - 'vpn.ipsec_manualkey-interface'
                 - 'vpn.ipsec_forticlient'
                 - 'vpn_kmip-server'
                 - 'vpn_pptp'
                 - 'vpn_l2tp'
                 - 'certificate_ca'
                 - 'certificate_remote'
                 - 'certificate_local'
                 - 'certificate_crl'
                 - 'webfilter_ftgd-local-cat'
                 - 'webfilter_content'
                 - 'webfilter_content-header'
                 - 'webfilter_urlfilter'
                 - 'webfilter_ips-urlfilter-setting'
                 - 'webfilter_ips-urlfilter-setting6'
                 - 'webfilter_ips-urlfilter-cache-setting'
                 - 'webfilter_profile'
                 - 'webfilter_fortiguard'
                 - 'webfilter_override'
                 - 'webfilter_ftgd-local-rating'
                 - 'webfilter_search-engine'
                 - 'ips_sensor'
                 - 'ips_custom'
                 - 'ips_global'
                 - 'ips_settings'
                 - 'sctp-filter_profile'
                 - 'diameter-filter_profile'
                 - 'web-proxy_profile'
                 - 'web-proxy_global'
                 - 'web-proxy_explicit'
                 - 'web-proxy_forward-server'
                 - 'web-proxy_forward-server-group'
                 - 'web-proxy_debug-url'
                 - 'web-proxy_wisp'
                 - 'web-proxy_fast-fallback'
                 - 'web-proxy_url-match'
                 - 'wanopt_webcache'
                 - 'wanopt_settings'
                 - 'wanopt_peer'
                 - 'wanopt_auth-group'
                 - 'wanopt_profile'
                 - 'wanopt_content-delivery-network-rule'
                 - 'wanopt_cache-service'
                 - 'wanopt_remote-storage'
                 - 'ftp-proxy_explicit'
                 - 'application_custom'
                 - 'application_list'
                 - 'application_group'
                 - 'dlp_data-type'
                 - 'dlp_dictionary'
                 - 'dlp_exact-data-match'
                 - 'dlp_sensor'
                 - 'dlp_filepattern'
                 - 'dlp_sensitivity'
                 - 'dlp_fp-doc-source'
                 - 'dlp_profile'
                 - 'dlp_settings'
                 - 'videofilter_youtube-key'
                 - 'videofilter_keyword'
                 - 'videofilter_profile'
                 - 'emailfilter_bword'
                 - 'emailfilter_block-allow-list'
                 - 'emailfilter_mheader'
                 - 'emailfilter_dnsbl'
                 - 'emailfilter_iptrust'
                 - 'emailfilter_profile'
                 - 'emailfilter_fortishield'
                 - 'emailfilter_options'
                 - 'log_threat-weight'
                 - 'log_custom-field'
                 - 'log.syslogd_setting'
                 - 'log.syslogd_override-setting'
                 - 'log.syslogd_filter'
                 - 'log.syslogd_override-filter'
                 - 'log.syslogd2_setting'
                 - 'log.syslogd2_override-setting'
                 - 'log.syslogd2_filter'
                 - 'log.syslogd2_override-filter'
                 - 'log.syslogd3_setting'
                 - 'log.syslogd3_override-setting'
                 - 'log.syslogd3_filter'
                 - 'log.syslogd3_override-filter'
                 - 'log.syslogd4_setting'
                 - 'log.syslogd4_override-setting'
                 - 'log.syslogd4_filter'
                 - 'log.syslogd4_override-filter'
                 - 'log.webtrends_setting'
                 - 'log.webtrends_filter'
                 - 'log.memory_global-setting'
                 - 'log.memory_setting'
                 - 'log.memory_filter'
                 - 'log.disk_setting'
                 - 'log.disk_filter'
                 - 'log_eventfilter'
                 - 'log.fortiguard_setting'
                 - 'log.fortiguard_override-setting'
                 - 'log.fortiguard_filter'
                 - 'log.fortiguard_override-filter'
                 - 'log.tacacs+accounting_setting'
                 - 'log.tacacs+accounting_filter'
                 - 'log.tacacs+accounting2_setting'
                 - 'log.tacacs+accounting2_filter'
                 - 'log.tacacs+accounting3_setting'
                 - 'log.tacacs+accounting3_filter'
                 - 'log.null-device_setting'
                 - 'log.null-device_filter'
                 - 'log_setting'
                 - 'log_gui-display'
                 - 'log.fortianalyzer_setting'
                 - 'log.fortianalyzer_override-setting'
                 - 'log.fortianalyzer_filter'
                 - 'log.fortianalyzer_override-filter'
                 - 'log.fortianalyzer2_setting'
                 - 'log.fortianalyzer2_override-setting'
                 - 'log.fortianalyzer2_filter'
                 - 'log.fortianalyzer2_override-filter'
                 - 'log.fortianalyzer3_setting'
                 - 'log.fortianalyzer3_override-setting'
                 - 'log.fortianalyzer3_filter'
                 - 'log.fortianalyzer3_override-filter'
                 - 'log.fortianalyzer-cloud_setting'
                 - 'log.fortianalyzer-cloud_override-setting'
                 - 'log.fortianalyzer-cloud_filter'
                 - 'log.fortianalyzer-cloud_override-filter'
                 - 'icap_server'
                 - 'icap_server-group'
                 - 'icap_profile'
                 - 'user_peer'
                 - 'user_peergrp'
                 - 'user_certificate'
                 - 'user_radius'
                 - 'user_tacacs+'
                 - 'user_exchange'
                 - 'user_ldap'
                 - 'user_krb-keytab'
                 - 'user_domain-controller'
                 - 'user_pop3'
                 - 'user_saml'
                 - 'user_external-identity-provider'
                 - 'user_fsso'
                 - 'user_adgrp'
                 - 'user_fsso-polling'
                 - 'user_fortitoken'
                 - 'user_password-policy'
                 - 'user_local'
                 - 'user_setting'
                 - 'user_quarantine'
                 - 'user_group'
                 - 'user_security-exempt-list'
                 - 'user_nac-policy'
                 - 'voip_profile'
                 - 'dnsfilter_domain-filter'
                 - 'dnsfilter_profile'
                 - 'nsxt_setting'
                 - 'nsxt_service-chain'
                 - 'antivirus_settings'
                 - 'antivirus_quarantine'
                 - 'antivirus_exempt-list'
                 - 'antivirus_profile'
                 - 'ssh-filter_profile'
                 - 'file-filter_profile'
                 - 'virtual-patch_profile'
                 - 'report_layout'
                 - 'report_setting'
                 - 'waf_main-class'
                 - 'waf_sub-class'
                 - 'waf_signature'
                 - 'waf_profile'
                 - 'casb_saas-application'
                 - 'casb_user-activity'
                 - 'casb_profile'
                 - 'authentication_scheme'
                 - 'authentication_rule'
                 - 'authentication_setting'
                 - 'extension-controller_dataplan'
                 - 'extension-controller_extender-vap'
                 - 'extension-controller_extender-profile'
                 - 'extension-controller_extender'
                 - 'extension-controller_fortigate-profile'
                 - 'extension-controller_fortigate'
                 - 'endpoint-control_fctems'
                 - 'endpoint-control_settings'
                 - 'endpoint-control_fctems-override'
                 - 'alertemail_setting'
                 - 'router_access-list'
                 - 'router_access-list6'
                 - 'router_aspath-list'
                 - 'router_prefix-list'
                 - 'router_prefix-list6'
                 - 'router_key-chain'
                 - 'router_community-list'
                 - 'router_extcommunity-list'
                 - 'router_route-map'
                 - 'router_rip'
                 - 'router_ripng'
                 - 'router_static'
                 - 'router_policy'
                 - 'router_policy6'
                 - 'router_static6'
                 - 'router_ospf'
                 - 'router_ospf6'
                 - 'router_bgp'
                 - 'router_isis'
                 - 'router_multicast-flow'
                 - 'router_multicast'
                 - 'router_multicast6'
                 - 'router_auth-path'
                 - 'router_setting'
                 - 'router_bfd'
                 - 'router_bfd6'
                 - 'automation_setting'
                 - 'dpdk_global'
                 - 'dpdk_cpus'
                 - 'system_isf-queue-profile'
                 - 'system_npu'
                 - 'system_np6'
                 - 'system_gi-gk'
                 - 'system_modem'
                 - 'system.3g-modem_custom'
                 - 'system_lte-modem'
                 - 'firewall_gtp'
                 - 'firewall_pfcp'
                 - 'firewall_acl'
                 - 'firewall_acl6'
                 - 'gtp_apn'
                 - 'gtp_apngrp'
                 - 'gtp_message-filter-v0v1'
                 - 'gtp_message-filter-v2'
                 - 'gtp_rat-timeout-profile'
                 - 'gtp_ie-allow-list'
                 - 'gtp_tunnel-limit'
                 - 'gtp_apn-shaper'
                 - 'pfcp_message-filter'
                 - 'monitoring_np6-ipsec-engine'
                 - 'monitoring_npu-hpe'
                 - 'system_npu-vlink'
                 - 'system_physical-switch'
                 - 'system_virtual-switch'
                 - 'system_stp'
                 - 'system_smc-ntp'
                 - 'videofilter_youtube-channel-filter'
                 - 'switch-controller.ptp_settings'
                 - 'switch-controller.ptp_policy'
                 - 'vpn_ocvpn'
                 - 'system.replacemsg_mail'
                 - 'system.replacemsg_http'
                 - 'system.replacemsg_webproxy'
                 - 'system.replacemsg_ftp'
                 - 'system.replacemsg_fortiguard-wf'
                 - 'system.replacemsg_spam'
                 - 'system.replacemsg_alertmail'
                 - 'system.replacemsg_admin'
                 - 'system.replacemsg_auth'
                 - 'system.replacemsg_sslvpn'
                 - 'system.replacemsg_nac-quar'
                 - 'system.replacemsg_traffic-quota'
                 - 'system.replacemsg_utm'
                 - 'system.replacemsg_icap'
                 - 'system.replacemsg_automation'
                 - 'system_status'
                 - 'system.performance_status'
                 - 'system.performance_top'
                 - 'system.performance.firewall_packet-distribution'
                 - 'system.performance.firewall_statistics'
                 - 'system_session'
                 - 'system_session6'
                 - 'system_cmdb'
                 - 'system_fortiguard-service'
                 - 'system_fortianalyzer-connectivity'
                 - 'system.checksum_status'
                 - 'system_mgmt-csum'
                 - 'system_ha-nonsync-csum'
                 - 'system_fortiguard-log-service'
                 - 'system_central-mgmt'
                 - 'system.info.admin_status'
                 - 'system.info.admin_ssh'
                 - 'system_geoip-country'
                 - 'system_cluster-sync'
                 - 'system_arp'
                 - 'system_startup-error-log'
                 - 'system.source-ip_status'
                 - 'system.auto-update_status'
                 - 'system.auto-update_versions'
                 - 'system.session-info_list'
                 - 'system.session-info_expectation'
                 - 'system.session-info_full-stat'
                 - 'system.session-info_statistics'
                 - 'system.session-info_ttl'
                 - 'system.session-helper-info_list'
                 - 'system.ip-conflict_status'
                 - 'wireless-controller_scan'
                 - 'wireless-controller_wlchanlistlic'
                 - 'wireless-controller_status'
                 - 'wireless-controller_wtp-status'
                 - 'wireless-controller_client-info'
                 - 'wireless-controller_vap-status'
                 - 'wireless-controller_rf-analysis'
                 - 'wireless-controller_spectral-info'
                 - 'ipsec_tunnel'
                 - 'firewall_city'
                 - 'firewall_region'
                 - 'firewall_country'
                 - 'firewall_internet-service'
                 - 'firewall_internet-service-reputation'
                 - 'firewall_internet-service-sld'
                 - 'firewall_internet-service-ipbl-vendor'
                 - 'firewall_internet-service-ipbl-reason'
                 - 'firewall_internet-service-owner'
                 - 'firewall_internet-service-list'
                 - 'firewall_internet-service-botnet'
                 - 'firewall_vendor-mac'
                 - 'firewall_vendor-mac-summary'
                 - 'firewall.shaper_traffic'
                 - 'firewall.shaper_per-ip'
                 - 'firewall.iprope_list'
                 - 'firewall.iprope.appctrl_list'
                 - 'firewall.iprope.appctrl_status'
                 - 'firewall_proute'
                 - 'firewall_proute6'
                 - 'vpn.ssl_monitor'
                 - 'vpn.ipsec.stats_crypto'
                 - 'vpn.ipsec.stats_tunnel'
                 - 'vpn.ipsec.tunnel_details'
                 - 'vpn.ipsec.tunnel_summary'
                 - 'vpn.ipsec.tunnel_name'
                 - 'vpn.ike_gateway'
                 - 'vpn.status_l2tp'
                 - 'vpn.status_pptp'
                 - 'vpn.status.ssl_list'
                 - 'vpn.status.ssl_hw-acceleration-status'
                 - 'webfilter_categories'
                 - 'webfilter_ftgd-statistics'
                 - 'webfilter_status'
                 - 'webfilter_override-usr'
                 - 'ips_view-map'
                 - 'ips_decoder'
                 - 'ips_rule'
                 - 'ips_rule-settings'
                 - 'ips_session'
                 - 'application_name'
                 - 'application_rule-settings'
                 - 'report.sql_status'
                 - 'extender-controller_dataplan'
                 - 'extender-controller_extender-profile'
                 - 'extender-controller_extender'
                 - 'router_info'
                 - 'router_info6'
                 - 'hardware_status'
                 - 'hardware_cpu'
                 - 'hardware_memory'
                 - 'hardware_nic'
                 - 'hardware.npu.np6_port-list'
                 - 'hardware.npu.np6_dce'
                 - 'hardware.npu.np6_session-stats'
                 - 'hardware.npu.np6_sse-stats'
                 - 'hardware.npu.np6_ipsec-stats'
                 - 'hardware.npu.np6_synproxy-stats'
                 - 'mgmt-data_status'
                 - 'extender_sys-info'
                 - 'extender_extender-info'
                 - 'extender_session-info'
                 - 'extender_datachannel-info'
                 - 'extender_fexwan'
                 - 'extender_modem-status'
                 - 'extender_lte-carrier-list'
                 - 'extender_lte-carrier-by-mcc-mnc'
                 - 'wireless-controller_address'
                 - 'wireless-controller_addrgrp'
                 - 'system_fortiai'
                 - 'system_fortimanager'
                 - 'system_fm'
                 - 'system_nat64'
                 - 'firewall_vip46'
                 - 'firewall_vip64'
                 - 'firewall_vipgrp46'
                 - 'firewall_vipgrp64'
                 - 'firewall_policy64'
                 - 'firewall_policy46'
                 - 'system.autoupdate_push-update'
                 - 'switch-controller_nac-settings'
                 - 'switch-controller_port-policy'
                 - 'switch-controller_nac-device'
                 - 'emailfilter_bwl'
                 - 'antivirus_heuristic'
                 - 'credential-store_domain-controller'
                 - 'report_dataset'
                 - 'report_chart'
                 - 'report_style'
                 - 'report_theme'
                 - 'gtp_ie-white-list'
                 - 'system.replacemsg_nntp'
                 - 'system.replacemsg_device-detection-portal'
                 - 'switch-controller_poe'
                 - 'cifs_domain-controller'
                 - 'cifs_profile'
                 - 'system.replacemsg_mms'
                 - 'system.replacemsg_mm1'
                 - 'system.replacemsg_mm3'
                 - 'system.replacemsg_mm4'
                 - 'system.replacemsg_mm7'
                 - 'system_virtual-wan-link'
                 - 'system_mem-mgr'
                 - 'firewall_carrier-endpoint-bwl'
                 - 'firewall_mms-profile'
                 - 'firewall.consolidated_policy'
                 - 'firewall_policy6'
                 - 'antivirus_notification'
                 - 'antivirus_mms-checksum'
                 - 'switch-controller_vlan'
                 - 'switch-controller.security-policy_captive-portal'
                 - 'user_device'
                 - 'user_device-group'
                 - 'endpoint-control_client'
                 - 'system.replacemsg_ec'
                 - 'dlp_fp-sensitivity'
                 - 'spamfilter_bword'
                 - 'spamfilter_bwl'
                 - 'spamfilter_mheader'
                 - 'spamfilter_dnsbl'
                 - 'spamfilter_iptrust'
                 - 'spamfilter_profile'
                 - 'spamfilter_fortishield'
                 - 'spamfilter_options'
                 - 'user_device-category'
                 - 'user_device-access-list'
                 - 'switch-controller_mac-sync-settings'
                 - 'endpoint-control_forticlient-ems'
                 - 'endpoint-control_profile'
                 - 'endpoint-control_forticlient-registration-sync'
                 - 'endpoint-control_registered-forticlient'

    selector:
        description:
            - selector for retrieving the fortigate facts
        type: str
        required: false
        choices:
         - 'system_vdom'
         - 'system_global'
         - 'system_accprofile'
         - 'system_vdom-link'
         - 'system_switch-interface'
         - 'system_object-tagging'
         - 'system_interface'
         - 'system_password-policy'
         - 'system_password-policy-guest-admin'
         - 'system_sms-server'
         - 'system_custom-language'
         - 'system_admin'
         - 'system_api-user'
         - 'system_sso-admin'
         - 'system_sso-forticloud-admin'
         - 'system_sso-fortigate-cloud-admin'
         - 'system_settings'
         - 'system_sit-tunnel'
         - 'system_fsso-polling'
         - 'system_ha'
         - 'system_ha-monitor'
         - 'system_storage'
         - 'system_dedicated-mgmt'
         - 'system_arp-table'
         - 'system_ipv6-neighbor-cache'
         - 'system_dns'
         - 'system_ddns'
         - 'system_sflow'
         - 'system_vdom-sflow'
         - 'system_netflow'
         - 'system_vdom-netflow'
         - 'system_vdom-dns'
         - 'system_replacemsg-image'
         - 'system_replacemsg-group'
         - 'system.snmp_sysinfo'
         - 'system.snmp_mib-view'
         - 'system.snmp_community'
         - 'system.snmp_user'
         - 'system.autoupdate_schedule'
         - 'system.autoupdate_tunneling'
         - 'system_session-ttl'
         - 'system.dhcp_server'
         - 'system.dhcp6_server'
         - 'system_alias'
         - 'system_auto-script'
         - 'system_management-tunnel'
         - 'system_central-management'
         - 'system_zone'
         - 'system_sdn-proxy'
         - 'system_sdn-connector'
         - 'system_ipv6-tunnel'
         - 'system_external-resource'
         - 'system_ips-urlfilter-dns'
         - 'system_ips-urlfilter-dns6'
         - 'system_network-visibility'
         - 'system_sdwan'
         - 'system_evpn'
         - 'system_gre-tunnel'
         - 'system_ipsec-aggregate'
         - 'system_ipip-tunnel'
         - 'system_mobile-tunnel'
         - 'system_pppoe-interface'
         - 'system_vxlan'
         - 'system_geneve'
         - 'system_virtual-wire-pair'
         - 'system_dns-database'
         - 'system_dns-server'
         - 'system_resource-limits'
         - 'system_vdom-property'
         - 'system_speed-test-server'
         - 'system.lldp_network-policy'
         - 'system_pcp-server'
         - 'system_speed-test-schedule'
         - 'system_speed-test-setting'
         - 'system_standalone-cluster'
         - 'system_fortiguard'
         - 'system_ips'
         - 'system_email-server'
         - 'system_alarm'
         - 'system_mac-address-table'
         - 'system_session-helper'
         - 'system_proxy-arp'
         - 'system_fips-cc'
         - 'system_tos-based-priority'
         - 'system_dscp-based-priority'
         - 'system_probe-response'
         - 'system_link-monitor'
         - 'system_auto-install'
         - 'system_console'
         - 'system_ntp'
         - 'system_ptp'
         - 'system_wccp'
         - 'system_dns64'
         - 'system_vdom-radius-server'
         - 'system_ftm-push'
         - 'system_geoip-override'
         - 'system_fortisandbox'
         - 'system_fortindr'
         - 'system_affinity-interrupt'
         - 'system_affinity-packet-redistribution'
         - 'system_vdom-exception'
         - 'system_csf'
         - 'system_automation-trigger'
         - 'system_automation-action'
         - 'system_automation-destination'
         - 'system_automation-stitch'
         - 'system_nd-proxy'
         - 'system_saml'
         - 'system_federated-upgrade'
         - 'system_device-upgrade'
         - 'system_vne-tunnel'
         - 'system_ike'
         - 'system_acme'
         - 'system_ipam'
         - 'system_fabric-vpn'
         - 'system_ssh-config'
         - 'wireless-controller_inter-controller'
         - 'wireless-controller_global'
         - 'wireless-controller.hotspot20_anqp-venue-name'
         - 'wireless-controller.hotspot20_anqp-venue-url'
         - 'wireless-controller.hotspot20_anqp-network-auth-type'
         - 'wireless-controller.hotspot20_anqp-roaming-consortium'
         - 'wireless-controller.hotspot20_anqp-nai-realm'
         - 'wireless-controller.hotspot20_anqp-3gpp-cellular'
         - 'wireless-controller.hotspot20_anqp-ip-address-type'
         - 'wireless-controller.hotspot20_h2qp-operator-name'
         - 'wireless-controller.hotspot20_h2qp-wan-metric'
         - 'wireless-controller.hotspot20_h2qp-conn-capability'
         - 'wireless-controller.hotspot20_icon'
         - 'wireless-controller.hotspot20_h2qp-osu-provider'
         - 'wireless-controller.hotspot20_qos-map'
         - 'wireless-controller.hotspot20_h2qp-advice-of-charge'
         - 'wireless-controller.hotspot20_h2qp-osu-provider-nai'
         - 'wireless-controller.hotspot20_h2qp-terms-and-conditions'
         - 'wireless-controller.hotspot20_hs-profile'
         - 'wireless-controller_vap'
         - 'wireless-controller_timers'
         - 'wireless-controller_setting'
         - 'wireless-controller_log'
         - 'wireless-controller_apcfg-profile'
         - 'wireless-controller_bonjour-profile'
         - 'wireless-controller_arrp-profile'
         - 'wireless-controller_region'
         - 'wireless-controller_vap-group'
         - 'wireless-controller_wids-profile'
         - 'wireless-controller_ble-profile'
         - 'wireless-controller_syslog-profile'
         - 'wireless-controller_wtp-profile'
         - 'wireless-controller_wtp'
         - 'wireless-controller_wtp-group'
         - 'wireless-controller_qos-profile'
         - 'wireless-controller_wag-profile'
         - 'wireless-controller_utm-profile'
         - 'wireless-controller_snmp'
         - 'wireless-controller_mpsk-profile'
         - 'wireless-controller_nac-profile'
         - 'wireless-controller_ssid-policy'
         - 'wireless-controller_access-control-list'
         - 'wireless-controller_ap-status'
         - 'switch-controller_traffic-policy'
         - 'switch-controller_fortilink-settings'
         - 'switch-controller_switch-interface-tag'
         - 'switch-controller_802-1X-settings'
         - 'switch-controller.security-policy_802-1X'
         - 'switch-controller.security-policy_local-access'
         - 'switch-controller_location'
         - 'switch-controller_lldp-settings'
         - 'switch-controller_lldp-profile'
         - 'switch-controller.qos_dot1p-map'
         - 'switch-controller.qos_ip-dscp-map'
         - 'switch-controller.qos_queue-policy'
         - 'switch-controller.qos_qos-policy'
         - 'switch-controller_storm-control-policy'
         - 'switch-controller.auto-config_policy'
         - 'switch-controller.auto-config_default'
         - 'switch-controller.auto-config_custom'
         - 'switch-controller.initial-config_template'
         - 'switch-controller.initial-config_vlans'
         - 'switch-controller_switch-profile'
         - 'switch-controller_custom-command'
         - 'switch-controller_virtual-port-pool'
         - 'switch-controller.ptp_profile'
         - 'switch-controller.ptp_interface-policy'
         - 'switch-controller_vlan-policy'
         - 'switch-controller.acl_ingress'
         - 'switch-controller.acl_group'
         - 'switch-controller_dynamic-port-policy'
         - 'switch-controller_managed-switch'
         - 'switch-controller_switch-group'
         - 'switch-controller_stp-settings'
         - 'switch-controller_stp-instance'
         - 'switch-controller_storm-control'
         - 'switch-controller_global'
         - 'switch-controller_system'
         - 'switch-controller_switch-log'
         - 'switch-controller_igmp-snooping'
         - 'switch-controller_sflow'
         - 'switch-controller_quarantine'
         - 'switch-controller_network-monitor-settings'
         - 'switch-controller_flow-tracking'
         - 'switch-controller_snmp-sysinfo'
         - 'switch-controller_snmp-trap-threshold'
         - 'switch-controller_snmp-community'
         - 'switch-controller_snmp-user'
         - 'switch-controller_traffic-sniffer'
         - 'switch-controller_remote-log'
         - 'switch-controller_mac-policy'
         - 'firewall_address'
         - 'firewall_multicast-address'
         - 'firewall_address6-template'
         - 'firewall_address6'
         - 'firewall_multicast-address6'
         - 'firewall_addrgrp'
         - 'firewall_addrgrp6'
         - 'firewall.wildcard-fqdn_custom'
         - 'firewall.wildcard-fqdn_group'
         - 'firewall_traffic-class'
         - 'firewall.service_category'
         - 'firewall.service_custom'
         - 'firewall.service_group'
         - 'firewall_internet-service-name'
         - 'firewall_internet-service-group'
         - 'firewall_internet-service-extension'
         - 'firewall_internet-service-custom'
         - 'firewall_internet-service-addition'
         - 'firewall_internet-service-append'
         - 'firewall_internet-service-custom-group'
         - 'firewall_internet-service-definition'
         - 'firewall_network-service-dynamic'
         - 'firewall.shaper_traffic-shaper'
         - 'firewall.shaper_per-ip-shaper'
         - 'firewall_proxy-address'
         - 'firewall_proxy-addrgrp'
         - 'firewall.schedule_onetime'
         - 'firewall.schedule_recurring'
         - 'firewall.schedule_group'
         - 'firewall_ippool'
         - 'firewall_ippool6'
         - 'firewall_ldb-monitor'
         - 'firewall_vip'
         - 'firewall_vip6'
         - 'firewall_vipgrp'
         - 'firewall_vipgrp6'
         - 'firewall.ssh_local-key'
         - 'firewall.ssh_local-ca'
         - 'firewall.ssh_setting'
         - 'firewall.ssh_host-key'
         - 'firewall_decrypted-traffic-mirror'
         - 'firewall_access-proxy-virtual-host'
         - 'firewall_access-proxy-ssh-client-cert'
         - 'firewall_access-proxy'
         - 'firewall_access-proxy6'
         - 'firewall.ipmacbinding_setting'
         - 'firewall.ipmacbinding_table'
         - 'firewall_profile-protocol-options'
         - 'firewall_ssl-ssh-profile'
         - 'firewall_ssl-server'
         - 'firewall_profile-group'
         - 'firewall_identity-based-route'
         - 'firewall_auth-portal'
         - 'firewall_security-policy'
         - 'firewall_policy'
         - 'firewall_shaping-policy'
         - 'firewall_shaping-profile'
         - 'firewall_local-in-policy'
         - 'firewall_local-in-policy6'
         - 'firewall_ttl-policy'
         - 'firewall_proxy-policy'
         - 'firewall_dnstranslation'
         - 'firewall_multicast-policy'
         - 'firewall_multicast-policy6'
         - 'firewall_interface-policy'
         - 'firewall_interface-policy6'
         - 'firewall_DoS-policy'
         - 'firewall_DoS-policy6'
         - 'firewall_sniffer'
         - 'firewall_on-demand-sniffer'
         - 'firewall_central-snat-map'
         - 'firewall.ssl_setting'
         - 'firewall_ip-translation'
         - 'firewall_ipv6-eh-filter'
         - 'firewall_global'
         - 'vpn.certificate_ca'
         - 'vpn.certificate_remote'
         - 'vpn.certificate_local'
         - 'vpn.certificate_crl'
         - 'vpn.certificate_ocsp-server'
         - 'vpn.certificate_setting'
         - 'vpn_qkd'
         - 'vpn.ssl.web_realm'
         - 'vpn.ssl.web_host-check-software'
         - 'vpn.ssl.web_portal'
         - 'vpn.ssl.web_user-group-bookmark'
         - 'vpn.ssl.web_user-bookmark'
         - 'vpn.ssl_settings'
         - 'vpn.ssl_client'
         - 'vpn.ipsec_fec'
         - 'vpn.ipsec_phase1'
         - 'vpn.ipsec_phase2'
         - 'vpn.ipsec_manualkey'
         - 'vpn.ipsec_concentrator'
         - 'vpn.ipsec_phase1-interface'
         - 'vpn.ipsec_phase2-interface'
         - 'vpn.ipsec_manualkey-interface'
         - 'vpn.ipsec_forticlient'
         - 'vpn_kmip-server'
         - 'vpn_pptp'
         - 'vpn_l2tp'
         - 'certificate_ca'
         - 'certificate_remote'
         - 'certificate_local'
         - 'certificate_crl'
         - 'webfilter_ftgd-local-cat'
         - 'webfilter_content'
         - 'webfilter_content-header'
         - 'webfilter_urlfilter'
         - 'webfilter_ips-urlfilter-setting'
         - 'webfilter_ips-urlfilter-setting6'
         - 'webfilter_ips-urlfilter-cache-setting'
         - 'webfilter_profile'
         - 'webfilter_fortiguard'
         - 'webfilter_override'
         - 'webfilter_ftgd-local-rating'
         - 'webfilter_search-engine'
         - 'ips_sensor'
         - 'ips_custom'
         - 'ips_global'
         - 'ips_settings'
         - 'sctp-filter_profile'
         - 'diameter-filter_profile'
         - 'web-proxy_profile'
         - 'web-proxy_global'
         - 'web-proxy_explicit'
         - 'web-proxy_forward-server'
         - 'web-proxy_forward-server-group'
         - 'web-proxy_debug-url'
         - 'web-proxy_wisp'
         - 'web-proxy_fast-fallback'
         - 'web-proxy_url-match'
         - 'wanopt_webcache'
         - 'wanopt_settings'
         - 'wanopt_peer'
         - 'wanopt_auth-group'
         - 'wanopt_profile'
         - 'wanopt_content-delivery-network-rule'
         - 'wanopt_cache-service'
         - 'wanopt_remote-storage'
         - 'ftp-proxy_explicit'
         - 'application_custom'
         - 'application_list'
         - 'application_group'
         - 'dlp_data-type'
         - 'dlp_dictionary'
         - 'dlp_exact-data-match'
         - 'dlp_sensor'
         - 'dlp_filepattern'
         - 'dlp_sensitivity'
         - 'dlp_fp-doc-source'
         - 'dlp_profile'
         - 'dlp_settings'
         - 'videofilter_youtube-key'
         - 'videofilter_keyword'
         - 'videofilter_profile'
         - 'emailfilter_bword'
         - 'emailfilter_block-allow-list'
         - 'emailfilter_mheader'
         - 'emailfilter_dnsbl'
         - 'emailfilter_iptrust'
         - 'emailfilter_profile'
         - 'emailfilter_fortishield'
         - 'emailfilter_options'
         - 'log_threat-weight'
         - 'log_custom-field'
         - 'log.syslogd_setting'
         - 'log.syslogd_override-setting'
         - 'log.syslogd_filter'
         - 'log.syslogd_override-filter'
         - 'log.syslogd2_setting'
         - 'log.syslogd2_override-setting'
         - 'log.syslogd2_filter'
         - 'log.syslogd2_override-filter'
         - 'log.syslogd3_setting'
         - 'log.syslogd3_override-setting'
         - 'log.syslogd3_filter'
         - 'log.syslogd3_override-filter'
         - 'log.syslogd4_setting'
         - 'log.syslogd4_override-setting'
         - 'log.syslogd4_filter'
         - 'log.syslogd4_override-filter'
         - 'log.webtrends_setting'
         - 'log.webtrends_filter'
         - 'log.memory_global-setting'
         - 'log.memory_setting'
         - 'log.memory_filter'
         - 'log.disk_setting'
         - 'log.disk_filter'
         - 'log_eventfilter'
         - 'log.fortiguard_setting'
         - 'log.fortiguard_override-setting'
         - 'log.fortiguard_filter'
         - 'log.fortiguard_override-filter'
         - 'log.tacacs+accounting_setting'
         - 'log.tacacs+accounting_filter'
         - 'log.tacacs+accounting2_setting'
         - 'log.tacacs+accounting2_filter'
         - 'log.tacacs+accounting3_setting'
         - 'log.tacacs+accounting3_filter'
         - 'log.null-device_setting'
         - 'log.null-device_filter'
         - 'log_setting'
         - 'log_gui-display'
         - 'log.fortianalyzer_setting'
         - 'log.fortianalyzer_override-setting'
         - 'log.fortianalyzer_filter'
         - 'log.fortianalyzer_override-filter'
         - 'log.fortianalyzer2_setting'
         - 'log.fortianalyzer2_override-setting'
         - 'log.fortianalyzer2_filter'
         - 'log.fortianalyzer2_override-filter'
         - 'log.fortianalyzer3_setting'
         - 'log.fortianalyzer3_override-setting'
         - 'log.fortianalyzer3_filter'
         - 'log.fortianalyzer3_override-filter'
         - 'log.fortianalyzer-cloud_setting'
         - 'log.fortianalyzer-cloud_override-setting'
         - 'log.fortianalyzer-cloud_filter'
         - 'log.fortianalyzer-cloud_override-filter'
         - 'icap_server'
         - 'icap_server-group'
         - 'icap_profile'
         - 'user_peer'
         - 'user_peergrp'
         - 'user_certificate'
         - 'user_radius'
         - 'user_tacacs+'
         - 'user_exchange'
         - 'user_ldap'
         - 'user_krb-keytab'
         - 'user_domain-controller'
         - 'user_pop3'
         - 'user_saml'
         - 'user_external-identity-provider'
         - 'user_fsso'
         - 'user_adgrp'
         - 'user_fsso-polling'
         - 'user_fortitoken'
         - 'user_password-policy'
         - 'user_local'
         - 'user_setting'
         - 'user_quarantine'
         - 'user_group'
         - 'user_security-exempt-list'
         - 'user_nac-policy'
         - 'voip_profile'
         - 'dnsfilter_domain-filter'
         - 'dnsfilter_profile'
         - 'nsxt_setting'
         - 'nsxt_service-chain'
         - 'antivirus_settings'
         - 'antivirus_quarantine'
         - 'antivirus_exempt-list'
         - 'antivirus_profile'
         - 'ssh-filter_profile'
         - 'file-filter_profile'
         - 'virtual-patch_profile'
         - 'report_layout'
         - 'report_setting'
         - 'waf_main-class'
         - 'waf_sub-class'
         - 'waf_signature'
         - 'waf_profile'
         - 'casb_saas-application'
         - 'casb_user-activity'
         - 'casb_profile'
         - 'authentication_scheme'
         - 'authentication_rule'
         - 'authentication_setting'
         - 'extension-controller_dataplan'
         - 'extension-controller_extender-vap'
         - 'extension-controller_extender-profile'
         - 'extension-controller_extender'
         - 'extension-controller_fortigate-profile'
         - 'extension-controller_fortigate'
         - 'endpoint-control_fctems'
         - 'endpoint-control_settings'
         - 'endpoint-control_fctems-override'
         - 'alertemail_setting'
         - 'router_access-list'
         - 'router_access-list6'
         - 'router_aspath-list'
         - 'router_prefix-list'
         - 'router_prefix-list6'
         - 'router_key-chain'
         - 'router_community-list'
         - 'router_extcommunity-list'
         - 'router_route-map'
         - 'router_rip'
         - 'router_ripng'
         - 'router_static'
         - 'router_policy'
         - 'router_policy6'
         - 'router_static6'
         - 'router_ospf'
         - 'router_ospf6'
         - 'router_bgp'
         - 'router_isis'
         - 'router_multicast-flow'
         - 'router_multicast'
         - 'router_multicast6'
         - 'router_auth-path'
         - 'router_setting'
         - 'router_bfd'
         - 'router_bfd6'
         - 'automation_setting'
         - 'dpdk_global'
         - 'dpdk_cpus'
         - 'system_isf-queue-profile'
         - 'system_npu'
         - 'system_np6'
         - 'system_gi-gk'
         - 'system_modem'
         - 'system.3g-modem_custom'
         - 'system_lte-modem'
         - 'firewall_gtp'
         - 'firewall_pfcp'
         - 'firewall_acl'
         - 'firewall_acl6'
         - 'gtp_apn'
         - 'gtp_apngrp'
         - 'gtp_message-filter-v0v1'
         - 'gtp_message-filter-v2'
         - 'gtp_rat-timeout-profile'
         - 'gtp_ie-allow-list'
         - 'gtp_tunnel-limit'
         - 'gtp_apn-shaper'
         - 'pfcp_message-filter'
         - 'monitoring_np6-ipsec-engine'
         - 'monitoring_npu-hpe'
         - 'system_npu-vlink'
         - 'system_physical-switch'
         - 'system_virtual-switch'
         - 'system_stp'
         - 'system_smc-ntp'
         - 'videofilter_youtube-channel-filter'
         - 'switch-controller.ptp_settings'
         - 'switch-controller.ptp_policy'
         - 'vpn_ocvpn'
         - 'system.replacemsg_mail'
         - 'system.replacemsg_http'
         - 'system.replacemsg_webproxy'
         - 'system.replacemsg_ftp'
         - 'system.replacemsg_fortiguard-wf'
         - 'system.replacemsg_spam'
         - 'system.replacemsg_alertmail'
         - 'system.replacemsg_admin'
         - 'system.replacemsg_auth'
         - 'system.replacemsg_sslvpn'
         - 'system.replacemsg_nac-quar'
         - 'system.replacemsg_traffic-quota'
         - 'system.replacemsg_utm'
         - 'system.replacemsg_icap'
         - 'system.replacemsg_automation'
         - 'system_status'
         - 'system.performance_status'
         - 'system.performance_top'
         - 'system.performance.firewall_packet-distribution'
         - 'system.performance.firewall_statistics'
         - 'system_session'
         - 'system_session6'
         - 'system_cmdb'
         - 'system_fortiguard-service'
         - 'system_fortianalyzer-connectivity'
         - 'system.checksum_status'
         - 'system_mgmt-csum'
         - 'system_ha-nonsync-csum'
         - 'system_fortiguard-log-service'
         - 'system_central-mgmt'
         - 'system.info.admin_status'
         - 'system.info.admin_ssh'
         - 'system_geoip-country'
         - 'system_cluster-sync'
         - 'system_arp'
         - 'system_startup-error-log'
         - 'system.source-ip_status'
         - 'system.auto-update_status'
         - 'system.auto-update_versions'
         - 'system.session-info_list'
         - 'system.session-info_expectation'
         - 'system.session-info_full-stat'
         - 'system.session-info_statistics'
         - 'system.session-info_ttl'
         - 'system.session-helper-info_list'
         - 'system.ip-conflict_status'
         - 'wireless-controller_scan'
         - 'wireless-controller_wlchanlistlic'
         - 'wireless-controller_status'
         - 'wireless-controller_wtp-status'
         - 'wireless-controller_client-info'
         - 'wireless-controller_vap-status'
         - 'wireless-controller_rf-analysis'
         - 'wireless-controller_spectral-info'
         - 'ipsec_tunnel'
         - 'firewall_city'
         - 'firewall_region'
         - 'firewall_country'
         - 'firewall_internet-service'
         - 'firewall_internet-service-reputation'
         - 'firewall_internet-service-sld'
         - 'firewall_internet-service-ipbl-vendor'
         - 'firewall_internet-service-ipbl-reason'
         - 'firewall_internet-service-owner'
         - 'firewall_internet-service-list'
         - 'firewall_internet-service-botnet'
         - 'firewall_vendor-mac'
         - 'firewall_vendor-mac-summary'
         - 'firewall.shaper_traffic'
         - 'firewall.shaper_per-ip'
         - 'firewall.iprope_list'
         - 'firewall.iprope.appctrl_list'
         - 'firewall.iprope.appctrl_status'
         - 'firewall_proute'
         - 'firewall_proute6'
         - 'vpn.ssl_monitor'
         - 'vpn.ipsec.stats_crypto'
         - 'vpn.ipsec.stats_tunnel'
         - 'vpn.ipsec.tunnel_details'
         - 'vpn.ipsec.tunnel_summary'
         - 'vpn.ipsec.tunnel_name'
         - 'vpn.ike_gateway'
         - 'vpn.status_l2tp'
         - 'vpn.status_pptp'
         - 'vpn.status.ssl_list'
         - 'vpn.status.ssl_hw-acceleration-status'
         - 'webfilter_categories'
         - 'webfilter_ftgd-statistics'
         - 'webfilter_status'
         - 'webfilter_override-usr'
         - 'ips_view-map'
         - 'ips_decoder'
         - 'ips_rule'
         - 'ips_rule-settings'
         - 'ips_session'
         - 'application_name'
         - 'application_rule-settings'
         - 'report.sql_status'
         - 'extender-controller_dataplan'
         - 'extender-controller_extender-profile'
         - 'extender-controller_extender'
         - 'router_info'
         - 'router_info6'
         - 'hardware_status'
         - 'hardware_cpu'
         - 'hardware_memory'
         - 'hardware_nic'
         - 'hardware.npu.np6_port-list'
         - 'hardware.npu.np6_dce'
         - 'hardware.npu.np6_session-stats'
         - 'hardware.npu.np6_sse-stats'
         - 'hardware.npu.np6_ipsec-stats'
         - 'hardware.npu.np6_synproxy-stats'
         - 'mgmt-data_status'
         - 'extender_sys-info'
         - 'extender_extender-info'
         - 'extender_session-info'
         - 'extender_datachannel-info'
         - 'extender_fexwan'
         - 'extender_modem-status'
         - 'extender_lte-carrier-list'
         - 'extender_lte-carrier-by-mcc-mnc'
         - 'wireless-controller_address'
         - 'wireless-controller_addrgrp'
         - 'system_fortiai'
         - 'system_fortimanager'
         - 'system_fm'
         - 'system_nat64'
         - 'firewall_vip46'
         - 'firewall_vip64'
         - 'firewall_vipgrp46'
         - 'firewall_vipgrp64'
         - 'firewall_policy64'
         - 'firewall_policy46'
         - 'system.autoupdate_push-update'
         - 'switch-controller_nac-settings'
         - 'switch-controller_port-policy'
         - 'switch-controller_nac-device'
         - 'emailfilter_bwl'
         - 'antivirus_heuristic'
         - 'credential-store_domain-controller'
         - 'report_dataset'
         - 'report_chart'
         - 'report_style'
         - 'report_theme'
         - 'gtp_ie-white-list'
         - 'system.replacemsg_nntp'
         - 'system.replacemsg_device-detection-portal'
         - 'switch-controller_poe'
         - 'cifs_domain-controller'
         - 'cifs_profile'
         - 'system.replacemsg_mms'
         - 'system.replacemsg_mm1'
         - 'system.replacemsg_mm3'
         - 'system.replacemsg_mm4'
         - 'system.replacemsg_mm7'
         - 'system_virtual-wan-link'
         - 'system_mem-mgr'
         - 'firewall_carrier-endpoint-bwl'
         - 'firewall_mms-profile'
         - 'firewall.consolidated_policy'
         - 'firewall_policy6'
         - 'antivirus_notification'
         - 'antivirus_mms-checksum'
         - 'switch-controller_vlan'
         - 'switch-controller.security-policy_captive-portal'
         - 'user_device'
         - 'user_device-group'
         - 'endpoint-control_client'
         - 'system.replacemsg_ec'
         - 'dlp_fp-sensitivity'
         - 'spamfilter_bword'
         - 'spamfilter_bwl'
         - 'spamfilter_mheader'
         - 'spamfilter_dnsbl'
         - 'spamfilter_iptrust'
         - 'spamfilter_profile'
         - 'spamfilter_fortishield'
         - 'spamfilter_options'
         - 'user_device-category'
         - 'user_device-access-list'
         - 'switch-controller_mac-sync-settings'
         - 'endpoint-control_forticlient-ems'
         - 'endpoint-control_profile'
         - 'endpoint-control_forticlient-registration-sync'
         - 'endpoint-control_registered-forticlient'

    params:
        description:
            - the parameter for each selector, see definition in above list.
        type: dict
        required: false
"""

EXAMPLES = """
- name: Get multiple selectors info concurrently
  fortinet.fortios.fortios_configuration_fact:
      selectors:
          - selector: firewall_address
            params:
                name: "gmail.com"
          - selector: system_interface
          - selector: log_eventfilter
            params: {}

- name: fact gathering
  fortinet.fortios.fortios_configuration_fact:
      vdom: root
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
  fortinet.fortios.fortios_configuration_fact:
      vdom: root
      access_token: ""
      selector: log_custom-field

- name: get single
  fortinet.fortios.fortios_configuration_fact:
      vdom: root
      access_token: ""
      selector: log_custom-field
      params:
          id: "3"

- name: fetch one firewall address
  fortinet.fortios.fortios_configuration_fact:
      selector: firewall_address
      params:
          name: "login.microsoft.com"

- name: fetch all firewall addresses
  fortinet.fortios.fortios_configuration_fact:
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

# from urllib.parse import quote
try:
    # For Python 3
    from urllib.parse import quote
except ImportError:
    # For Python 2
    from urllib import quote

MODULE_MKEY_DEFINITONS = {
    "system_vdom": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_global": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_accprofile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_vdom-link": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_switch-interface": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_object-tagging": {
        "mkey": "category",
        "mkey_type": str,
    },
    "system_interface": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_password-policy": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_password-policy-guest-admin": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_sms-server": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_custom-language": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_admin": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_api-user": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_sso-admin": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_sso-forticloud-admin": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_sso-fortigate-cloud-admin": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_settings": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_sit-tunnel": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_fsso-polling": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_ha": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_ha-monitor": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_storage": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_dedicated-mgmt": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_arp-table": {
        "mkey": "id",
        "mkey_type": int,
    },
    "system_ipv6-neighbor-cache": {
        "mkey": "id",
        "mkey_type": int,
    },
    "system_dns": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_ddns": {
        "mkey": "ddnsid",
        "mkey_type": int,
    },
    "system_sflow": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_vdom-sflow": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_netflow": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_vdom-netflow": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_vdom-dns": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_replacemsg-image": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_replacemsg-group": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system.snmp_sysinfo": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.snmp_mib-view": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system.snmp_community": {
        "mkey": "id",
        "mkey_type": int,
    },
    "system.snmp_user": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system.autoupdate_schedule": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.autoupdate_tunneling": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_session-ttl": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.dhcp_server": {
        "mkey": "id",
        "mkey_type": int,
    },
    "system.dhcp6_server": {
        "mkey": "id",
        "mkey_type": int,
    },
    "system_alias": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_auto-script": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_management-tunnel": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_central-management": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_zone": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_sdn-proxy": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_sdn-connector": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_ipv6-tunnel": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_external-resource": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_ips-urlfilter-dns": {
        "mkey": "address",
        "mkey_type": str,
    },
    "system_ips-urlfilter-dns6": {
        "mkey": "address6",
        "mkey_type": str,
    },
    "system_network-visibility": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_sdwan": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_evpn": {
        "mkey": "id",
        "mkey_type": int,
    },
    "system_gre-tunnel": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_ipsec-aggregate": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_ipip-tunnel": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_mobile-tunnel": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_pppoe-interface": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_vxlan": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_geneve": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_virtual-wire-pair": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_dns-database": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_dns-server": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_resource-limits": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_vdom-property": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_speed-test-server": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system.lldp_network-policy": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_pcp-server": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_speed-test-schedule": {
        "mkey": "interface",
        "mkey_type": str,
    },
    "system_speed-test-setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_standalone-cluster": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_fortiguard": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_ips": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_email-server": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_alarm": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_mac-address-table": {
        "mkey": "mac",
        "mkey_type": str,
    },
    "system_session-helper": {
        "mkey": "id",
        "mkey_type": int,
    },
    "system_proxy-arp": {
        "mkey": "id",
        "mkey_type": int,
    },
    "system_fips-cc": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_tos-based-priority": {
        "mkey": "id",
        "mkey_type": int,
    },
    "system_dscp-based-priority": {
        "mkey": "id",
        "mkey_type": int,
    },
    "system_probe-response": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_link-monitor": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_auto-install": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_console": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_ntp": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_ptp": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_wccp": {
        "mkey": "service_id",
        "mkey_type": str,
    },
    "system_dns64": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_vdom-radius-server": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_ftm-push": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_geoip-override": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_fortisandbox": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_fortindr": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_affinity-interrupt": {
        "mkey": "id",
        "mkey_type": int,
    },
    "system_affinity-packet-redistribution": {
        "mkey": "id",
        "mkey_type": int,
    },
    "system_vdom-exception": {
        "mkey": "id",
        "mkey_type": int,
    },
    "system_csf": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_automation-trigger": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_automation-action": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_automation-destination": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_automation-stitch": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_nd-proxy": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_saml": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_federated-upgrade": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_device-upgrade": {
        "mkey": "serial",
        "mkey_type": str,
    },
    "system_vne-tunnel": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_ike": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_acme": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_ipam": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_fabric-vpn": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_ssh-config": {
        "mkey": "None",
        "mkey_type": None,
    },
    "wireless-controller_inter-controller": {
        "mkey": "None",
        "mkey_type": None,
    },
    "wireless-controller_global": {
        "mkey": "None",
        "mkey_type": None,
    },
    "wireless-controller.hotspot20_anqp-venue-name": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller.hotspot20_anqp-venue-url": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller.hotspot20_anqp-network-auth-type": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller.hotspot20_anqp-roaming-consortium": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller.hotspot20_anqp-nai-realm": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller.hotspot20_anqp-3gpp-cellular": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller.hotspot20_anqp-ip-address-type": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller.hotspot20_h2qp-operator-name": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller.hotspot20_h2qp-wan-metric": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller.hotspot20_h2qp-conn-capability": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller.hotspot20_icon": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller.hotspot20_h2qp-osu-provider": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller.hotspot20_qos-map": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller.hotspot20_h2qp-advice-of-charge": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller.hotspot20_h2qp-osu-provider-nai": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller.hotspot20_h2qp-terms-and-conditions": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller.hotspot20_hs-profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller_vap": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller_timers": {
        "mkey": "None",
        "mkey_type": None,
    },
    "wireless-controller_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "wireless-controller_log": {
        "mkey": "None",
        "mkey_type": None,
    },
    "wireless-controller_apcfg-profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller_bonjour-profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller_arrp-profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller_region": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller_vap-group": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller_wids-profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller_ble-profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller_syslog-profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller_wtp-profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller_wtp": {
        "mkey": "wtp_id",
        "mkey_type": str,
    },
    "wireless-controller_wtp-group": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller_qos-profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller_wag-profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller_utm-profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller_snmp": {
        "mkey": "None",
        "mkey_type": None,
    },
    "wireless-controller_mpsk-profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller_nac-profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller_ssid-policy": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller_access-control-list": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wireless-controller_ap-status": {
        "mkey": "id",
        "mkey_type": int,
    },
    "switch-controller_traffic-policy": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller_fortilink-settings": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller_switch-interface-tag": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller_802-1X-settings": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch-controller.security-policy_802-1X": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller.security-policy_local-access": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller_location": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller_lldp-settings": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch-controller_lldp-profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller.qos_dot1p-map": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller.qos_ip-dscp-map": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller.qos_queue-policy": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller.qos_qos-policy": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller_storm-control-policy": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller.auto-config_policy": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller.auto-config_default": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch-controller.auto-config_custom": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller.initial-config_template": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller.initial-config_vlans": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch-controller_switch-profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller_custom-command": {
        "mkey": "command_name",
        "mkey_type": str,
    },
    "switch-controller_virtual-port-pool": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller.ptp_profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller.ptp_interface-policy": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller_vlan-policy": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller.acl_ingress": {
        "mkey": "id",
        "mkey_type": int,
    },
    "switch-controller.acl_group": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller_dynamic-port-policy": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller_managed-switch": {
        "mkey": "switch_id",
        "mkey_type": str,
    },
    "switch-controller_switch-group": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller_stp-settings": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch-controller_stp-instance": {
        "mkey": "id",
        "mkey_type": str,
    },
    "switch-controller_storm-control": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch-controller_global": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch-controller_system": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch-controller_switch-log": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch-controller_igmp-snooping": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch-controller_sflow": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch-controller_quarantine": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch-controller_network-monitor-settings": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch-controller_flow-tracking": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch-controller_snmp-sysinfo": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch-controller_snmp-trap-threshold": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch-controller_snmp-community": {
        "mkey": "id",
        "mkey_type": int,
    },
    "switch-controller_snmp-user": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller_traffic-sniffer": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch-controller_remote-log": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller_mac-policy": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_address": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_multicast-address": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_address6-template": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_address6": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_multicast-address6": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_addrgrp": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_addrgrp6": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall.wildcard-fqdn_custom": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall.wildcard-fqdn_group": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_traffic-class": {
        "mkey": "class_id",
        "mkey_type": int,
    },
    "firewall.service_category": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall.service_custom": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall.service_group": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_internet-service-name": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_internet-service-group": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_internet-service-extension": {
        "mkey": "id",
        "mkey_type": int,
    },
    "firewall_internet-service-custom": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_internet-service-addition": {
        "mkey": "id",
        "mkey_type": int,
    },
    "firewall_internet-service-append": {
        "mkey": "None",
        "mkey_type": None,
    },
    "firewall_internet-service-custom-group": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_internet-service-definition": {
        "mkey": "id",
        "mkey_type": int,
    },
    "firewall_network-service-dynamic": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall.shaper_traffic-shaper": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall.shaper_per-ip-shaper": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_proxy-address": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_proxy-addrgrp": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall.schedule_onetime": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall.schedule_recurring": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall.schedule_group": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_ippool": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_ippool6": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_ldb-monitor": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_vip": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_vip6": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_vipgrp": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_vipgrp6": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall.ssh_local-key": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall.ssh_local-ca": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall.ssh_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "firewall.ssh_host-key": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_decrypted-traffic-mirror": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_access-proxy-virtual-host": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_access-proxy-ssh-client-cert": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_access-proxy": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_access-proxy6": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall.ipmacbinding_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "firewall.ipmacbinding_table": {
        "mkey": "seq_num",
        "mkey_type": int,
    },
    "firewall_profile-protocol-options": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_ssl-ssh-profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_ssl-server": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_profile-group": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_identity-based-route": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_auth-portal": {
        "mkey": "None",
        "mkey_type": None,
    },
    "firewall_security-policy": {
        "mkey": "policyid",
        "mkey_type": int,
    },
    "firewall_policy": {
        "mkey": "policyid",
        "mkey_type": int,
    },
    "firewall_shaping-policy": {
        "mkey": "id",
        "mkey_type": int,
    },
    "firewall_shaping-profile": {
        "mkey": "profile_name",
        "mkey_type": str,
    },
    "firewall_local-in-policy": {
        "mkey": "policyid",
        "mkey_type": int,
    },
    "firewall_local-in-policy6": {
        "mkey": "policyid",
        "mkey_type": int,
    },
    "firewall_ttl-policy": {
        "mkey": "id",
        "mkey_type": int,
    },
    "firewall_proxy-policy": {
        "mkey": "policyid",
        "mkey_type": int,
    },
    "firewall_dnstranslation": {
        "mkey": "id",
        "mkey_type": int,
    },
    "firewall_multicast-policy": {
        "mkey": "id",
        "mkey_type": int,
    },
    "firewall_multicast-policy6": {
        "mkey": "id",
        "mkey_type": int,
    },
    "firewall_interface-policy": {
        "mkey": "policyid",
        "mkey_type": int,
    },
    "firewall_interface-policy6": {
        "mkey": "policyid",
        "mkey_type": int,
    },
    "firewall_DoS-policy": {
        "mkey": "policyid",
        "mkey_type": int,
    },
    "firewall_DoS-policy6": {
        "mkey": "policyid",
        "mkey_type": int,
    },
    "firewall_sniffer": {
        "mkey": "id",
        "mkey_type": int,
    },
    "firewall_on-demand-sniffer": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_central-snat-map": {
        "mkey": "policyid",
        "mkey_type": int,
    },
    "firewall.ssl_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "firewall_ip-translation": {
        "mkey": "transid",
        "mkey_type": int,
    },
    "firewall_ipv6-eh-filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "firewall_global": {
        "mkey": "None",
        "mkey_type": None,
    },
    "vpn.certificate_ca": {
        "mkey": "name",
        "mkey_type": str,
    },
    "vpn.certificate_remote": {
        "mkey": "name",
        "mkey_type": str,
    },
    "vpn.certificate_local": {
        "mkey": "name",
        "mkey_type": str,
    },
    "vpn.certificate_crl": {
        "mkey": "name",
        "mkey_type": str,
    },
    "vpn.certificate_ocsp-server": {
        "mkey": "name",
        "mkey_type": str,
    },
    "vpn.certificate_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "vpn_qkd": {
        "mkey": "name",
        "mkey_type": str,
    },
    "vpn.ssl.web_realm": {
        "mkey": "url_path",
        "mkey_type": str,
    },
    "vpn.ssl.web_host-check-software": {
        "mkey": "name",
        "mkey_type": str,
    },
    "vpn.ssl.web_portal": {
        "mkey": "name",
        "mkey_type": str,
    },
    "vpn.ssl.web_user-group-bookmark": {
        "mkey": "name",
        "mkey_type": str,
    },
    "vpn.ssl.web_user-bookmark": {
        "mkey": "name",
        "mkey_type": str,
    },
    "vpn.ssl_settings": {
        "mkey": "None",
        "mkey_type": None,
    },
    "vpn.ssl_client": {
        "mkey": "name",
        "mkey_type": str,
    },
    "vpn.ipsec_fec": {
        "mkey": "name",
        "mkey_type": str,
    },
    "vpn.ipsec_phase1": {
        "mkey": "name",
        "mkey_type": str,
    },
    "vpn.ipsec_phase2": {
        "mkey": "name",
        "mkey_type": str,
    },
    "vpn.ipsec_manualkey": {
        "mkey": "name",
        "mkey_type": str,
    },
    "vpn.ipsec_concentrator": {
        "mkey": "id",
        "mkey_type": int,
    },
    "vpn.ipsec_phase1-interface": {
        "mkey": "name",
        "mkey_type": str,
    },
    "vpn.ipsec_phase2-interface": {
        "mkey": "name",
        "mkey_type": str,
    },
    "vpn.ipsec_manualkey-interface": {
        "mkey": "name",
        "mkey_type": str,
    },
    "vpn.ipsec_forticlient": {
        "mkey": "realm",
        "mkey_type": str,
    },
    "vpn_kmip-server": {
        "mkey": "name",
        "mkey_type": str,
    },
    "vpn_pptp": {
        "mkey": "None",
        "mkey_type": None,
    },
    "vpn_l2tp": {
        "mkey": "None",
        "mkey_type": None,
    },
    "certificate_ca": {
        "mkey": "name",
        "mkey_type": str,
    },
    "certificate_remote": {
        "mkey": "name",
        "mkey_type": str,
    },
    "certificate_local": {
        "mkey": "name",
        "mkey_type": str,
    },
    "certificate_crl": {
        "mkey": "name",
        "mkey_type": str,
    },
    "webfilter_ftgd-local-cat": {
        "mkey": "desc",
        "mkey_type": str,
    },
    "webfilter_content": {
        "mkey": "id",
        "mkey_type": int,
    },
    "webfilter_content-header": {
        "mkey": "id",
        "mkey_type": int,
    },
    "webfilter_urlfilter": {
        "mkey": "id",
        "mkey_type": int,
    },
    "webfilter_ips-urlfilter-setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "webfilter_ips-urlfilter-setting6": {
        "mkey": "None",
        "mkey_type": None,
    },
    "webfilter_ips-urlfilter-cache-setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "webfilter_profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "webfilter_fortiguard": {
        "mkey": "None",
        "mkey_type": None,
    },
    "webfilter_override": {
        "mkey": "id",
        "mkey_type": int,
    },
    "webfilter_ftgd-local-rating": {
        "mkey": "url",
        "mkey_type": str,
    },
    "webfilter_search-engine": {
        "mkey": "name",
        "mkey_type": str,
    },
    "ips_sensor": {
        "mkey": "name",
        "mkey_type": str,
    },
    "ips_custom": {
        "mkey": "tag",
        "mkey_type": str,
    },
    "ips_global": {
        "mkey": "None",
        "mkey_type": None,
    },
    "ips_settings": {
        "mkey": "None",
        "mkey_type": None,
    },
    "sctp-filter_profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "diameter-filter_profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "web-proxy_profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "web-proxy_global": {
        "mkey": "None",
        "mkey_type": None,
    },
    "web-proxy_explicit": {
        "mkey": "None",
        "mkey_type": None,
    },
    "web-proxy_forward-server": {
        "mkey": "name",
        "mkey_type": str,
    },
    "web-proxy_forward-server-group": {
        "mkey": "name",
        "mkey_type": str,
    },
    "web-proxy_debug-url": {
        "mkey": "name",
        "mkey_type": str,
    },
    "web-proxy_wisp": {
        "mkey": "name",
        "mkey_type": str,
    },
    "web-proxy_fast-fallback": {
        "mkey": "name",
        "mkey_type": str,
    },
    "web-proxy_url-match": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wanopt_webcache": {
        "mkey": "None",
        "mkey_type": None,
    },
    "wanopt_settings": {
        "mkey": "None",
        "mkey_type": None,
    },
    "wanopt_peer": {
        "mkey": "peer_host_id",
        "mkey_type": str,
    },
    "wanopt_auth-group": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wanopt_profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wanopt_content-delivery-network-rule": {
        "mkey": "name",
        "mkey_type": str,
    },
    "wanopt_cache-service": {
        "mkey": "None",
        "mkey_type": None,
    },
    "wanopt_remote-storage": {
        "mkey": "None",
        "mkey_type": None,
    },
    "ftp-proxy_explicit": {
        "mkey": "None",
        "mkey_type": None,
    },
    "application_custom": {
        "mkey": "tag",
        "mkey_type": str,
    },
    "application_list": {
        "mkey": "name",
        "mkey_type": str,
    },
    "application_group": {
        "mkey": "name",
        "mkey_type": str,
    },
    "dlp_data-type": {
        "mkey": "name",
        "mkey_type": str,
    },
    "dlp_dictionary": {
        "mkey": "name",
        "mkey_type": str,
    },
    "dlp_exact-data-match": {
        "mkey": "name",
        "mkey_type": str,
    },
    "dlp_sensor": {
        "mkey": "name",
        "mkey_type": str,
    },
    "dlp_filepattern": {
        "mkey": "id",
        "mkey_type": int,
    },
    "dlp_sensitivity": {
        "mkey": "name",
        "mkey_type": str,
    },
    "dlp_fp-doc-source": {
        "mkey": "name",
        "mkey_type": str,
    },
    "dlp_profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "dlp_settings": {
        "mkey": "None",
        "mkey_type": None,
    },
    "videofilter_youtube-key": {
        "mkey": "id",
        "mkey_type": int,
    },
    "videofilter_keyword": {
        "mkey": "id",
        "mkey_type": int,
    },
    "videofilter_profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "emailfilter_bword": {
        "mkey": "id",
        "mkey_type": int,
    },
    "emailfilter_block-allow-list": {
        "mkey": "id",
        "mkey_type": int,
    },
    "emailfilter_mheader": {
        "mkey": "id",
        "mkey_type": int,
    },
    "emailfilter_dnsbl": {
        "mkey": "id",
        "mkey_type": int,
    },
    "emailfilter_iptrust": {
        "mkey": "id",
        "mkey_type": int,
    },
    "emailfilter_profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "emailfilter_fortishield": {
        "mkey": "None",
        "mkey_type": None,
    },
    "emailfilter_options": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log_threat-weight": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log_custom-field": {
        "mkey": "id",
        "mkey_type": str,
    },
    "log.syslogd_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.syslogd_override-setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.syslogd_filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.syslogd_override-filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.syslogd2_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.syslogd2_override-setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.syslogd2_filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.syslogd2_override-filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.syslogd3_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.syslogd3_override-setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.syslogd3_filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.syslogd3_override-filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.syslogd4_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.syslogd4_override-setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.syslogd4_filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.syslogd4_override-filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.webtrends_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.webtrends_filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.memory_global-setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.memory_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.memory_filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.disk_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.disk_filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log_eventfilter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortiguard_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortiguard_override-setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortiguard_filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortiguard_override-filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.tacacs+accounting_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.tacacs+accounting_filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.tacacs+accounting2_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.tacacs+accounting2_filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.tacacs+accounting3_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.tacacs+accounting3_filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.null-device_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.null-device_filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log_gui-display": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortianalyzer_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortianalyzer_override-setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortianalyzer_filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortianalyzer_override-filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortianalyzer2_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortianalyzer2_override-setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortianalyzer2_filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortianalyzer2_override-filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortianalyzer3_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortianalyzer3_override-setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortianalyzer3_filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortianalyzer3_override-filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortianalyzer-cloud_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortianalyzer-cloud_override-setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortianalyzer-cloud_filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "log.fortianalyzer-cloud_override-filter": {
        "mkey": "None",
        "mkey_type": None,
    },
    "icap_server": {
        "mkey": "name",
        "mkey_type": str,
    },
    "icap_server-group": {
        "mkey": "name",
        "mkey_type": str,
    },
    "icap_profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "user_peer": {
        "mkey": "name",
        "mkey_type": str,
    },
    "user_peergrp": {
        "mkey": "name",
        "mkey_type": str,
    },
    "user_certificate": {
        "mkey": "name",
        "mkey_type": str,
    },
    "user_radius": {
        "mkey": "name",
        "mkey_type": str,
    },
    "user_tacacs+": {
        "mkey": "name",
        "mkey_type": str,
    },
    "user_exchange": {
        "mkey": "name",
        "mkey_type": str,
    },
    "user_ldap": {
        "mkey": "name",
        "mkey_type": str,
    },
    "user_krb-keytab": {
        "mkey": "name",
        "mkey_type": str,
    },
    "user_domain-controller": {
        "mkey": "name",
        "mkey_type": str,
    },
    "user_pop3": {
        "mkey": "name",
        "mkey_type": str,
    },
    "user_saml": {
        "mkey": "name",
        "mkey_type": str,
    },
    "user_external-identity-provider": {
        "mkey": "name",
        "mkey_type": str,
    },
    "user_fsso": {
        "mkey": "name",
        "mkey_type": str,
    },
    "user_adgrp": {
        "mkey": "name",
        "mkey_type": str,
    },
    "user_fsso-polling": {
        "mkey": "id",
        "mkey_type": int,
    },
    "user_fortitoken": {
        "mkey": "serial_number",
        "mkey_type": str,
    },
    "user_password-policy": {
        "mkey": "name",
        "mkey_type": str,
    },
    "user_local": {
        "mkey": "name",
        "mkey_type": str,
    },
    "user_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "user_quarantine": {
        "mkey": "None",
        "mkey_type": None,
    },
    "user_group": {
        "mkey": "name",
        "mkey_type": str,
    },
    "user_security-exempt-list": {
        "mkey": "name",
        "mkey_type": str,
    },
    "user_nac-policy": {
        "mkey": "name",
        "mkey_type": str,
    },
    "voip_profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "dnsfilter_domain-filter": {
        "mkey": "id",
        "mkey_type": int,
    },
    "dnsfilter_profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "nsxt_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "nsxt_service-chain": {
        "mkey": "id",
        "mkey_type": int,
    },
    "antivirus_settings": {
        "mkey": "None",
        "mkey_type": None,
    },
    "antivirus_quarantine": {
        "mkey": "None",
        "mkey_type": None,
    },
    "antivirus_exempt-list": {
        "mkey": "name",
        "mkey_type": str,
    },
    "antivirus_profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "ssh-filter_profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "file-filter_profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "virtual-patch_profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "report_layout": {
        "mkey": "name",
        "mkey_type": str,
    },
    "report_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "waf_main-class": {
        "mkey": "id",
        "mkey_type": int,
    },
    "waf_sub-class": {
        "mkey": "id",
        "mkey_type": int,
    },
    "waf_signature": {
        "mkey": "id",
        "mkey_type": int,
    },
    "waf_profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "casb_saas-application": {
        "mkey": "name",
        "mkey_type": str,
    },
    "casb_user-activity": {
        "mkey": "name",
        "mkey_type": str,
    },
    "casb_profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "authentication_scheme": {
        "mkey": "name",
        "mkey_type": str,
    },
    "authentication_rule": {
        "mkey": "name",
        "mkey_type": str,
    },
    "authentication_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "extension-controller_dataplan": {
        "mkey": "name",
        "mkey_type": str,
    },
    "extension-controller_extender-vap": {
        "mkey": "name",
        "mkey_type": str,
    },
    "extension-controller_extender-profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "extension-controller_extender": {
        "mkey": "name",
        "mkey_type": str,
    },
    "extension-controller_fortigate-profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "extension-controller_fortigate": {
        "mkey": "name",
        "mkey_type": str,
    },
    "endpoint-control_fctems": {
        "mkey": "ems_id",
        "mkey_type": int,
    },
    "endpoint-control_settings": {
        "mkey": "None",
        "mkey_type": None,
    },
    "endpoint-control_fctems-override": {
        "mkey": "ems_id",
        "mkey_type": int,
    },
    "alertemail_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "router_access-list": {
        "mkey": "name",
        "mkey_type": str,
    },
    "router_access-list6": {
        "mkey": "name",
        "mkey_type": str,
    },
    "router_aspath-list": {
        "mkey": "name",
        "mkey_type": str,
    },
    "router_prefix-list": {
        "mkey": "name",
        "mkey_type": str,
    },
    "router_prefix-list6": {
        "mkey": "name",
        "mkey_type": str,
    },
    "router_key-chain": {
        "mkey": "name",
        "mkey_type": str,
    },
    "router_community-list": {
        "mkey": "name",
        "mkey_type": str,
    },
    "router_extcommunity-list": {
        "mkey": "name",
        "mkey_type": str,
    },
    "router_route-map": {
        "mkey": "name",
        "mkey_type": str,
    },
    "router_rip": {
        "mkey": "None",
        "mkey_type": None,
    },
    "router_ripng": {
        "mkey": "None",
        "mkey_type": None,
    },
    "router_static": {
        "mkey": "seq_num",
        "mkey_type": int,
    },
    "router_policy": {
        "mkey": "seq_num",
        "mkey_type": int,
    },
    "router_policy6": {
        "mkey": "seq_num",
        "mkey_type": int,
    },
    "router_static6": {
        "mkey": "seq_num",
        "mkey_type": int,
    },
    "router_ospf": {
        "mkey": "None",
        "mkey_type": None,
    },
    "router_ospf6": {
        "mkey": "None",
        "mkey_type": None,
    },
    "router_bgp": {
        "mkey": "None",
        "mkey_type": None,
    },
    "router_isis": {
        "mkey": "None",
        "mkey_type": None,
    },
    "router_multicast-flow": {
        "mkey": "name",
        "mkey_type": str,
    },
    "router_multicast": {
        "mkey": "None",
        "mkey_type": None,
    },
    "router_multicast6": {
        "mkey": "None",
        "mkey_type": None,
    },
    "router_auth-path": {
        "mkey": "name",
        "mkey_type": str,
    },
    "router_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "router_bfd": {
        "mkey": "None",
        "mkey_type": None,
    },
    "router_bfd6": {
        "mkey": "None",
        "mkey_type": None,
    },
    "automation_setting": {
        "mkey": "None",
        "mkey_type": None,
    },
    "dpdk_global": {
        "mkey": "None",
        "mkey_type": None,
    },
    "dpdk_cpus": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_isf-queue-profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_npu": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_np6": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_gi-gk": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_modem": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.3g-modem_custom": {
        "mkey": "id",
        "mkey_type": int,
    },
    "system_lte-modem": {
        "mkey": "None",
        "mkey_type": None,
    },
    "firewall_gtp": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_pfcp": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_acl": {
        "mkey": "policyid",
        "mkey_type": int,
    },
    "firewall_acl6": {
        "mkey": "policyid",
        "mkey_type": int,
    },
    "gtp_apn": {
        "mkey": "name",
        "mkey_type": str,
    },
    "gtp_apngrp": {
        "mkey": "name",
        "mkey_type": str,
    },
    "gtp_message-filter-v0v1": {
        "mkey": "name",
        "mkey_type": str,
    },
    "gtp_message-filter-v2": {
        "mkey": "name",
        "mkey_type": str,
    },
    "gtp_rat-timeout-profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "gtp_ie-allow-list": {
        "mkey": "name",
        "mkey_type": str,
    },
    "gtp_tunnel-limit": {
        "mkey": "name",
        "mkey_type": str,
    },
    "gtp_apn-shaper": {
        "mkey": "id",
        "mkey_type": int,
    },
    "pfcp_message-filter": {
        "mkey": "name",
        "mkey_type": str,
    },
    "monitoring_np6-ipsec-engine": {
        "mkey": "None",
        "mkey_type": None,
    },
    "monitoring_npu-hpe": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_npu-vlink": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_physical-switch": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_virtual-switch": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system_stp": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_smc-ntp": {
        "mkey": "None",
        "mkey_type": None,
    },
    "videofilter_youtube-channel-filter": {
        "mkey": "id",
        "mkey_type": int,
    },
    "switch-controller.ptp_settings": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch-controller.ptp_policy": {
        "mkey": "name",
        "mkey_type": str,
    },
    "vpn_ocvpn": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.replacemsg_mail": {
        "mkey": "msg_type",
        "mkey_type": str,
    },
    "system.replacemsg_http": {
        "mkey": "msg_type",
        "mkey_type": str,
    },
    "system.replacemsg_webproxy": {
        "mkey": "msg_type",
        "mkey_type": str,
    },
    "system.replacemsg_ftp": {
        "mkey": "msg_type",
        "mkey_type": str,
    },
    "system.replacemsg_fortiguard-wf": {
        "mkey": "msg_type",
        "mkey_type": str,
    },
    "system.replacemsg_spam": {
        "mkey": "msg_type",
        "mkey_type": str,
    },
    "system.replacemsg_alertmail": {
        "mkey": "msg_type",
        "mkey_type": str,
    },
    "system.replacemsg_admin": {
        "mkey": "msg_type",
        "mkey_type": str,
    },
    "system.replacemsg_auth": {
        "mkey": "msg_type",
        "mkey_type": str,
    },
    "system.replacemsg_sslvpn": {
        "mkey": "msg_type",
        "mkey_type": str,
    },
    "system.replacemsg_nac-quar": {
        "mkey": "msg_type",
        "mkey_type": str,
    },
    "system.replacemsg_traffic-quota": {
        "mkey": "msg_type",
        "mkey_type": str,
    },
    "system.replacemsg_utm": {
        "mkey": "msg_type",
        "mkey_type": str,
    },
    "system.replacemsg_icap": {
        "mkey": "msg_type",
        "mkey_type": str,
    },
    "system.replacemsg_automation": {
        "mkey": "msg_type",
        "mkey_type": str,
    },
    "system_status": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.performance_status": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.performance_top": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.performance.firewall_packet-distribution": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.performance.firewall_statistics": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_session": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_session6": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_cmdb": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_fortiguard-service": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_fortianalyzer-connectivity": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.checksum_status": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_mgmt-csum": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_ha-nonsync-csum": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_fortiguard-log-service": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_central-mgmt": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.info.admin_status": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.info.admin_ssh": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_geoip-country": {
        "mkey": "id",
        "mkey_type": str,
    },
    "system_cluster-sync": {
        "mkey": "sync_id",
        "mkey_type": int,
    },
    "system_arp": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_startup-error-log": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.source-ip_status": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.auto-update_status": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.auto-update_versions": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.session-info_list": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.session-info_expectation": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.session-info_full-stat": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.session-info_statistics": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.session-info_ttl": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.session-helper-info_list": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system.ip-conflict_status": {
        "mkey": "None",
        "mkey_type": None,
    },
    "wireless-controller_scan": {
        "mkey": "None",
        "mkey_type": None,
    },
    "wireless-controller_wlchanlistlic": {
        "mkey": "None",
        "mkey_type": None,
    },
    "wireless-controller_status": {
        "mkey": "None",
        "mkey_type": None,
    },
    "wireless-controller_wtp-status": {
        "mkey": "None",
        "mkey_type": None,
    },
    "wireless-controller_client-info": {
        "mkey": "None",
        "mkey_type": None,
    },
    "wireless-controller_vap-status": {
        "mkey": "None",
        "mkey_type": None,
    },
    "wireless-controller_rf-analysis": {
        "mkey": "None",
        "mkey_type": None,
    },
    "wireless-controller_spectral-info": {
        "mkey": "None",
        "mkey_type": None,
    },
    "ipsec_tunnel": {
        "mkey": "None",
        "mkey_type": None,
    },
    "firewall_city": {
        "mkey": "id",
        "mkey_type": int,
    },
    "firewall_region": {
        "mkey": "id",
        "mkey_type": int,
    },
    "firewall_country": {
        "mkey": "id",
        "mkey_type": int,
    },
    "firewall_internet-service": {
        "mkey": "id",
        "mkey_type": int,
    },
    "firewall_internet-service-reputation": {
        "mkey": "id",
        "mkey_type": int,
    },
    "firewall_internet-service-sld": {
        "mkey": "id",
        "mkey_type": int,
    },
    "firewall_internet-service-ipbl-vendor": {
        "mkey": "id",
        "mkey_type": int,
    },
    "firewall_internet-service-ipbl-reason": {
        "mkey": "id",
        "mkey_type": int,
    },
    "firewall_internet-service-owner": {
        "mkey": "id",
        "mkey_type": int,
    },
    "firewall_internet-service-list": {
        "mkey": "id",
        "mkey_type": int,
    },
    "firewall_internet-service-botnet": {
        "mkey": "id",
        "mkey_type": int,
    },
    "firewall_vendor-mac": {
        "mkey": "id",
        "mkey_type": int,
    },
    "firewall_vendor-mac-summary": {
        "mkey": "None",
        "mkey_type": None,
    },
    "firewall.shaper_traffic": {
        "mkey": "None",
        "mkey_type": None,
    },
    "firewall.shaper_per-ip": {
        "mkey": "None",
        "mkey_type": None,
    },
    "firewall.iprope_list": {
        "mkey": "None",
        "mkey_type": None,
    },
    "firewall.iprope.appctrl_list": {
        "mkey": "None",
        "mkey_type": None,
    },
    "firewall.iprope.appctrl_status": {
        "mkey": "None",
        "mkey_type": None,
    },
    "firewall_proute": {
        "mkey": "None",
        "mkey_type": None,
    },
    "firewall_proute6": {
        "mkey": "None",
        "mkey_type": None,
    },
    "vpn.ssl_monitor": {
        "mkey": "None",
        "mkey_type": None,
    },
    "vpn.ipsec.stats_crypto": {
        "mkey": "None",
        "mkey_type": None,
    },
    "vpn.ipsec.stats_tunnel": {
        "mkey": "None",
        "mkey_type": None,
    },
    "vpn.ipsec.tunnel_details": {
        "mkey": "None",
        "mkey_type": None,
    },
    "vpn.ipsec.tunnel_summary": {
        "mkey": "None",
        "mkey_type": None,
    },
    "vpn.ipsec.tunnel_name": {
        "mkey": "None",
        "mkey_type": None,
    },
    "vpn.ike_gateway": {
        "mkey": "None",
        "mkey_type": None,
    },
    "vpn.status_l2tp": {
        "mkey": "None",
        "mkey_type": None,
    },
    "vpn.status_pptp": {
        "mkey": "None",
        "mkey_type": None,
    },
    "vpn.status.ssl_list": {
        "mkey": "None",
        "mkey_type": None,
    },
    "vpn.status.ssl_hw-acceleration-status": {
        "mkey": "None",
        "mkey_type": None,
    },
    "webfilter_categories": {
        "mkey": "None",
        "mkey_type": None,
    },
    "webfilter_ftgd-statistics": {
        "mkey": "None",
        "mkey_type": None,
    },
    "webfilter_status": {
        "mkey": "None",
        "mkey_type": None,
    },
    "webfilter_override-usr": {
        "mkey": "None",
        "mkey_type": None,
    },
    "ips_view-map": {
        "mkey": "id",
        "mkey_type": int,
    },
    "ips_decoder": {
        "mkey": "name",
        "mkey_type": str,
    },
    "ips_rule": {
        "mkey": "name",
        "mkey_type": str,
    },
    "ips_rule-settings": {
        "mkey": "id",
        "mkey_type": int,
    },
    "ips_session": {
        "mkey": "None",
        "mkey_type": None,
    },
    "application_name": {
        "mkey": "name",
        "mkey_type": str,
    },
    "application_rule-settings": {
        "mkey": "id",
        "mkey_type": int,
    },
    "report.sql_status": {
        "mkey": "None",
        "mkey_type": None,
    },
    "extender-controller_dataplan": {
        "mkey": "name",
        "mkey_type": str,
    },
    "extender-controller_extender-profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "extender-controller_extender": {
        "mkey": "name",
        "mkey_type": str,
    },
    "router_info": {
        "mkey": "None",
        "mkey_type": None,
    },
    "router_info6": {
        "mkey": "None",
        "mkey_type": None,
    },
    "hardware_status": {
        "mkey": "None",
        "mkey_type": None,
    },
    "hardware_cpu": {
        "mkey": "None",
        "mkey_type": None,
    },
    "hardware_memory": {
        "mkey": "None",
        "mkey_type": None,
    },
    "hardware_nic": {
        "mkey": "None",
        "mkey_type": None,
    },
    "hardware.npu.np6_port-list": {
        "mkey": "None",
        "mkey_type": None,
    },
    "hardware.npu.np6_dce": {
        "mkey": "None",
        "mkey_type": None,
    },
    "hardware.npu.np6_session-stats": {
        "mkey": "None",
        "mkey_type": None,
    },
    "hardware.npu.np6_sse-stats": {
        "mkey": "None",
        "mkey_type": None,
    },
    "hardware.npu.np6_ipsec-stats": {
        "mkey": "None",
        "mkey_type": None,
    },
    "hardware.npu.np6_synproxy-stats": {
        "mkey": "None",
        "mkey_type": None,
    },
    "mgmt-data_status": {
        "mkey": "None",
        "mkey_type": None,
    },
    "extender_sys-info": {
        "mkey": "None",
        "mkey_type": None,
    },
    "extender_extender-info": {
        "mkey": "None",
        "mkey_type": None,
    },
    "extender_session-info": {
        "mkey": "None",
        "mkey_type": None,
    },
    "extender_datachannel-info": {
        "mkey": "None",
        "mkey_type": None,
    },
    "extender_fexwan": {
        "mkey": "None",
        "mkey_type": None,
    },
    "extender_modem-status": {
        "mkey": "None",
        "mkey_type": None,
    },
    "extender_lte-carrier-list": {
        "mkey": "None",
        "mkey_type": None,
    },
    "extender_lte-carrier-by-mcc-mnc": {
        "mkey": "None",
        "mkey_type": None,
    },
    "wireless-controller_address": {
        "mkey": "id",
        "mkey_type": str,
    },
    "wireless-controller_addrgrp": {
        "mkey": "id",
        "mkey_type": str,
    },
    "system_fortiai": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_fortimanager": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_fm": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_nat64": {
        "mkey": "None",
        "mkey_type": None,
    },
    "firewall_vip46": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_vip64": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_vipgrp46": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_vipgrp64": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall_policy64": {
        "mkey": "policyid",
        "mkey_type": int,
    },
    "firewall_policy46": {
        "mkey": "policyid",
        "mkey_type": int,
    },
    "system.autoupdate_push-update": {
        "mkey": "None",
        "mkey_type": None,
    },
    "switch-controller_nac-settings": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller_port-policy": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller_nac-device": {
        "mkey": "id",
        "mkey_type": int,
    },
    "emailfilter_bwl": {
        "mkey": "id",
        "mkey_type": int,
    },
    "antivirus_heuristic": {
        "mkey": "None",
        "mkey_type": None,
    },
    "credential-store_domain-controller": {
        "mkey": "server_name",
        "mkey_type": str,
    },
    "report_dataset": {
        "mkey": "name",
        "mkey_type": str,
    },
    "report_chart": {
        "mkey": "name",
        "mkey_type": str,
    },
    "report_style": {
        "mkey": "name",
        "mkey_type": str,
    },
    "report_theme": {
        "mkey": "name",
        "mkey_type": str,
    },
    "gtp_ie-white-list": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system.replacemsg_nntp": {
        "mkey": "msg_type",
        "mkey_type": str,
    },
    "system.replacemsg_device-detection-portal": {
        "mkey": "msg_type",
        "mkey_type": str,
    },
    "switch-controller_poe": {
        "mkey": "None",
        "mkey_type": None,
    },
    "cifs_domain-controller": {
        "mkey": "server_name",
        "mkey_type": str,
    },
    "cifs_profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "system.replacemsg_mms": {
        "mkey": "msg_type",
        "mkey_type": str,
    },
    "system.replacemsg_mm1": {
        "mkey": "msg_type",
        "mkey_type": str,
    },
    "system.replacemsg_mm3": {
        "mkey": "msg_type",
        "mkey_type": str,
    },
    "system.replacemsg_mm4": {
        "mkey": "msg_type",
        "mkey_type": str,
    },
    "system.replacemsg_mm7": {
        "mkey": "msg_type",
        "mkey_type": str,
    },
    "system_virtual-wan-link": {
        "mkey": "None",
        "mkey_type": None,
    },
    "system_mem-mgr": {
        "mkey": "None",
        "mkey_type": None,
    },
    "firewall_carrier-endpoint-bwl": {
        "mkey": "id",
        "mkey_type": int,
    },
    "firewall_mms-profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "firewall.consolidated_policy": {
        "mkey": "policyid",
        "mkey_type": int,
    },
    "firewall_policy6": {
        "mkey": "policyid",
        "mkey_type": int,
    },
    "antivirus_notification": {
        "mkey": "id",
        "mkey_type": int,
    },
    "antivirus_mms-checksum": {
        "mkey": "id",
        "mkey_type": int,
    },
    "switch-controller_vlan": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller.security-policy_captive-portal": {
        "mkey": "name",
        "mkey_type": str,
    },
    "user_device": {
        "mkey": "alias",
        "mkey_type": str,
    },
    "user_device-group": {
        "mkey": "name",
        "mkey_type": str,
    },
    "endpoint-control_client": {
        "mkey": "id",
        "mkey_type": int,
    },
    "system.replacemsg_ec": {
        "mkey": "msg_type",
        "mkey_type": str,
    },
    "dlp_fp-sensitivity": {
        "mkey": "name",
        "mkey_type": str,
    },
    "spamfilter_bword": {
        "mkey": "id",
        "mkey_type": int,
    },
    "spamfilter_bwl": {
        "mkey": "id",
        "mkey_type": int,
    },
    "spamfilter_mheader": {
        "mkey": "id",
        "mkey_type": int,
    },
    "spamfilter_dnsbl": {
        "mkey": "id",
        "mkey_type": int,
    },
    "spamfilter_iptrust": {
        "mkey": "id",
        "mkey_type": int,
    },
    "spamfilter_profile": {
        "mkey": "name",
        "mkey_type": str,
    },
    "spamfilter_fortishield": {
        "mkey": "None",
        "mkey_type": None,
    },
    "spamfilter_options": {
        "mkey": "None",
        "mkey_type": None,
    },
    "user_device-category": {
        "mkey": "name",
        "mkey_type": str,
    },
    "user_device-access-list": {
        "mkey": "name",
        "mkey_type": str,
    },
    "switch-controller_mac-sync-settings": {
        "mkey": "None",
        "mkey_type": None,
    },
    "endpoint-control_forticlient-ems": {
        "mkey": "name",
        "mkey_type": str,
    },
    "endpoint-control_profile": {
        "mkey": "profile_name",
        "mkey_type": str,
    },
    "endpoint-control_forticlient-registration-sync": {
        "mkey": "peer_name",
        "mkey_type": str,
    },
    "endpoint-control_registered-forticlient": {
        "mkey": "uid",
        "mkey_type": str,
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
        filter_body = quote(params["filters"][0])
        for filter_item in params["filters"][1:]:
            filter_body = "%s&filter=%s" % (filter_body, quote(filter_item))
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
                "system_vdom",
                "system_global",
                "system_accprofile",
                "system_vdom-link",
                "system_switch-interface",
                "system_object-tagging",
                "system_interface",
                "system_password-policy",
                "system_password-policy-guest-admin",
                "system_sms-server",
                "system_custom-language",
                "system_admin",
                "system_api-user",
                "system_sso-admin",
                "system_sso-forticloud-admin",
                "system_sso-fortigate-cloud-admin",
                "system_settings",
                "system_sit-tunnel",
                "system_fsso-polling",
                "system_ha",
                "system_ha-monitor",
                "system_storage",
                "system_dedicated-mgmt",
                "system_arp-table",
                "system_ipv6-neighbor-cache",
                "system_dns",
                "system_ddns",
                "system_sflow",
                "system_vdom-sflow",
                "system_netflow",
                "system_vdom-netflow",
                "system_vdom-dns",
                "system_replacemsg-image",
                "system_replacemsg-group",
                "system.snmp_sysinfo",
                "system.snmp_mib-view",
                "system.snmp_community",
                "system.snmp_user",
                "system.autoupdate_schedule",
                "system.autoupdate_tunneling",
                "system_session-ttl",
                "system.dhcp_server",
                "system.dhcp6_server",
                "system_alias",
                "system_auto-script",
                "system_management-tunnel",
                "system_central-management",
                "system_zone",
                "system_sdn-proxy",
                "system_sdn-connector",
                "system_ipv6-tunnel",
                "system_external-resource",
                "system_ips-urlfilter-dns",
                "system_ips-urlfilter-dns6",
                "system_network-visibility",
                "system_sdwan",
                "system_evpn",
                "system_gre-tunnel",
                "system_ipsec-aggregate",
                "system_ipip-tunnel",
                "system_mobile-tunnel",
                "system_pppoe-interface",
                "system_vxlan",
                "system_geneve",
                "system_virtual-wire-pair",
                "system_dns-database",
                "system_dns-server",
                "system_resource-limits",
                "system_vdom-property",
                "system_speed-test-server",
                "system.lldp_network-policy",
                "system_pcp-server",
                "system_speed-test-schedule",
                "system_speed-test-setting",
                "system_standalone-cluster",
                "system_fortiguard",
                "system_ips",
                "system_email-server",
                "system_alarm",
                "system_mac-address-table",
                "system_session-helper",
                "system_proxy-arp",
                "system_fips-cc",
                "system_tos-based-priority",
                "system_dscp-based-priority",
                "system_probe-response",
                "system_link-monitor",
                "system_auto-install",
                "system_console",
                "system_ntp",
                "system_ptp",
                "system_wccp",
                "system_dns64",
                "system_vdom-radius-server",
                "system_ftm-push",
                "system_geoip-override",
                "system_fortisandbox",
                "system_fortindr",
                "system_affinity-interrupt",
                "system_affinity-packet-redistribution",
                "system_vdom-exception",
                "system_csf",
                "system_automation-trigger",
                "system_automation-action",
                "system_automation-destination",
                "system_automation-stitch",
                "system_nd-proxy",
                "system_saml",
                "system_federated-upgrade",
                "system_device-upgrade",
                "system_vne-tunnel",
                "system_ike",
                "system_acme",
                "system_ipam",
                "system_fabric-vpn",
                "system_ssh-config",
                "wireless-controller_inter-controller",
                "wireless-controller_global",
                "wireless-controller.hotspot20_anqp-venue-name",
                "wireless-controller.hotspot20_anqp-venue-url",
                "wireless-controller.hotspot20_anqp-network-auth-type",
                "wireless-controller.hotspot20_anqp-roaming-consortium",
                "wireless-controller.hotspot20_anqp-nai-realm",
                "wireless-controller.hotspot20_anqp-3gpp-cellular",
                "wireless-controller.hotspot20_anqp-ip-address-type",
                "wireless-controller.hotspot20_h2qp-operator-name",
                "wireless-controller.hotspot20_h2qp-wan-metric",
                "wireless-controller.hotspot20_h2qp-conn-capability",
                "wireless-controller.hotspot20_icon",
                "wireless-controller.hotspot20_h2qp-osu-provider",
                "wireless-controller.hotspot20_qos-map",
                "wireless-controller.hotspot20_h2qp-advice-of-charge",
                "wireless-controller.hotspot20_h2qp-osu-provider-nai",
                "wireless-controller.hotspot20_h2qp-terms-and-conditions",
                "wireless-controller.hotspot20_hs-profile",
                "wireless-controller_vap",
                "wireless-controller_timers",
                "wireless-controller_setting",
                "wireless-controller_log",
                "wireless-controller_apcfg-profile",
                "wireless-controller_bonjour-profile",
                "wireless-controller_arrp-profile",
                "wireless-controller_region",
                "wireless-controller_vap-group",
                "wireless-controller_wids-profile",
                "wireless-controller_ble-profile",
                "wireless-controller_syslog-profile",
                "wireless-controller_wtp-profile",
                "wireless-controller_wtp",
                "wireless-controller_wtp-group",
                "wireless-controller_qos-profile",
                "wireless-controller_wag-profile",
                "wireless-controller_utm-profile",
                "wireless-controller_snmp",
                "wireless-controller_mpsk-profile",
                "wireless-controller_nac-profile",
                "wireless-controller_ssid-policy",
                "wireless-controller_access-control-list",
                "wireless-controller_ap-status",
                "switch-controller_traffic-policy",
                "switch-controller_fortilink-settings",
                "switch-controller_switch-interface-tag",
                "switch-controller_802-1X-settings",
                "switch-controller.security-policy_802-1X",
                "switch-controller.security-policy_local-access",
                "switch-controller_location",
                "switch-controller_lldp-settings",
                "switch-controller_lldp-profile",
                "switch-controller.qos_dot1p-map",
                "switch-controller.qos_ip-dscp-map",
                "switch-controller.qos_queue-policy",
                "switch-controller.qos_qos-policy",
                "switch-controller_storm-control-policy",
                "switch-controller.auto-config_policy",
                "switch-controller.auto-config_default",
                "switch-controller.auto-config_custom",
                "switch-controller.initial-config_template",
                "switch-controller.initial-config_vlans",
                "switch-controller_switch-profile",
                "switch-controller_custom-command",
                "switch-controller_virtual-port-pool",
                "switch-controller.ptp_profile",
                "switch-controller.ptp_interface-policy",
                "switch-controller_vlan-policy",
                "switch-controller.acl_ingress",
                "switch-controller.acl_group",
                "switch-controller_dynamic-port-policy",
                "switch-controller_managed-switch",
                "switch-controller_switch-group",
                "switch-controller_stp-settings",
                "switch-controller_stp-instance",
                "switch-controller_storm-control",
                "switch-controller_global",
                "switch-controller_system",
                "switch-controller_switch-log",
                "switch-controller_igmp-snooping",
                "switch-controller_sflow",
                "switch-controller_quarantine",
                "switch-controller_network-monitor-settings",
                "switch-controller_flow-tracking",
                "switch-controller_snmp-sysinfo",
                "switch-controller_snmp-trap-threshold",
                "switch-controller_snmp-community",
                "switch-controller_snmp-user",
                "switch-controller_traffic-sniffer",
                "switch-controller_remote-log",
                "switch-controller_mac-policy",
                "firewall_address",
                "firewall_multicast-address",
                "firewall_address6-template",
                "firewall_address6",
                "firewall_multicast-address6",
                "firewall_addrgrp",
                "firewall_addrgrp6",
                "firewall.wildcard-fqdn_custom",
                "firewall.wildcard-fqdn_group",
                "firewall_traffic-class",
                "firewall.service_category",
                "firewall.service_custom",
                "firewall.service_group",
                "firewall_internet-service-name",
                "firewall_internet-service-group",
                "firewall_internet-service-extension",
                "firewall_internet-service-custom",
                "firewall_internet-service-addition",
                "firewall_internet-service-append",
                "firewall_internet-service-custom-group",
                "firewall_internet-service-definition",
                "firewall_network-service-dynamic",
                "firewall.shaper_traffic-shaper",
                "firewall.shaper_per-ip-shaper",
                "firewall_proxy-address",
                "firewall_proxy-addrgrp",
                "firewall.schedule_onetime",
                "firewall.schedule_recurring",
                "firewall.schedule_group",
                "firewall_ippool",
                "firewall_ippool6",
                "firewall_ldb-monitor",
                "firewall_vip",
                "firewall_vip6",
                "firewall_vipgrp",
                "firewall_vipgrp6",
                "firewall.ssh_local-key",
                "firewall.ssh_local-ca",
                "firewall.ssh_setting",
                "firewall.ssh_host-key",
                "firewall_decrypted-traffic-mirror",
                "firewall_access-proxy-virtual-host",
                "firewall_access-proxy-ssh-client-cert",
                "firewall_access-proxy",
                "firewall_access-proxy6",
                "firewall.ipmacbinding_setting",
                "firewall.ipmacbinding_table",
                "firewall_profile-protocol-options",
                "firewall_ssl-ssh-profile",
                "firewall_ssl-server",
                "firewall_profile-group",
                "firewall_identity-based-route",
                "firewall_auth-portal",
                "firewall_security-policy",
                "firewall_policy",
                "firewall_shaping-policy",
                "firewall_shaping-profile",
                "firewall_local-in-policy",
                "firewall_local-in-policy6",
                "firewall_ttl-policy",
                "firewall_proxy-policy",
                "firewall_dnstranslation",
                "firewall_multicast-policy",
                "firewall_multicast-policy6",
                "firewall_interface-policy",
                "firewall_interface-policy6",
                "firewall_DoS-policy",
                "firewall_DoS-policy6",
                "firewall_sniffer",
                "firewall_on-demand-sniffer",
                "firewall_central-snat-map",
                "firewall.ssl_setting",
                "firewall_ip-translation",
                "firewall_ipv6-eh-filter",
                "firewall_global",
                "vpn.certificate_ca",
                "vpn.certificate_remote",
                "vpn.certificate_local",
                "vpn.certificate_crl",
                "vpn.certificate_ocsp-server",
                "vpn.certificate_setting",
                "vpn_qkd",
                "vpn.ssl.web_realm",
                "vpn.ssl.web_host-check-software",
                "vpn.ssl.web_portal",
                "vpn.ssl.web_user-group-bookmark",
                "vpn.ssl.web_user-bookmark",
                "vpn.ssl_settings",
                "vpn.ssl_client",
                "vpn.ipsec_fec",
                "vpn.ipsec_phase1",
                "vpn.ipsec_phase2",
                "vpn.ipsec_manualkey",
                "vpn.ipsec_concentrator",
                "vpn.ipsec_phase1-interface",
                "vpn.ipsec_phase2-interface",
                "vpn.ipsec_manualkey-interface",
                "vpn.ipsec_forticlient",
                "vpn_kmip-server",
                "vpn_pptp",
                "vpn_l2tp",
                "certificate_ca",
                "certificate_remote",
                "certificate_local",
                "certificate_crl",
                "webfilter_ftgd-local-cat",
                "webfilter_content",
                "webfilter_content-header",
                "webfilter_urlfilter",
                "webfilter_ips-urlfilter-setting",
                "webfilter_ips-urlfilter-setting6",
                "webfilter_ips-urlfilter-cache-setting",
                "webfilter_profile",
                "webfilter_fortiguard",
                "webfilter_override",
                "webfilter_ftgd-local-rating",
                "webfilter_search-engine",
                "ips_sensor",
                "ips_custom",
                "ips_global",
                "ips_settings",
                "sctp-filter_profile",
                "diameter-filter_profile",
                "web-proxy_profile",
                "web-proxy_global",
                "web-proxy_explicit",
                "web-proxy_forward-server",
                "web-proxy_forward-server-group",
                "web-proxy_debug-url",
                "web-proxy_wisp",
                "web-proxy_fast-fallback",
                "web-proxy_url-match",
                "wanopt_webcache",
                "wanopt_settings",
                "wanopt_peer",
                "wanopt_auth-group",
                "wanopt_profile",
                "wanopt_content-delivery-network-rule",
                "wanopt_cache-service",
                "wanopt_remote-storage",
                "ftp-proxy_explicit",
                "application_custom",
                "application_list",
                "application_group",
                "dlp_data-type",
                "dlp_dictionary",
                "dlp_exact-data-match",
                "dlp_sensor",
                "dlp_filepattern",
                "dlp_sensitivity",
                "dlp_fp-doc-source",
                "dlp_profile",
                "dlp_settings",
                "videofilter_youtube-key",
                "videofilter_keyword",
                "videofilter_profile",
                "emailfilter_bword",
                "emailfilter_block-allow-list",
                "emailfilter_mheader",
                "emailfilter_dnsbl",
                "emailfilter_iptrust",
                "emailfilter_profile",
                "emailfilter_fortishield",
                "emailfilter_options",
                "log_threat-weight",
                "log_custom-field",
                "log.syslogd_setting",
                "log.syslogd_override-setting",
                "log.syslogd_filter",
                "log.syslogd_override-filter",
                "log.syslogd2_setting",
                "log.syslogd2_override-setting",
                "log.syslogd2_filter",
                "log.syslogd2_override-filter",
                "log.syslogd3_setting",
                "log.syslogd3_override-setting",
                "log.syslogd3_filter",
                "log.syslogd3_override-filter",
                "log.syslogd4_setting",
                "log.syslogd4_override-setting",
                "log.syslogd4_filter",
                "log.syslogd4_override-filter",
                "log.webtrends_setting",
                "log.webtrends_filter",
                "log.memory_global-setting",
                "log.memory_setting",
                "log.memory_filter",
                "log.disk_setting",
                "log.disk_filter",
                "log_eventfilter",
                "log.fortiguard_setting",
                "log.fortiguard_override-setting",
                "log.fortiguard_filter",
                "log.fortiguard_override-filter",
                "log.tacacs+accounting_setting",
                "log.tacacs+accounting_filter",
                "log.tacacs+accounting2_setting",
                "log.tacacs+accounting2_filter",
                "log.tacacs+accounting3_setting",
                "log.tacacs+accounting3_filter",
                "log.null-device_setting",
                "log.null-device_filter",
                "log_setting",
                "log_gui-display",
                "log.fortianalyzer_setting",
                "log.fortianalyzer_override-setting",
                "log.fortianalyzer_filter",
                "log.fortianalyzer_override-filter",
                "log.fortianalyzer2_setting",
                "log.fortianalyzer2_override-setting",
                "log.fortianalyzer2_filter",
                "log.fortianalyzer2_override-filter",
                "log.fortianalyzer3_setting",
                "log.fortianalyzer3_override-setting",
                "log.fortianalyzer3_filter",
                "log.fortianalyzer3_override-filter",
                "log.fortianalyzer-cloud_setting",
                "log.fortianalyzer-cloud_override-setting",
                "log.fortianalyzer-cloud_filter",
                "log.fortianalyzer-cloud_override-filter",
                "icap_server",
                "icap_server-group",
                "icap_profile",
                "user_peer",
                "user_peergrp",
                "user_certificate",
                "user_radius",
                "user_tacacs+",
                "user_exchange",
                "user_ldap",
                "user_krb-keytab",
                "user_domain-controller",
                "user_pop3",
                "user_saml",
                "user_external-identity-provider",
                "user_fsso",
                "user_adgrp",
                "user_fsso-polling",
                "user_fortitoken",
                "user_password-policy",
                "user_local",
                "user_setting",
                "user_quarantine",
                "user_group",
                "user_security-exempt-list",
                "user_nac-policy",
                "voip_profile",
                "dnsfilter_domain-filter",
                "dnsfilter_profile",
                "nsxt_setting",
                "nsxt_service-chain",
                "antivirus_settings",
                "antivirus_quarantine",
                "antivirus_exempt-list",
                "antivirus_profile",
                "ssh-filter_profile",
                "file-filter_profile",
                "virtual-patch_profile",
                "report_layout",
                "report_setting",
                "waf_main-class",
                "waf_sub-class",
                "waf_signature",
                "waf_profile",
                "casb_saas-application",
                "casb_user-activity",
                "casb_profile",
                "authentication_scheme",
                "authentication_rule",
                "authentication_setting",
                "extension-controller_dataplan",
                "extension-controller_extender-vap",
                "extension-controller_extender-profile",
                "extension-controller_extender",
                "extension-controller_fortigate-profile",
                "extension-controller_fortigate",
                "endpoint-control_fctems",
                "endpoint-control_settings",
                "endpoint-control_fctems-override",
                "alertemail_setting",
                "router_access-list",
                "router_access-list6",
                "router_aspath-list",
                "router_prefix-list",
                "router_prefix-list6",
                "router_key-chain",
                "router_community-list",
                "router_extcommunity-list",
                "router_route-map",
                "router_rip",
                "router_ripng",
                "router_static",
                "router_policy",
                "router_policy6",
                "router_static6",
                "router_ospf",
                "router_ospf6",
                "router_bgp",
                "router_isis",
                "router_multicast-flow",
                "router_multicast",
                "router_multicast6",
                "router_auth-path",
                "router_setting",
                "router_bfd",
                "router_bfd6",
                "automation_setting",
                "dpdk_global",
                "dpdk_cpus",
                "system_isf-queue-profile",
                "system_npu",
                "system_np6",
                "system_gi-gk",
                "system_modem",
                "system.3g-modem_custom",
                "system_lte-modem",
                "firewall_gtp",
                "firewall_pfcp",
                "firewall_acl",
                "firewall_acl6",
                "gtp_apn",
                "gtp_apngrp",
                "gtp_message-filter-v0v1",
                "gtp_message-filter-v2",
                "gtp_rat-timeout-profile",
                "gtp_ie-allow-list",
                "gtp_tunnel-limit",
                "gtp_apn-shaper",
                "pfcp_message-filter",
                "monitoring_np6-ipsec-engine",
                "monitoring_npu-hpe",
                "system_npu-vlink",
                "system_physical-switch",
                "system_virtual-switch",
                "system_stp",
                "system_smc-ntp",
                "videofilter_youtube-channel-filter",
                "switch-controller.ptp_settings",
                "switch-controller.ptp_policy",
                "vpn_ocvpn",
                "system.replacemsg_mail",
                "system.replacemsg_http",
                "system.replacemsg_webproxy",
                "system.replacemsg_ftp",
                "system.replacemsg_fortiguard-wf",
                "system.replacemsg_spam",
                "system.replacemsg_alertmail",
                "system.replacemsg_admin",
                "system.replacemsg_auth",
                "system.replacemsg_sslvpn",
                "system.replacemsg_nac-quar",
                "system.replacemsg_traffic-quota",
                "system.replacemsg_utm",
                "system.replacemsg_icap",
                "system.replacemsg_automation",
                "system_status",
                "system.performance_status",
                "system.performance_top",
                "system.performance.firewall_packet-distribution",
                "system.performance.firewall_statistics",
                "system_session",
                "system_session6",
                "system_cmdb",
                "system_fortiguard-service",
                "system_fortianalyzer-connectivity",
                "system.checksum_status",
                "system_mgmt-csum",
                "system_ha-nonsync-csum",
                "system_fortiguard-log-service",
                "system_central-mgmt",
                "system.info.admin_status",
                "system.info.admin_ssh",
                "system_geoip-country",
                "system_cluster-sync",
                "system_arp",
                "system_startup-error-log",
                "system.source-ip_status",
                "system.auto-update_status",
                "system.auto-update_versions",
                "system.session-info_list",
                "system.session-info_expectation",
                "system.session-info_full-stat",
                "system.session-info_statistics",
                "system.session-info_ttl",
                "system.session-helper-info_list",
                "system.ip-conflict_status",
                "wireless-controller_scan",
                "wireless-controller_wlchanlistlic",
                "wireless-controller_status",
                "wireless-controller_wtp-status",
                "wireless-controller_client-info",
                "wireless-controller_vap-status",
                "wireless-controller_rf-analysis",
                "wireless-controller_spectral-info",
                "ipsec_tunnel",
                "firewall_city",
                "firewall_region",
                "firewall_country",
                "firewall_internet-service",
                "firewall_internet-service-reputation",
                "firewall_internet-service-sld",
                "firewall_internet-service-ipbl-vendor",
                "firewall_internet-service-ipbl-reason",
                "firewall_internet-service-owner",
                "firewall_internet-service-list",
                "firewall_internet-service-botnet",
                "firewall_vendor-mac",
                "firewall_vendor-mac-summary",
                "firewall.shaper_traffic",
                "firewall.shaper_per-ip",
                "firewall.iprope_list",
                "firewall.iprope.appctrl_list",
                "firewall.iprope.appctrl_status",
                "firewall_proute",
                "firewall_proute6",
                "vpn.ssl_monitor",
                "vpn.ipsec.stats_crypto",
                "vpn.ipsec.stats_tunnel",
                "vpn.ipsec.tunnel_details",
                "vpn.ipsec.tunnel_summary",
                "vpn.ipsec.tunnel_name",
                "vpn.ike_gateway",
                "vpn.status_l2tp",
                "vpn.status_pptp",
                "vpn.status.ssl_list",
                "vpn.status.ssl_hw-acceleration-status",
                "webfilter_categories",
                "webfilter_ftgd-statistics",
                "webfilter_status",
                "webfilter_override-usr",
                "ips_view-map",
                "ips_decoder",
                "ips_rule",
                "ips_rule-settings",
                "ips_session",
                "application_name",
                "application_rule-settings",
                "report.sql_status",
                "extender-controller_dataplan",
                "extender-controller_extender-profile",
                "extender-controller_extender",
                "router_info",
                "router_info6",
                "hardware_status",
                "hardware_cpu",
                "hardware_memory",
                "hardware_nic",
                "hardware.npu.np6_port-list",
                "hardware.npu.np6_dce",
                "hardware.npu.np6_session-stats",
                "hardware.npu.np6_sse-stats",
                "hardware.npu.np6_ipsec-stats",
                "hardware.npu.np6_synproxy-stats",
                "mgmt-data_status",
                "extender_sys-info",
                "extender_extender-info",
                "extender_session-info",
                "extender_datachannel-info",
                "extender_fexwan",
                "extender_modem-status",
                "extender_lte-carrier-list",
                "extender_lte-carrier-by-mcc-mnc",
                "wireless-controller_address",
                "wireless-controller_addrgrp",
                "system_fortiai",
                "system_fortimanager",
                "system_fm",
                "system_nat64",
                "firewall_vip46",
                "firewall_vip64",
                "firewall_vipgrp46",
                "firewall_vipgrp64",
                "firewall_policy64",
                "firewall_policy46",
                "system.autoupdate_push-update",
                "switch-controller_nac-settings",
                "switch-controller_port-policy",
                "switch-controller_nac-device",
                "emailfilter_bwl",
                "antivirus_heuristic",
                "credential-store_domain-controller",
                "report_dataset",
                "report_chart",
                "report_style",
                "report_theme",
                "gtp_ie-white-list",
                "system.replacemsg_nntp",
                "system.replacemsg_device-detection-portal",
                "switch-controller_poe",
                "cifs_domain-controller",
                "cifs_profile",
                "system.replacemsg_mms",
                "system.replacemsg_mm1",
                "system.replacemsg_mm3",
                "system.replacemsg_mm4",
                "system.replacemsg_mm7",
                "system_virtual-wan-link",
                "system_mem-mgr",
                "firewall_carrier-endpoint-bwl",
                "firewall_mms-profile",
                "firewall.consolidated_policy",
                "firewall_policy6",
                "antivirus_notification",
                "antivirus_mms-checksum",
                "switch-controller_vlan",
                "switch-controller.security-policy_captive-portal",
                "user_device",
                "user_device-group",
                "endpoint-control_client",
                "system.replacemsg_ec",
                "dlp_fp-sensitivity",
                "spamfilter_bword",
                "spamfilter_bwl",
                "spamfilter_mheader",
                "spamfilter_dnsbl",
                "spamfilter_iptrust",
                "spamfilter_profile",
                "spamfilter_fortishield",
                "spamfilter_options",
                "user_device-category",
                "user_device-access-list",
                "switch-controller_mac-sync-settings",
                "endpoint-control_forticlient-ems",
                "endpoint-control_profile",
                "endpoint-control_forticlient-registration-sync",
                "endpoint-control_registered-forticlient",
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
                        "system_vdom",
                        "system_global",
                        "system_accprofile",
                        "system_vdom-link",
                        "system_switch-interface",
                        "system_object-tagging",
                        "system_interface",
                        "system_password-policy",
                        "system_password-policy-guest-admin",
                        "system_sms-server",
                        "system_custom-language",
                        "system_admin",
                        "system_api-user",
                        "system_sso-admin",
                        "system_sso-forticloud-admin",
                        "system_sso-fortigate-cloud-admin",
                        "system_settings",
                        "system_sit-tunnel",
                        "system_fsso-polling",
                        "system_ha",
                        "system_ha-monitor",
                        "system_storage",
                        "system_dedicated-mgmt",
                        "system_arp-table",
                        "system_ipv6-neighbor-cache",
                        "system_dns",
                        "system_ddns",
                        "system_sflow",
                        "system_vdom-sflow",
                        "system_netflow",
                        "system_vdom-netflow",
                        "system_vdom-dns",
                        "system_replacemsg-image",
                        "system_replacemsg-group",
                        "system.snmp_sysinfo",
                        "system.snmp_mib-view",
                        "system.snmp_community",
                        "system.snmp_user",
                        "system.autoupdate_schedule",
                        "system.autoupdate_tunneling",
                        "system_session-ttl",
                        "system.dhcp_server",
                        "system.dhcp6_server",
                        "system_alias",
                        "system_auto-script",
                        "system_management-tunnel",
                        "system_central-management",
                        "system_zone",
                        "system_sdn-proxy",
                        "system_sdn-connector",
                        "system_ipv6-tunnel",
                        "system_external-resource",
                        "system_ips-urlfilter-dns",
                        "system_ips-urlfilter-dns6",
                        "system_network-visibility",
                        "system_sdwan",
                        "system_evpn",
                        "system_gre-tunnel",
                        "system_ipsec-aggregate",
                        "system_ipip-tunnel",
                        "system_mobile-tunnel",
                        "system_pppoe-interface",
                        "system_vxlan",
                        "system_geneve",
                        "system_virtual-wire-pair",
                        "system_dns-database",
                        "system_dns-server",
                        "system_resource-limits",
                        "system_vdom-property",
                        "system_speed-test-server",
                        "system.lldp_network-policy",
                        "system_pcp-server",
                        "system_speed-test-schedule",
                        "system_speed-test-setting",
                        "system_standalone-cluster",
                        "system_fortiguard",
                        "system_ips",
                        "system_email-server",
                        "system_alarm",
                        "system_mac-address-table",
                        "system_session-helper",
                        "system_proxy-arp",
                        "system_fips-cc",
                        "system_tos-based-priority",
                        "system_dscp-based-priority",
                        "system_probe-response",
                        "system_link-monitor",
                        "system_auto-install",
                        "system_console",
                        "system_ntp",
                        "system_ptp",
                        "system_wccp",
                        "system_dns64",
                        "system_vdom-radius-server",
                        "system_ftm-push",
                        "system_geoip-override",
                        "system_fortisandbox",
                        "system_fortindr",
                        "system_affinity-interrupt",
                        "system_affinity-packet-redistribution",
                        "system_vdom-exception",
                        "system_csf",
                        "system_automation-trigger",
                        "system_automation-action",
                        "system_automation-destination",
                        "system_automation-stitch",
                        "system_nd-proxy",
                        "system_saml",
                        "system_federated-upgrade",
                        "system_device-upgrade",
                        "system_vne-tunnel",
                        "system_ike",
                        "system_acme",
                        "system_ipam",
                        "system_fabric-vpn",
                        "system_ssh-config",
                        "wireless-controller_inter-controller",
                        "wireless-controller_global",
                        "wireless-controller.hotspot20_anqp-venue-name",
                        "wireless-controller.hotspot20_anqp-venue-url",
                        "wireless-controller.hotspot20_anqp-network-auth-type",
                        "wireless-controller.hotspot20_anqp-roaming-consortium",
                        "wireless-controller.hotspot20_anqp-nai-realm",
                        "wireless-controller.hotspot20_anqp-3gpp-cellular",
                        "wireless-controller.hotspot20_anqp-ip-address-type",
                        "wireless-controller.hotspot20_h2qp-operator-name",
                        "wireless-controller.hotspot20_h2qp-wan-metric",
                        "wireless-controller.hotspot20_h2qp-conn-capability",
                        "wireless-controller.hotspot20_icon",
                        "wireless-controller.hotspot20_h2qp-osu-provider",
                        "wireless-controller.hotspot20_qos-map",
                        "wireless-controller.hotspot20_h2qp-advice-of-charge",
                        "wireless-controller.hotspot20_h2qp-osu-provider-nai",
                        "wireless-controller.hotspot20_h2qp-terms-and-conditions",
                        "wireless-controller.hotspot20_hs-profile",
                        "wireless-controller_vap",
                        "wireless-controller_timers",
                        "wireless-controller_setting",
                        "wireless-controller_log",
                        "wireless-controller_apcfg-profile",
                        "wireless-controller_bonjour-profile",
                        "wireless-controller_arrp-profile",
                        "wireless-controller_region",
                        "wireless-controller_vap-group",
                        "wireless-controller_wids-profile",
                        "wireless-controller_ble-profile",
                        "wireless-controller_syslog-profile",
                        "wireless-controller_wtp-profile",
                        "wireless-controller_wtp",
                        "wireless-controller_wtp-group",
                        "wireless-controller_qos-profile",
                        "wireless-controller_wag-profile",
                        "wireless-controller_utm-profile",
                        "wireless-controller_snmp",
                        "wireless-controller_mpsk-profile",
                        "wireless-controller_nac-profile",
                        "wireless-controller_ssid-policy",
                        "wireless-controller_access-control-list",
                        "wireless-controller_ap-status",
                        "switch-controller_traffic-policy",
                        "switch-controller_fortilink-settings",
                        "switch-controller_switch-interface-tag",
                        "switch-controller_802-1X-settings",
                        "switch-controller.security-policy_802-1X",
                        "switch-controller.security-policy_local-access",
                        "switch-controller_location",
                        "switch-controller_lldp-settings",
                        "switch-controller_lldp-profile",
                        "switch-controller.qos_dot1p-map",
                        "switch-controller.qos_ip-dscp-map",
                        "switch-controller.qos_queue-policy",
                        "switch-controller.qos_qos-policy",
                        "switch-controller_storm-control-policy",
                        "switch-controller.auto-config_policy",
                        "switch-controller.auto-config_default",
                        "switch-controller.auto-config_custom",
                        "switch-controller.initial-config_template",
                        "switch-controller.initial-config_vlans",
                        "switch-controller_switch-profile",
                        "switch-controller_custom-command",
                        "switch-controller_virtual-port-pool",
                        "switch-controller.ptp_profile",
                        "switch-controller.ptp_interface-policy",
                        "switch-controller_vlan-policy",
                        "switch-controller.acl_ingress",
                        "switch-controller.acl_group",
                        "switch-controller_dynamic-port-policy",
                        "switch-controller_managed-switch",
                        "switch-controller_switch-group",
                        "switch-controller_stp-settings",
                        "switch-controller_stp-instance",
                        "switch-controller_storm-control",
                        "switch-controller_global",
                        "switch-controller_system",
                        "switch-controller_switch-log",
                        "switch-controller_igmp-snooping",
                        "switch-controller_sflow",
                        "switch-controller_quarantine",
                        "switch-controller_network-monitor-settings",
                        "switch-controller_flow-tracking",
                        "switch-controller_snmp-sysinfo",
                        "switch-controller_snmp-trap-threshold",
                        "switch-controller_snmp-community",
                        "switch-controller_snmp-user",
                        "switch-controller_traffic-sniffer",
                        "switch-controller_remote-log",
                        "switch-controller_mac-policy",
                        "firewall_address",
                        "firewall_multicast-address",
                        "firewall_address6-template",
                        "firewall_address6",
                        "firewall_multicast-address6",
                        "firewall_addrgrp",
                        "firewall_addrgrp6",
                        "firewall.wildcard-fqdn_custom",
                        "firewall.wildcard-fqdn_group",
                        "firewall_traffic-class",
                        "firewall.service_category",
                        "firewall.service_custom",
                        "firewall.service_group",
                        "firewall_internet-service-name",
                        "firewall_internet-service-group",
                        "firewall_internet-service-extension",
                        "firewall_internet-service-custom",
                        "firewall_internet-service-addition",
                        "firewall_internet-service-append",
                        "firewall_internet-service-custom-group",
                        "firewall_internet-service-definition",
                        "firewall_network-service-dynamic",
                        "firewall.shaper_traffic-shaper",
                        "firewall.shaper_per-ip-shaper",
                        "firewall_proxy-address",
                        "firewall_proxy-addrgrp",
                        "firewall.schedule_onetime",
                        "firewall.schedule_recurring",
                        "firewall.schedule_group",
                        "firewall_ippool",
                        "firewall_ippool6",
                        "firewall_ldb-monitor",
                        "firewall_vip",
                        "firewall_vip6",
                        "firewall_vipgrp",
                        "firewall_vipgrp6",
                        "firewall.ssh_local-key",
                        "firewall.ssh_local-ca",
                        "firewall.ssh_setting",
                        "firewall.ssh_host-key",
                        "firewall_decrypted-traffic-mirror",
                        "firewall_access-proxy-virtual-host",
                        "firewall_access-proxy-ssh-client-cert",
                        "firewall_access-proxy",
                        "firewall_access-proxy6",
                        "firewall.ipmacbinding_setting",
                        "firewall.ipmacbinding_table",
                        "firewall_profile-protocol-options",
                        "firewall_ssl-ssh-profile",
                        "firewall_ssl-server",
                        "firewall_profile-group",
                        "firewall_identity-based-route",
                        "firewall_auth-portal",
                        "firewall_security-policy",
                        "firewall_policy",
                        "firewall_shaping-policy",
                        "firewall_shaping-profile",
                        "firewall_local-in-policy",
                        "firewall_local-in-policy6",
                        "firewall_ttl-policy",
                        "firewall_proxy-policy",
                        "firewall_dnstranslation",
                        "firewall_multicast-policy",
                        "firewall_multicast-policy6",
                        "firewall_interface-policy",
                        "firewall_interface-policy6",
                        "firewall_DoS-policy",
                        "firewall_DoS-policy6",
                        "firewall_sniffer",
                        "firewall_on-demand-sniffer",
                        "firewall_central-snat-map",
                        "firewall.ssl_setting",
                        "firewall_ip-translation",
                        "firewall_ipv6-eh-filter",
                        "firewall_global",
                        "vpn.certificate_ca",
                        "vpn.certificate_remote",
                        "vpn.certificate_local",
                        "vpn.certificate_crl",
                        "vpn.certificate_ocsp-server",
                        "vpn.certificate_setting",
                        "vpn_qkd",
                        "vpn.ssl.web_realm",
                        "vpn.ssl.web_host-check-software",
                        "vpn.ssl.web_portal",
                        "vpn.ssl.web_user-group-bookmark",
                        "vpn.ssl.web_user-bookmark",
                        "vpn.ssl_settings",
                        "vpn.ssl_client",
                        "vpn.ipsec_fec",
                        "vpn.ipsec_phase1",
                        "vpn.ipsec_phase2",
                        "vpn.ipsec_manualkey",
                        "vpn.ipsec_concentrator",
                        "vpn.ipsec_phase1-interface",
                        "vpn.ipsec_phase2-interface",
                        "vpn.ipsec_manualkey-interface",
                        "vpn.ipsec_forticlient",
                        "vpn_kmip-server",
                        "vpn_pptp",
                        "vpn_l2tp",
                        "certificate_ca",
                        "certificate_remote",
                        "certificate_local",
                        "certificate_crl",
                        "webfilter_ftgd-local-cat",
                        "webfilter_content",
                        "webfilter_content-header",
                        "webfilter_urlfilter",
                        "webfilter_ips-urlfilter-setting",
                        "webfilter_ips-urlfilter-setting6",
                        "webfilter_ips-urlfilter-cache-setting",
                        "webfilter_profile",
                        "webfilter_fortiguard",
                        "webfilter_override",
                        "webfilter_ftgd-local-rating",
                        "webfilter_search-engine",
                        "ips_sensor",
                        "ips_custom",
                        "ips_global",
                        "ips_settings",
                        "sctp-filter_profile",
                        "diameter-filter_profile",
                        "web-proxy_profile",
                        "web-proxy_global",
                        "web-proxy_explicit",
                        "web-proxy_forward-server",
                        "web-proxy_forward-server-group",
                        "web-proxy_debug-url",
                        "web-proxy_wisp",
                        "web-proxy_fast-fallback",
                        "web-proxy_url-match",
                        "wanopt_webcache",
                        "wanopt_settings",
                        "wanopt_peer",
                        "wanopt_auth-group",
                        "wanopt_profile",
                        "wanopt_content-delivery-network-rule",
                        "wanopt_cache-service",
                        "wanopt_remote-storage",
                        "ftp-proxy_explicit",
                        "application_custom",
                        "application_list",
                        "application_group",
                        "dlp_data-type",
                        "dlp_dictionary",
                        "dlp_exact-data-match",
                        "dlp_sensor",
                        "dlp_filepattern",
                        "dlp_sensitivity",
                        "dlp_fp-doc-source",
                        "dlp_profile",
                        "dlp_settings",
                        "videofilter_youtube-key",
                        "videofilter_keyword",
                        "videofilter_profile",
                        "emailfilter_bword",
                        "emailfilter_block-allow-list",
                        "emailfilter_mheader",
                        "emailfilter_dnsbl",
                        "emailfilter_iptrust",
                        "emailfilter_profile",
                        "emailfilter_fortishield",
                        "emailfilter_options",
                        "log_threat-weight",
                        "log_custom-field",
                        "log.syslogd_setting",
                        "log.syslogd_override-setting",
                        "log.syslogd_filter",
                        "log.syslogd_override-filter",
                        "log.syslogd2_setting",
                        "log.syslogd2_override-setting",
                        "log.syslogd2_filter",
                        "log.syslogd2_override-filter",
                        "log.syslogd3_setting",
                        "log.syslogd3_override-setting",
                        "log.syslogd3_filter",
                        "log.syslogd3_override-filter",
                        "log.syslogd4_setting",
                        "log.syslogd4_override-setting",
                        "log.syslogd4_filter",
                        "log.syslogd4_override-filter",
                        "log.webtrends_setting",
                        "log.webtrends_filter",
                        "log.memory_global-setting",
                        "log.memory_setting",
                        "log.memory_filter",
                        "log.disk_setting",
                        "log.disk_filter",
                        "log_eventfilter",
                        "log.fortiguard_setting",
                        "log.fortiguard_override-setting",
                        "log.fortiguard_filter",
                        "log.fortiguard_override-filter",
                        "log.tacacs+accounting_setting",
                        "log.tacacs+accounting_filter",
                        "log.tacacs+accounting2_setting",
                        "log.tacacs+accounting2_filter",
                        "log.tacacs+accounting3_setting",
                        "log.tacacs+accounting3_filter",
                        "log.null-device_setting",
                        "log.null-device_filter",
                        "log_setting",
                        "log_gui-display",
                        "log.fortianalyzer_setting",
                        "log.fortianalyzer_override-setting",
                        "log.fortianalyzer_filter",
                        "log.fortianalyzer_override-filter",
                        "log.fortianalyzer2_setting",
                        "log.fortianalyzer2_override-setting",
                        "log.fortianalyzer2_filter",
                        "log.fortianalyzer2_override-filter",
                        "log.fortianalyzer3_setting",
                        "log.fortianalyzer3_override-setting",
                        "log.fortianalyzer3_filter",
                        "log.fortianalyzer3_override-filter",
                        "log.fortianalyzer-cloud_setting",
                        "log.fortianalyzer-cloud_override-setting",
                        "log.fortianalyzer-cloud_filter",
                        "log.fortianalyzer-cloud_override-filter",
                        "icap_server",
                        "icap_server-group",
                        "icap_profile",
                        "user_peer",
                        "user_peergrp",
                        "user_certificate",
                        "user_radius",
                        "user_tacacs+",
                        "user_exchange",
                        "user_ldap",
                        "user_krb-keytab",
                        "user_domain-controller",
                        "user_pop3",
                        "user_saml",
                        "user_external-identity-provider",
                        "user_fsso",
                        "user_adgrp",
                        "user_fsso-polling",
                        "user_fortitoken",
                        "user_password-policy",
                        "user_local",
                        "user_setting",
                        "user_quarantine",
                        "user_group",
                        "user_security-exempt-list",
                        "user_nac-policy",
                        "voip_profile",
                        "dnsfilter_domain-filter",
                        "dnsfilter_profile",
                        "nsxt_setting",
                        "nsxt_service-chain",
                        "antivirus_settings",
                        "antivirus_quarantine",
                        "antivirus_exempt-list",
                        "antivirus_profile",
                        "ssh-filter_profile",
                        "file-filter_profile",
                        "virtual-patch_profile",
                        "report_layout",
                        "report_setting",
                        "waf_main-class",
                        "waf_sub-class",
                        "waf_signature",
                        "waf_profile",
                        "casb_saas-application",
                        "casb_user-activity",
                        "casb_profile",
                        "authentication_scheme",
                        "authentication_rule",
                        "authentication_setting",
                        "extension-controller_dataplan",
                        "extension-controller_extender-vap",
                        "extension-controller_extender-profile",
                        "extension-controller_extender",
                        "extension-controller_fortigate-profile",
                        "extension-controller_fortigate",
                        "endpoint-control_fctems",
                        "endpoint-control_settings",
                        "endpoint-control_fctems-override",
                        "alertemail_setting",
                        "router_access-list",
                        "router_access-list6",
                        "router_aspath-list",
                        "router_prefix-list",
                        "router_prefix-list6",
                        "router_key-chain",
                        "router_community-list",
                        "router_extcommunity-list",
                        "router_route-map",
                        "router_rip",
                        "router_ripng",
                        "router_static",
                        "router_policy",
                        "router_policy6",
                        "router_static6",
                        "router_ospf",
                        "router_ospf6",
                        "router_bgp",
                        "router_isis",
                        "router_multicast-flow",
                        "router_multicast",
                        "router_multicast6",
                        "router_auth-path",
                        "router_setting",
                        "router_bfd",
                        "router_bfd6",
                        "automation_setting",
                        "dpdk_global",
                        "dpdk_cpus",
                        "system_isf-queue-profile",
                        "system_npu",
                        "system_np6",
                        "system_gi-gk",
                        "system_modem",
                        "system.3g-modem_custom",
                        "system_lte-modem",
                        "firewall_gtp",
                        "firewall_pfcp",
                        "firewall_acl",
                        "firewall_acl6",
                        "gtp_apn",
                        "gtp_apngrp",
                        "gtp_message-filter-v0v1",
                        "gtp_message-filter-v2",
                        "gtp_rat-timeout-profile",
                        "gtp_ie-allow-list",
                        "gtp_tunnel-limit",
                        "gtp_apn-shaper",
                        "pfcp_message-filter",
                        "monitoring_np6-ipsec-engine",
                        "monitoring_npu-hpe",
                        "system_npu-vlink",
                        "system_physical-switch",
                        "system_virtual-switch",
                        "system_stp",
                        "system_smc-ntp",
                        "videofilter_youtube-channel-filter",
                        "switch-controller.ptp_settings",
                        "switch-controller.ptp_policy",
                        "vpn_ocvpn",
                        "system.replacemsg_mail",
                        "system.replacemsg_http",
                        "system.replacemsg_webproxy",
                        "system.replacemsg_ftp",
                        "system.replacemsg_fortiguard-wf",
                        "system.replacemsg_spam",
                        "system.replacemsg_alertmail",
                        "system.replacemsg_admin",
                        "system.replacemsg_auth",
                        "system.replacemsg_sslvpn",
                        "system.replacemsg_nac-quar",
                        "system.replacemsg_traffic-quota",
                        "system.replacemsg_utm",
                        "system.replacemsg_icap",
                        "system.replacemsg_automation",
                        "system_status",
                        "system.performance_status",
                        "system.performance_top",
                        "system.performance.firewall_packet-distribution",
                        "system.performance.firewall_statistics",
                        "system_session",
                        "system_session6",
                        "system_cmdb",
                        "system_fortiguard-service",
                        "system_fortianalyzer-connectivity",
                        "system.checksum_status",
                        "system_mgmt-csum",
                        "system_ha-nonsync-csum",
                        "system_fortiguard-log-service",
                        "system_central-mgmt",
                        "system.info.admin_status",
                        "system.info.admin_ssh",
                        "system_geoip-country",
                        "system_cluster-sync",
                        "system_arp",
                        "system_startup-error-log",
                        "system.source-ip_status",
                        "system.auto-update_status",
                        "system.auto-update_versions",
                        "system.session-info_list",
                        "system.session-info_expectation",
                        "system.session-info_full-stat",
                        "system.session-info_statistics",
                        "system.session-info_ttl",
                        "system.session-helper-info_list",
                        "system.ip-conflict_status",
                        "wireless-controller_scan",
                        "wireless-controller_wlchanlistlic",
                        "wireless-controller_status",
                        "wireless-controller_wtp-status",
                        "wireless-controller_client-info",
                        "wireless-controller_vap-status",
                        "wireless-controller_rf-analysis",
                        "wireless-controller_spectral-info",
                        "ipsec_tunnel",
                        "firewall_city",
                        "firewall_region",
                        "firewall_country",
                        "firewall_internet-service",
                        "firewall_internet-service-reputation",
                        "firewall_internet-service-sld",
                        "firewall_internet-service-ipbl-vendor",
                        "firewall_internet-service-ipbl-reason",
                        "firewall_internet-service-owner",
                        "firewall_internet-service-list",
                        "firewall_internet-service-botnet",
                        "firewall_vendor-mac",
                        "firewall_vendor-mac-summary",
                        "firewall.shaper_traffic",
                        "firewall.shaper_per-ip",
                        "firewall.iprope_list",
                        "firewall.iprope.appctrl_list",
                        "firewall.iprope.appctrl_status",
                        "firewall_proute",
                        "firewall_proute6",
                        "vpn.ssl_monitor",
                        "vpn.ipsec.stats_crypto",
                        "vpn.ipsec.stats_tunnel",
                        "vpn.ipsec.tunnel_details",
                        "vpn.ipsec.tunnel_summary",
                        "vpn.ipsec.tunnel_name",
                        "vpn.ike_gateway",
                        "vpn.status_l2tp",
                        "vpn.status_pptp",
                        "vpn.status.ssl_list",
                        "vpn.status.ssl_hw-acceleration-status",
                        "webfilter_categories",
                        "webfilter_ftgd-statistics",
                        "webfilter_status",
                        "webfilter_override-usr",
                        "ips_view-map",
                        "ips_decoder",
                        "ips_rule",
                        "ips_rule-settings",
                        "ips_session",
                        "application_name",
                        "application_rule-settings",
                        "report.sql_status",
                        "extender-controller_dataplan",
                        "extender-controller_extender-profile",
                        "extender-controller_extender",
                        "router_info",
                        "router_info6",
                        "hardware_status",
                        "hardware_cpu",
                        "hardware_memory",
                        "hardware_nic",
                        "hardware.npu.np6_port-list",
                        "hardware.npu.np6_dce",
                        "hardware.npu.np6_session-stats",
                        "hardware.npu.np6_sse-stats",
                        "hardware.npu.np6_ipsec-stats",
                        "hardware.npu.np6_synproxy-stats",
                        "mgmt-data_status",
                        "extender_sys-info",
                        "extender_extender-info",
                        "extender_session-info",
                        "extender_datachannel-info",
                        "extender_fexwan",
                        "extender_modem-status",
                        "extender_lte-carrier-list",
                        "extender_lte-carrier-by-mcc-mnc",
                        "wireless-controller_address",
                        "wireless-controller_addrgrp",
                        "system_fortiai",
                        "system_fortimanager",
                        "system_fm",
                        "system_nat64",
                        "firewall_vip46",
                        "firewall_vip64",
                        "firewall_vipgrp46",
                        "firewall_vipgrp64",
                        "firewall_policy64",
                        "firewall_policy46",
                        "system.autoupdate_push-update",
                        "switch-controller_nac-settings",
                        "switch-controller_port-policy",
                        "switch-controller_nac-device",
                        "emailfilter_bwl",
                        "antivirus_heuristic",
                        "credential-store_domain-controller",
                        "report_dataset",
                        "report_chart",
                        "report_style",
                        "report_theme",
                        "gtp_ie-white-list",
                        "system.replacemsg_nntp",
                        "system.replacemsg_device-detection-portal",
                        "switch-controller_poe",
                        "cifs_domain-controller",
                        "cifs_profile",
                        "system.replacemsg_mms",
                        "system.replacemsg_mm1",
                        "system.replacemsg_mm3",
                        "system.replacemsg_mm4",
                        "system.replacemsg_mm7",
                        "system_virtual-wan-link",
                        "system_mem-mgr",
                        "firewall_carrier-endpoint-bwl",
                        "firewall_mms-profile",
                        "firewall.consolidated_policy",
                        "firewall_policy6",
                        "antivirus_notification",
                        "antivirus_mms-checksum",
                        "switch-controller_vlan",
                        "switch-controller.security-policy_captive-portal",
                        "user_device",
                        "user_device-group",
                        "endpoint-control_client",
                        "system.replacemsg_ec",
                        "dlp_fp-sensitivity",
                        "spamfilter_bword",
                        "spamfilter_bwl",
                        "spamfilter_mheader",
                        "spamfilter_dnsbl",
                        "spamfilter_iptrust",
                        "spamfilter_profile",
                        "spamfilter_fortishield",
                        "spamfilter_options",
                        "user_device-category",
                        "user_device-access-list",
                        "switch-controller_mac-sync-settings",
                        "endpoint-control_forticlient-ems",
                        "endpoint-control_profile",
                        "endpoint-control_forticlient-registration-sync",
                        "endpoint-control_registered-forticlient",
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
            connection.set_custom_option("access_token", module.params["access_token"])
        if "enable_log" in module.params:
            connection.set_custom_option("enable_log", module.params["enable_log"])
        else:
            connection.set_custom_option("enable_log", False)

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
