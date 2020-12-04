from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import FortiOSHandler
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import check_legacy_fortiosapi
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import FAIL_SOCKET_MSG

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
    "test_openstackd": {
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
    "test_forticldd": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.replacemsg_sslvpn": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "ips_view-map": {
        "mkey_type": int,
        "mkey": "id",
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
    "system_affinity-packet-redistribution": {
        "mkey_type": int,
        "mkey": "id",
    },
    "firewall_proxy-address": {
        "mkey_type": str,
        "mkey": "name",
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
    "test_uploadd": {
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
    "switch-controller_remote-log": {
        "mkey_type": str,
        "mkey": "name",
    },
    "router_rip": {
        "mkey_type": None,
        "mkey": "None",
    },
    "test_ipsmonitor": {
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
    "test_pop3": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wireless-controller_wag-profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_internet-service-reputation": {
        "mkey_type": int,
        "mkey": "id",
    },
    "test_wf_monitor": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_internet-service": {
        "mkey_type": int,
        "mkey": "id",
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
    "router_prefix-list6": {
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
    "wireless-controller_scan": {
        "mkey_type": None,
        "mkey": "None",
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
    "webfilter_ips-urlfilter-setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch-controller_network-monitor-settings": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_alias": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch-controller.auto-config_policy": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch-controller_port-policy": {
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
    "firewall.service_group": {
        "mkey_type": str,
        "mkey": "name",
    },
    "test_radvd": {
        "mkey_type": None,
        "mkey": "None",
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
    "webfilter_search-engine": {
        "mkey_type": str,
        "mkey": "name",
    },
    "endpoint-control_fctems": {
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
    "system_nat64": {
        "mkey_type": None,
        "mkey": "None",
    },
    "report_layout": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall.consolidated_policy": {
        "mkey_type": int,
        "mkey": "policyid",
    },
    "wireless-controller.hotspot20_icon": {
        "mkey_type": str,
        "mkey": "name",
    },
    "test_dhcp6r": {
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
    "vpn.ike_gateway": {
        "mkey_type": None,
        "mkey": "None",
    },
    "webfilter_override": {
        "mkey_type": int,
        "mkey": "id",
    },
    "test_reportd": {
        "mkey_type": None,
        "mkey": "None",
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
    "test_info-sslvpnd": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch-controller_lldp-profile": {
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
    "test_ftpd": {
        "mkey_type": None,
        "mkey": "None",
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
    "system.session-info_full-stat": {
        "mkey_type": None,
        "mkey": "None",
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
    "webfilter_ftgd-statistics": {
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
    "system_dedicated-mgmt": {
        "mkey_type": None,
        "mkey": "None",
    },
    "test_ipamd": {
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
    "log.memory_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_auth-portal": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_sflow": {
        "mkey_type": None,
        "mkey": "None",
    },
    "test_hasync": {
        "mkey_type": None,
        "mkey": "None",
    },
    "test_wad": {
        "mkey_type": None,
        "mkey": "None",
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
    "system_npu": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_vip46": {
        "mkey_type": str,
        "mkey": "name",
    },
    "test_harelay": {
        "mkey_type": None,
        "mkey": "None",
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
    "system_custom-language": {
        "mkey_type": str,
        "mkey": "name",
    },
    "web-proxy_explicit": {
        "mkey_type": None,
        "mkey": "None",
    },
    "vpn.ipsec_concentrator": {
        "mkey_type": str,
        "mkey": "name",
    },
    "test_snmpd": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wireless-controller_wtp-group": {
        "mkey_type": str,
        "mkey": "name",
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
    "test_hatalk": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.null-device_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "ips_rule-settings": {
        "mkey_type": int,
        "mkey": "id",
    },
    "log.syslogd_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.session-info_expectation": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch-controller.security-policy_802-1X": {
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
    "test_ocid": {
        "mkey_type": None,
        "mkey": "None",
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
    "test_lnkmtd": {
        "mkey_type": None,
        "mkey": "None",
    },
    "test_fas": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_prefix-list": {
        "mkey_type": str,
        "mkey": "name",
    },
    "waf_sub-class": {
        "mkey_type": int,
        "mkey": "id",
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
    "test_azd": {
        "mkey_type": None,
        "mkey": "None",
    },
    "user_exchange": {
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
    "test_sdncd": {
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
    "system_arp": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_internet-service-addition": {
        "mkey_type": int,
        "mkey": "id",
    },
    "test_dhcp6c": {
        "mkey_type": None,
        "mkey": "None",
    },
    "test_miglogd": {
        "mkey_type": None,
        "mkey": "None",
    },
    "webfilter_status": {
        "mkey_type": None,
        "mkey": "None",
    },
    "test_iotd": {
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
    "switch-controller_virtual-port-pool": {
        "mkey_type": str,
        "mkey": "name",
    },
    "wireless-controller_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_static6": {
        "mkey_type": int,
        "mkey": "seq_num",
    },
    "wireless-controller.hotspot20_anqp-ip-address-type": {
        "mkey_type": str,
        "mkey": "name",
    },
    "test_dsd": {
        "mkey_type": None,
        "mkey": "None",
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
    "test_gcpd": {
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
    "firewall.schedule_onetime": {
        "mkey_type": str,
        "mkey": "name",
    },
    "vpn.status_pptp": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.fortianalyzer_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "test_autod": {
        "mkey_type": None,
        "mkey": "None",
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
    "cifs_domain-controller": {
        "mkey_type": str,
        "mkey": "server_name",
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
    "test_smtp": {
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
    "system.3g-modem_custom": {
        "mkey_type": int,
        "mkey": "id",
    },
    "test_fcnacd": {
        "mkey_type": None,
        "mkey": "None",
    },
    "ftp-proxy_explicit": {
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
    "firewall_country": {
        "mkey_type": int,
        "mkey": "id",
    },
    "log.disk_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "dlp_filepattern": {
        "mkey_type": int,
        "mkey": "id",
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
    "test_forticron": {
        "mkey_type": None,
        "mkey": "None",
    },
    "test_radiusd": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wireless-controller_inter-controller": {
        "mkey_type": None,
        "mkey": "None",
    },
    "test_zebos_launcher": {
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
    "test_bfd": {
        "mkey_type": None,
        "mkey": "None",
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
    "test_dnsproxy": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_status": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.fortiguard_override-setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_proute": {
        "mkey_type": None,
        "mkey": "None",
    },
    "test_dlpfingerprint": {
        "mkey_type": None,
        "mkey": "None",
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
    "test_radius-das": {
        "mkey_type": None,
        "mkey": "None",
    },
    "test_ipsengine": {
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
    "test_acid": {
        "mkey_type": None,
        "mkey": "None",
    },
    "test_awsd": {
        "mkey_type": None,
        "mkey": "None",
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
    "firewall.shaper_per-ip-shaper": {
        "mkey_type": str,
        "mkey": "name",
    },
    "test_sflowd": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wireless-controller_utm-profile": {
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
    "log.fortianalyzer3_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_email-server": {
        "mkey_type": None,
        "mkey": "None",
    },
    "dlp_sensor": {
        "mkey_type": str,
        "mkey": "name",
    },
    "application_list": {
        "mkey_type": str,
        "mkey": "name",
    },
    "vpn.ssl.web_user-bookmark": {
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
    "test_dhcprelay": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_csf": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.replacemsg_nntp": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "switch-controller_stp-instance": {
        "mkey_type": str,
        "mkey": "id",
    },
    "mgmt-data_status": {
        "mkey_type": None,
        "mkey": "None",
    },
    "dnsfilter_profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_ha-monitor": {
        "mkey_type": None,
        "mkey": "None",
    },
    "test_mrd": {
        "mkey_type": None,
        "mkey": "None",
    },
    "test_ovrd": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wireless-controller.hotspot20_anqp-venue-name": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.snmp_sysinfo": {
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
    "firewall_internet-service-botnet": {
        "mkey_type": int,
        "mkey": "id",
    },
    "firewall_internet-service-definition": {
        "mkey_type": int,
        "mkey": "id",
    },
    "system_mobile-tunnel": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.syslogd3_override-setting": {
        "mkey_type": None,
        "mkey": "None",
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
    "webfilter_fortiguard": {
        "mkey_type": None,
        "mkey": "None",
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
    "wireless-controller_region": {
        "mkey_type": str,
        "mkey": "name",
    },
    "router_policy": {
        "mkey_type": int,
        "mkey": "seq_num",
    },
    "web-proxy_forward-server-group": {
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
    "test_fsvrd": {
        "mkey_type": None,
        "mkey": "None",
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
    "test_wccpd": {
        "mkey_type": None,
        "mkey": "None",
    },
    "report_dataset": {
        "mkey_type": str,
        "mkey": "name",
    },
    "webfilter_ftgd-local-cat": {
        "mkey_type": str,
        "mkey": "desc",
    },
    "router_multicast6": {
        "mkey_type": None,
        "mkey": "None",
    },
    "test_init": {
        "mkey_type": None,
        "mkey": "None",
    },
    "vpn.certificate_remote": {
        "mkey_type": str,
        "mkey": "name",
    },
    "dlp_settings": {
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
    "test_ddnscd": {
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
    "test_dlpfpcache": {
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
    "system_lte-modem": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall.ssh_host-key": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_vdom-link": {
        "mkey_type": str,
        "mkey": "name",
    },
    "test_urlfilter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_fortianalyzer-connectivity": {
        "mkey_type": None,
        "mkey": "None",
    },
    "test_l2tpcd": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_ospf6": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.fortiguard_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.snmp_community": {
        "mkey_type": int,
        "mkey": "id",
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
    "test_csfd": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_profile-protocol-options": {
        "mkey_type": str,
        "mkey": "name",
    },
    "report_theme": {
        "mkey_type": str,
        "mkey": "name",
    },
    "test_kubed": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall.ssh_local-key": {
        "mkey_type": str,
        "mkey": "name",
    },
    "test_pptpcd": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_mgmt-csum": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_vip64": {
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
    "system_fortiguard": {
        "mkey_type": None,
        "mkey": "None",
    },
    "web-proxy_global": {
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
    "wireless-controller.hotspot20_anqp-3gpp-cellular": {
        "mkey_type": str,
        "mkey": "name",
    },
    "report_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_vxlan": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch-controller_snmp-trap-threshold": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch-controller_nac-settings": {
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
    "test_acd": {
        "mkey_type": None,
        "mkey": "None",
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
    "test_imap": {
        "mkey_type": None,
        "mkey": "None",
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
    "test_fsd": {
        "mkey_type": None,
        "mkey": "None",
    },
    "test_sessionsync": {
        "mkey_type": None,
        "mkey": "None",
    },
    "test_nntp": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_interface-policy": {
        "mkey_type": int,
        "mkey": "policyid",
    },
    "system.replacemsg_fortiguard-wf": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "wireless-controller_bonjour-profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "test_ipsufd": {
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
    "dpdk_global": {
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
    "test_fnbamd": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_policy6": {
        "mkey_type": int,
        "mkey": "policyid",
    },
    "router_ripng": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_vip6": {
        "mkey_type": str,
        "mkey": "name",
    },
    "web-proxy_forward-server": {
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
    "test_netxd": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall.ssh_local-ca": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_admin": {
        "mkey_type": str,
        "mkey": "name",
    },
    "test_vmwd": {
        "mkey_type": None,
        "mkey": "None",
    },
    "switch-controller_location": {
        "mkey_type": str,
        "mkey": "name",
    },
    "wireless-controller_timers": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_access-list6": {
        "mkey_type": str,
        "mkey": "name",
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
    "test_quarantined": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_ptp": {
        "mkey_type": None,
        "mkey": "None",
    },
    "test_sepmd": {
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
    "test_ipldbd": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log_threat-weight": {
        "mkey_type": None,
        "mkey": "None",
    },
    "extender-controller_extender": {
        "mkey_type": str,
        "mkey": "id",
    },
    "wireless-controller.hotspot20_h2qp-conn-capability": {
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
    "test_lted": {
        "mkey_type": None,
        "mkey": "None",
    },
}


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def validate_mkey(params):
    selector = params['selector']
    selector_params = params.get('params', {})
    definition = MODULE_MKEY_DEFINITONS.get(selector, {})

    if not selector_params or len(selector_params) == 0 or len(definition) == 0:
        return True, {}

    mkey = definition['mkey']
    mkey_type = definition['mkey_type']
    if mkey_type is None:
        return False, {"message": "params are not allowed for " + selector}
    mkey_value = selector_params.get(mkey)

    if not mkey_value:
        return False, {"message": "param '" + mkey + "' is required"}
    if not isinstance(mkey_value, mkey_type):
        return False, {"message": "param '" + mkey + "' does not match, " + str(mkey_type) + " required"}

    return True, {}


def fortios_configuration_fact(params, fos):
    isValid, result = validate_mkey(params)
    if not isValid:
        return True, False, result

    selector = params['selector']
    selector_params = params['params']
    mkey_name = MODULE_MKEY_DEFINITONS[selector]['mkey']
    mkey_value = selector_params.get(mkey_name) if selector_params else None

    [path, name] = selector.split('_')

    fact = None
    if mkey_value:
        fact = fos.get(path, name, vdom=params['vdom'], mkey=mkey_value)
    else:
        fact = fos.get(path, name, vdom=params['vdom'])

    return not is_successful_status(fact), False, fact


def main():
    fields = {
        "host": {"required": False, "type": "str"},
        "username": {"required": False, "type": "str"},
        "password": {"required": False, "type": "str", "default": "", "no_log": True},
        "access_token": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "ssl_verify": {"required": False, "type": "bool", "default": True},
        "params": {"required": False, "type": "dict"},
        "selector": {
            "required": True,
            "type": "str",
            "options": [
                "log_gui-display",
                "system_fortiguard-service",
                "router_route-map",
                "system_sso-admin",
                "wireless-controller_address",
                "vpn.ssl_monitor",
                "system.auto-update_status",
                "system_cmdb",
                "test_openstackd",
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
                "test_forticldd",
                "system.replacemsg_sslvpn",
                "ips_view-map",
                "system_pppoe-interface",
                "webfilter_categories",
                "firewall_addrgrp6",
                "log.disk_filter",
                "system_affinity-packet-redistribution",
                "firewall_proxy-address",
                "router_bgp",
                "router_auth-path",
                "system_resource-limits",
                "system.replacemsg_auth",
                "system.autoupdate_schedule",
                "test_uploadd",
                "switch-controller.qos_ip-dscp-map",
                "firewall_local-in-policy6",
                "log.fortianalyzer2_override-setting",
                "log.fortianalyzer_override-filter",
                "system.replacemsg_icap",
                "system_object-tagging",
                "switch-controller_remote-log",
                "router_rip",
                "test_ipsmonitor",
                "switch-controller.security-policy_local-access",
                "vpn.ipsec.stats_tunnel",
                "log.fortianalyzer-cloud_override-filter",
                "firewall.shaper_traffic",
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
                "test_pop3",
                "wireless-controller_wag-profile",
                "firewall_internet-service-reputation",
                "test_wf_monitor",
                "firewall_internet-service",
                "firewall.iprope.appctrl_status",
                "firewall_vipgrp46",
                "log.webtrends_filter",
                "application_name",
                "router_prefix-list6",
                "log_setting",
                "firewall_address6-template",
                "wireless-controller_scan",
                "wireless-controller.hotspot20_h2qp-wan-metric",
                "system_automation-action",
                "system.autoupdate_tunneling",
                "webfilter_ips-urlfilter-setting",
                "switch-controller_network-monitor-settings",
                "system_alias",
                "switch-controller.auto-config_policy",
                "switch-controller_port-policy",
                "system_session-helper",
                "router_community-list",
                "wireless-controller_qos-profile",
                "firewall_dnstranslation",
                "vpn.ssl.web_portal",
                "firewall_internet-service-custom",
                "system.replacemsg_device-detection-portal",
                "wireless-controller_ble-profile",
                "firewall_internet-service-custom-group",
                "system.performance.firewall_statistics",
                "firewall_profile-group",
                "firewall.service_group",
                "test_radvd",
                "system.autoupdate_push-update",
                "firewall_address6",
                "system.performance_top",
                "wireless-controller_vap-status",
                "wireless-controller_wids-profile",
                "emailfilter_bword",
                "log.fortiguard_filter",
                "firewall_ipv6-eh-filter",
                "webfilter_search-engine",
                "endpoint-control_fctems",
                "firewall_identity-based-route",
                "system.session-helper-info_list",
                "system_console",
                "certificate_local",
                "system_ntp",
                "system_nat64",
                "report_layout",
                "firewall.consolidated_policy",
                "wireless-controller.hotspot20_icon",
                "test_dhcp6r",
                "log.memory_global-setting",
                "router_multicast-flow",
                "ssh-filter_profile",
                "system_fortisandbox",
                "system_virtual-wan-link",
                "ips_sensor",
                "firewall.wildcard-fqdn_custom",
                "router_static",
                "alertemail_setting",
                "user_peergrp",
                "user_fortitoken",
                "web-proxy_debug-url",
                "vpn.ike_gateway",
                "webfilter_override",
                "test_reportd",
                "switch-controller_nac-device",
                "system_fsso-polling",
                "user_peer",
                "vpn.ssl.web_host-check-software",
                "test_info-sslvpnd",
                "switch-controller_lldp-profile",
                "vpn.ssl.web_realm",
                "system_stp",
                "user_nac-policy",
                "wireless-controller_snmp",
                "emailfilter_fortishield",
                "test_ftpd",
                "firewall_shaping-policy",
                "wireless-controller_wlchanlistlic",
                "log_custom-field",
                "switch-controller_mac-policy",
                "firewall_address",
                "certificate_crl",
                "firewall.ssh_setting",
                "system.session-info_full-stat",
                "system_nd-proxy",
                "log.memory_setting",
                "system_alarm",
                "system_ips-urlfilter-dns6",
                "wireless-controller_log",
                "webfilter_ftgd-statistics",
                "firewall_vendor-mac-summary",
                "system_cluster-sync",
                "wanopt_settings",
                "emailfilter_dnsbl",
                "system_dedicated-mgmt",
                "test_ipamd",
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
                "log.memory_filter",
                "firewall_auth-portal",
                "system_sflow",
                "test_hasync",
                "test_wad",
                "user_ldap",
                "ips_global",
                "wanopt_remote-storage",
                "wireless-controller.hotspot20_qos-map",
                "system.session-info_ttl",
                "vpn_l2tp",
                "system_npu",
                "firewall_vip46",
                "test_harelay",
                "authentication_setting",
                "vpn.certificate_ocsp-server",
                "antivirus_heuristic",
                "system_custom-language",
                "web-proxy_explicit",
                "vpn.ipsec_concentrator",
                "test_snmpd",
                "wireless-controller_wtp-group",
                "system_vdom-sflow",
                "switch-controller_igmp-snooping",
                "waf_signature",
                "test_hatalk",
                "log.null-device_setting",
                "ips_rule-settings",
                "log.syslogd_setting",
                "system.session-info_expectation",
                "switch-controller.security-policy_802-1X",
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
                "test_ocid",
                "system_proxy-arp",
                "webfilter_ftgd-local-rating",
                "switch-controller_snmp-user",
                "ips_custom",
                "switch-controller_switch-interface-tag",
                "router_policy6",
                "test_lnkmtd",
                "test_fas",
                "router_prefix-list",
                "waf_sub-class",
                "log_eventfilter",
                "system_vdom-property",
                "switch-controller_traffic-sniffer",
                "firewall_security-policy",
                "system_external-resource",
                "test_azd",
                "user_exchange",
                "system_ipv6-neighbor-cache",
                "vpn.ipsec.tunnel_details",
                "report_style",
                "log.syslogd2_override-filter",
                "wireless-controller_wtp",
                "wireless-controller_rf-analysis",
                "wanopt_peer",
                "system_saml",
                "test_sdncd",
                "system.dhcp6_server",
                "emailfilter_profile",
                "log.fortianalyzer3_override-filter",
                "hardware_status",
                "firewall_multicast-policy",
                "vpn_ocvpn",
                "system_arp",
                "firewall_internet-service-addition",
                "test_dhcp6c",
                "test_miglogd",
                "webfilter_status",
                "test_iotd",
                "emailfilter_bwl",
                "system_password-policy",
                "switch-controller_virtual-port-pool",
                "wireless-controller_setting",
                "router_static6",
                "wireless-controller.hotspot20_anqp-ip-address-type",
                "test_dsd",
                "firewall_vipgrp",
                "firewall_city",
                "web-proxy_profile",
                "system_switch-interface",
                "router_isis",
                "firewall_policy",
                "log.syslogd_override-setting",
                "test_gcpd",
                "hardware_memory",
                "router_info",
                "system.performance.firewall_packet-distribution",
                "webfilter_content",
                "firewall_vipgrp6",
                "switch-controller.initial-config_template",
                "firewall.schedule_onetime",
                "vpn.status_pptp",
                "log.fortianalyzer_setting",
                "test_autod",
                "vpn.ipsec.tunnel_name",
                "firewall_ippool6",
                "wireless-controller_status",
                "system_central-management",
                "system.replacemsg_http",
                "vpn.status.ssl_list",
                "vpn.ipsec.tunnel_summary",
                "cifs_domain-controller",
                "system_zone",
                "system_vdom-dns",
                "firewall_multicast-address",
                "wireless-controller_wtp-profile",
                "vpn.ssl_settings",
                "router_ospf",
                "test_smtp",
                "switch-controller.qos_queue-policy",
                "dpdk_cpus",
                "system.3g-modem_custom",
                "test_fcnacd",
                "ftp-proxy_explicit",
                "system_fortimanager",
                "system.lldp_network-policy",
                "vpn.certificate_crl",
                "system.replacemsg_admin",
                "router_multicast",
                "webfilter_profile",
                "switch-controller_storm-control",
                "firewall_ssl-ssh-profile",
                "firewall_country",
                "log.disk_setting",
                "dlp_filepattern",
                "firewall_ippool",
                "web-proxy_url-match",
                "vpn.status.ssl_hw-acceleration-status",
                "system_interface",
                "log.syslogd3_override-filter",
                "router_bfd",
                "switch-controller_custom-command",
                "firewall_internet-service-extension",
                "system.replacemsg_webproxy",
                "user_password-policy",
                "test_forticron",
                "test_radiusd",
                "wireless-controller_inter-controller",
                "test_zebos_launcher",
                "log.syslogd4_setting",
                "log.fortianalyzer_filter",
                "hardware_cpu",
                "switch-controller_switch-group",
                "user_fsso",
                "emailfilter_mheader",
                "firewall_vipgrp64",
                "test_bfd",
                "user_quarantine",
                "system_ips-urlfilter-dns",
                "wireless-controller_addrgrp",
                "system_fm",
                "wireless-controller_apcfg-profile",
                "system_global",
                "vpn.ipsec.stats_crypto",
                "wireless-controller.hotspot20_anqp-nai-realm",
                "system_physical-switch",
                "test_dnsproxy",
                "system_status",
                "log.fortiguard_override-setting",
                "firewall_proute",
                "test_dlpfingerprint",
                "log.fortianalyzer3_setting",
                "system.auto-update_versions",
                "firewall_vip",
                "system_virtual-switch",
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
                "test_radius-das",
                "test_ipsengine",
                "antivirus_quarantine",
                "log.fortianalyzer2_override-filter",
                "system.session-info_list",
                "vpn.certificate_ca",
                "test_acid",
                "test_awsd",
                "system_sdn-connector",
                "vpn.ssl.web_user-group-bookmark",
                "system_fortiguard-log-service",
                "system_central-mgmt",
                "hardware_nic",
                "log.null-device_filter",
                "firewall.shaper_per-ip-shaper",
                "test_sflowd",
                "wireless-controller_utm-profile",
                "router_aspath-list",
                "firewall.schedule_group",
                "firewall_internet-service-list",
                "system_dscp-based-priority",
                "dlp_sensitivity",
                "icap_server",
                "vpn.ipsec_phase1-interface",
                "authentication_scheme",
                "log.fortianalyzer3_filter",
                "system_email-server",
                "dlp_sensor",
                "application_list",
                "vpn.ssl.web_user-bookmark",
                "firewall.shaper_traffic-shaper",
                "switch-controller_traffic-policy",
                "test_dhcprelay",
                "system_csf",
                "system.replacemsg_nntp",
                "switch-controller_stp-instance",
                "mgmt-data_status",
                "dnsfilter_profile",
                "system_ha-monitor",
                "test_mrd",
                "test_ovrd",
                "wireless-controller.hotspot20_anqp-venue-name",
                "system.snmp_sysinfo",
                "application_custom",
                "ips_session",
                "system_api-user",
                "system.info.admin_ssh",
                "ips_rule",
                "log.fortianalyzer-cloud_filter",
                "system_netflow",
                "vpn.ipsec_forticlient",
                "system_automation-trigger",
                "firewall_policy64",
                "wireless-controller.hotspot20_h2qp-osu-provider",
                "webfilter_ips-urlfilter-setting6",
                "switch-controller_sflow",
                "firewall.service_custom",
                "firewall_internet-service-botnet",
                "firewall_internet-service-definition",
                "system_mobile-tunnel",
                "log.syslogd3_override-setting",
                "user_saml",
                "firewall_ttl-policy",
                "wireless-controller_client-info",
                "webfilter_fortiguard",
                "vpn_pptp",
                "wireless-controller.hotspot20_hs-profile",
                "log.webtrends_setting",
                "firewall_local-in-policy",
                "wireless-controller_region",
                "router_policy",
                "web-proxy_forward-server-group",
                "switch-controller.qos_dot1p-map",
                "firewall_multicast-policy6",
                "switch-controller.initial-config_vlans",
                "wanopt_content-delivery-network-rule",
                "firewall_region",
                "system_dns-database",
                "waf_main-class",
                "system.replacemsg_nac-quar",
                "system_vdom-radius-server",
                "system_vdom",
                "test_fsvrd",
                "user_tacacs+",
                "system_ipip-tunnel",
                "log.syslogd3_setting",
                "test_wccpd",
                "report_dataset",
                "webfilter_ftgd-local-cat",
                "router_multicast6",
                "test_init",
                "vpn.certificate_remote",
                "dlp_settings",
                "system_fips-cc",
                "switch-controller_snmp-community",
                "system_geneve",
                "system_ha",
                "log.syslogd3_filter",
                "test_ddnscd",
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
                "voip_profile",
                "vpn.ipsec_manualkey-interface",
                "emailfilter_options",
                "system.info.admin_status",
                "switch-controller_snmp-sysinfo",
                "firewall_internet-service-sld",
                "system_vdom-netflow",
                "test_dlpfpcache",
                "firewall.ipmacbinding_table",
                "system_automation-destination",
                "dlp_fp-doc-source",
                "firewall_ldb-monitor",
                "system_lte-modem",
                "firewall.ssh_host-key",
                "system_vdom-link",
                "test_urlfilter",
                "system_fortianalyzer-connectivity",
                "test_l2tpcd",
                "router_ospf6",
                "log.fortiguard_setting",
                "system.snmp_community",
                "ips_settings",
                "firewall_internet-service-ipbl-vendor",
                "system_vdom-exception",
                "system_wccp",
                "router_info6",
                "system_ha-nonsync-csum",
                "system_automation-stitch",
                "test_csfd",
                "firewall_profile-protocol-options",
                "report_theme",
                "test_kubed",
                "firewall.ssh_local-key",
                "test_pptpcd",
                "system_mgmt-csum",
                "firewall_vip64",
                "web-proxy_wisp",
                "switch-controller_switch-profile",
                "system.checksum_status",
                "system_dns-server",
                "system.replacemsg_alertmail",
                "log.fortiguard_override-filter",
                "system_fortiguard",
                "web-proxy_global",
                "wanopt_profile",
                "system_management-tunnel",
                "wireless-controller.hotspot20_anqp-3gpp-cellular",
                "report_setting",
                "system_vxlan",
                "switch-controller_snmp-trap-threshold",
                "switch-controller_nac-settings",
                "system_ipv6-tunnel",
                "firewall.iprope.appctrl_list",
                "test_acd",
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
                "switch-controller_lldp-settings",
                "webfilter_content-header",
                "system_auto-install",
                "log.fortianalyzer3_override-setting",
                "user_domain-controller",
                "wireless-controller_wtp-status",
                "firewall_ssl-server",
                "test_imap",
                "system.replacemsg_traffic-quota",
                "system_virtual-wire-pair",
                "system_mac-address-table",
                "firewall_internet-service-owner",
                "system_network-visibility",
                "log.syslogd_override-filter",
                "test_fsd",
                "test_sessionsync",
                "test_nntp",
                "firewall_interface-policy",
                "system.replacemsg_fortiguard-wf",
                "wireless-controller_bonjour-profile",
                "test_ipsufd",
                "webfilter_urlfilter",
                "wireless-controller_spectral-info",
                "credential-store_domain-controller",
                "dpdk_global",
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
                "test_fnbamd",
                "firewall_policy6",
                "router_ripng",
                "firewall_vip6",
                "web-proxy_forward-server",
                "system.replacemsg_spam",
                "certificate_ca",
                "test_netxd",
                "firewall.ssh_local-ca",
                "system_admin",
                "test_vmwd",
                "switch-controller_location",
                "wireless-controller_timers",
                "router_access-list6",
                "waf_profile",
                "firewall.wildcard-fqdn_group",
                "system_gre-tunnel",
                "user_group",
                "log.syslogd2_override-setting",
                "user_krb-keytab",
                "firewall.iprope_list",
                "test_quarantined",
                "system_ptp",
                "test_sepmd",
                "application_group",
                "system.replacemsg_ftp",
                "test_ipldbd",
                "log_threat-weight",
                "extender-controller_extender",
                "wireless-controller.hotspot20_h2qp-conn-capability",
                "system_session6",
                "switch-controller_managed-switch",
                "test_lted",
            ],
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

        fos = FortiOSHandler(connection, module)

        is_error, has_changed, result = fortios_configuration_fact(module.params, fos)
        if not is_error:
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
