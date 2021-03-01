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
    "router_route-map": {
        "mkey_type": str,
        "mkey": "name",
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
    "system.replacemsg_sslvpn": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "system_pppoe-interface": {
        "mkey_type": str,
        "mkey": "name",
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
    "switch-controller_custom-command": {
        "mkey_type": str,
        "mkey": "command_name",
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
    "waf_sub-class": {
        "mkey_type": int,
        "mkey": "id",
    },
    "firewall_local-in-policy6": {
        "mkey_type": int,
        "mkey": "policyid",
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
    "spamfilter_bwl": {
        "mkey_type": int,
        "mkey": "id",
    },
    "web-proxy_profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "spamfilter_mheader": {
        "mkey_type": int,
        "mkey": "id",
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
    "switch-controller.qos_qos-policy": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_sniffer": {
        "mkey_type": int,
        "mkey": "id",
    },
    "log.fortiguard_override-setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_internet-service": {
        "mkey_type": int,
        "mkey": "id",
    },
    "firewall_vipgrp46": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.webtrends_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "webfilter_ips-urlfilter-setting6": {
        "mkey_type": None,
        "mkey": "None",
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
    "switch-controller_mac-sync-settings": {
        "mkey_type": None,
        "mkey": "None",
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
    "firewall_dnstranslation": {
        "mkey_type": int,
        "mkey": "id",
    },
    "vpn.ssl.web_portal": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_vdom-property": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.replacemsg_device-detection-portal": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "log.syslogd2_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_internet-service-custom-group": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_profile-group": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall.service_group": {
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
    "endpoint-control_profile": {
        "mkey_type": str,
        "mkey": "profile_name",
    },
    "wireless-controller_wids-profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.fortiguard_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_ipv6-eh-filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "user_device-category": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_identity-based-route": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_console": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_ntp": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_nat64": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.3g-modem_custom": {
        "mkey_type": int,
        "mkey": "id",
    },
    "report_layout": {
        "mkey_type": str,
        "mkey": "name",
    },
    "wireless-controller_timers": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wireless-controller.hotspot20_icon": {
        "mkey_type": str,
        "mkey": "name",
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
    "user_fortitoken": {
        "mkey_type": str,
        "mkey": "serial_number",
    },
    "web-proxy_debug-url": {
        "mkey_type": str,
        "mkey": "name",
    },
    "webfilter_override": {
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
    "switch-controller.security-policy_captive-portal": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_shaping-policy": {
        "mkey_type": int,
        "mkey": "id",
    },
    "log_custom-field": {
        "mkey_type": str,
        "mkey": "id",
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
    "router_access-list": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.memory_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_alarm": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_ipv6-neighbor-cache": {
        "mkey_type": int,
        "mkey": "id",
    },
    "system_cluster-sync": {
        "mkey_type": int,
        "mkey": "sync_id",
    },
    "wanopt_settings": {
        "mkey_type": None,
        "mkey": "None",
    },
    "endpoint-control_registered-forticlient": {
        "mkey_type": str,
        "mkey": "uid",
    },
    "system_dedicated-mgmt": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_policy46": {
        "mkey_type": int,
        "mkey": "policyid",
    },
    "system_modem": {
        "mkey_type": None,
        "mkey": "None",
    },
    "antivirus_settings": {
        "mkey_type": None,
        "mkey": "None",
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
    "switch-controller.security-policy_802-1X": {
        "mkey_type": str,
        "mkey": "name",
    },
    "report_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "user_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "icap_profile": {
        "mkey_type": str,
        "mkey": "name",
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
    "application_rule-settings": {
        "mkey_type": int,
        "mkey": "id",
    },
    "log.syslogd4_filter": {
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
    "switch-controller.qos_ip-dscp-map": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log_eventfilter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_internet-service-custom": {
        "mkey_type": str,
        "mkey": "name",
    },
    "router_auth-path": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_external-resource": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_ips-urlfilter-dns6": {
        "mkey_type": str,
        "mkey": "address6",
    },
    "report_style": {
        "mkey_type": str,
        "mkey": "name",
    },
    "wireless-controller_wtp": {
        "mkey_type": str,
        "mkey": "wtp_id",
    },
    "system_ipip-tunnel": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.dhcp6_server": {
        "mkey_type": int,
        "mkey": "id",
    },
    "firewall_multicast-policy": {
        "mkey_type": int,
        "mkey": "id",
    },
    "vpn_ocvpn": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_rip": {
        "mkey_type": None,
        "mkey": "None",
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
    "firewall_vipgrp": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch-controller_switch-profile": {
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
    "system_lte-modem": {
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
    "firewall.schedule_onetime": {
        "mkey_type": str,
        "mkey": "name",
    },
    "antivirus_profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.fortianalyzer_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall_ippool6": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_central-management": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.replacemsg_http": {
        "mkey_type": str,
        "mkey": "msg_type",
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
    "endpoint-control_forticlient-ems": {
        "mkey_type": str,
        "mkey": "name",
    },
    "ftp-proxy_explicit": {
        "mkey_type": None,
        "mkey": "None",
    },
    "user_device-group": {
        "mkey_type": str,
        "mkey": "name",
    },
    "vpn.certificate_crl": {
        "mkey_type": str,
        "mkey": "name",
    },
    "user_local": {
        "mkey_type": str,
        "mkey": "name",
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
    "dlp_fp-sensitivity": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_interface": {
        "mkey_type": str,
        "mkey": "name",
    },
    "router_bfd": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_virtual-wire-pair": {
        "mkey_type": str,
        "mkey": "name",
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
    "log.syslogd4_setting": {
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
    "system_fm": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_global": {
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
    "log.fortianalyzer3_setting": {
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
    "wanopt_cache-service": {
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
    "system_replacemsg-image": {
        "mkey_type": str,
        "mkey": "name",
    },
    "antivirus_quarantine": {
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
    "endpoint-control_settings": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.null-device_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "dlp_settings": {
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
    "system_dscp-based-priority": {
        "mkey_type": int,
        "mkey": "id",
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
    "wireless-controller_ap-status": {
        "mkey_type": int,
        "mkey": "id",
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
    "system_management-tunnel": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_csf": {
        "mkey_type": None,
        "mkey": "None",
    },
    "firewall.shaper_per-ip-shaper": {
        "mkey_type": str,
        "mkey": "name",
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
    "system_api-user": {
        "mkey_type": str,
        "mkey": "name",
    },
    "ips_rule": {
        "mkey_type": str,
        "mkey": "name",
    },
    "spamfilter_fortishield": {
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
    "application_name": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall.service_custom": {
        "mkey_type": str,
        "mkey": "name",
    },
    "spamfilter_iptrust": {
        "mkey_type": int,
        "mkey": "id",
    },
    "system_mobile-tunnel": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_ttl-policy": {
        "mkey_type": int,
        "mkey": "id",
    },
    "system.replacemsg_utm": {
        "mkey_type": str,
        "mkey": "msg_type",
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
    "router_policy": {
        "mkey_type": int,
        "mkey": "seq_num",
    },
    "switch-controller.qos_dot1p-map": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_multicast-policy6": {
        "mkey_type": int,
        "mkey": "id",
    },
    "wanopt_content-delivery-network-rule": {
        "mkey_type": str,
        "mkey": "name",
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
    "user_tacacs+": {
        "mkey_type": str,
        "mkey": "name",
    },
    "wanopt_peer": {
        "mkey_type": str,
        "mkey": "peer_host_id",
    },
    "log.syslogd3_setting": {
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
    "vpn.certificate_remote": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_fips-cc": {
        "mkey_type": None,
        "mkey": "None",
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
    "dlp_sensor": {
        "mkey_type": str,
        "mkey": "name",
    },
    "log.syslogd2_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wireless-controller_ble-profile": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_password-policy-guest-admin": {
        "mkey_type": None,
        "mkey": "None",
    },
    "user_pop3": {
        "mkey_type": str,
        "mkey": "name",
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
    "system_admin": {
        "mkey_type": str,
        "mkey": "name",
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
    "ips_settings": {
        "mkey_type": None,
        "mkey": "None",
    },
    "log.syslogd_override-filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_vdom-exception": {
        "mkey_type": int,
        "mkey": "id",
    },
    "system_wccp": {
        "mkey_type": str,
        "mkey": "service_id",
    },
    "system_automation-stitch": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_profile-protocol-options": {
        "mkey_type": str,
        "mkey": "name",
    },
    "report_theme": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall.ssh_local-key": {
        "mkey_type": str,
        "mkey": "name",
    },
    "firewall_vip64": {
        "mkey_type": str,
        "mkey": "name",
    },
    "web-proxy_wisp": {
        "mkey_type": str,
        "mkey": "name",
    },
    "spamfilter_options": {
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
    "endpoint-control_client": {
        "mkey_type": int,
        "mkey": "id",
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
    "wireless-controller.hotspot20_anqp-3gpp-cellular": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system.replacemsg_ec": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "switch-controller_vlan": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_vxlan": {
        "mkey_type": str,
        "mkey": "name",
    },
    "webfilter_search-engine": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_ipv6-tunnel": {
        "mkey_type": str,
        "mkey": "name",
    },
    "certificate_local": {
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
    "system.replacemsg_nntp": {
        "mkey_type": str,
        "mkey": "msg_type",
    },
    "firewall_proxy-policy": {
        "mkey_type": int,
        "mkey": "policyid",
    },
    "system_dns": {
        "mkey_type": None,
        "mkey": "None",
    },
    "user_peergrp": {
        "mkey_type": str,
        "mkey": "name",
    },
    "vpn.ipsec_concentrator": {
        "mkey_type": str,
        "mkey": "name",
    },
    "ips_decoder": {
        "mkey_type": str,
        "mkey": "name",
    },
    "dnsfilter_domain-filter": {
        "mkey_type": int,
        "mkey": "id",
    },
    "wireless-controller_vap-group": {
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
    "firewall_interface-policy6": {
        "mkey_type": int,
        "mkey": "policyid",
    },
    "vpn.ipsec_manualkey": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch-controller_global": {
        "mkey_type": None,
        "mkey": "None",
    },
    "router_setting": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system.replacemsg_admin": {
        "mkey_type": str,
        "mkey": "msg_type",
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
    "user_domain-controller": {
        "mkey_type": str,
        "mkey": "name",
    },
    "router_multicast": {
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
    "system_fortimanager": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_mac-address-table": {
        "mkey_type": str,
        "mkey": "mac",
    },
    "log.fortianalyzer_filter": {
        "mkey_type": None,
        "mkey": "None",
    },
    "system_network-visibility": {
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
    "webfilter_urlfilter": {
        "mkey_type": int,
        "mkey": "id",
    },
    "system_probe-response": {
        "mkey_type": None,
        "mkey": "None",
    },
    "wireless-controller.hotspot20_h2qp-operator-name": {
        "mkey_type": str,
        "mkey": "name",
    },
    "switch-controller_sflow": {
        "mkey_type": None,
        "mkey": "None",
    },
    "webfilter_fortiguard": {
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
    "firewall.ssh_local-ca": {
        "mkey_type": str,
        "mkey": "name",
    },
    "spamfilter_dnsbl": {
        "mkey_type": int,
        "mkey": "id",
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
    "switch-controller_managed-switch": {
        "mkey_type": str,
        "mkey": "switch_id",
    },
    "user_group": {
        "mkey_type": str,
        "mkey": "name",
    },
    "user_krb-keytab": {
        "mkey_type": str,
        "mkey": "name",
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
        "mkey": "id",
    },
    "wireless-controller.hotspot20_h2qp-conn-capability": {
        "mkey_type": str,
        "mkey": "name",
    },
    "router_prefix-list": {
        "mkey_type": str,
        "mkey": "name",
    },
    "system_gre-tunnel": {
        "mkey_type": str,
        "mkey": "name",
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
                "router_route-map",
                "authentication_rule",
                "log.fortianalyzer_override-setting",
                "firewall.ssl_setting",
                "vpn.ipsec_phase2-interface",
                "router_key-chain",
                "system_ddns",
                "system_replacemsg-group",
                "system_ftm-push",
                "system_sms-server",
                "firewall_central-snat-map",
                "firewall_multicast-address6",
                "system.replacemsg_sslvpn",
                "system_pppoe-interface",
                "firewall_addrgrp6",
                "log.disk_filter",
                "system_affinity-packet-redistribution",
                "firewall_proxy-address",
                "router_bgp",
                "switch-controller_custom-command",
                "system_resource-limits",
                "system.replacemsg_auth",
                "system.autoupdate_schedule",
                "waf_sub-class",
                "firewall_local-in-policy6",
                "log.fortianalyzer_override-filter",
                "system.replacemsg_icap",
                "system_object-tagging",
                "spamfilter_profile",
                "spamfilter_bwl",
                "web-proxy_profile",
                "spamfilter_mheader",
                "user_adgrp",
                "system_auto-script",
                "switch-controller_quarantine",
                "firewall.service_category",
                "system_link-monitor",
                "switch-controller_stp-settings",
                "user_security-exempt-list",
                "switch-controller.qos_qos-policy",
                "firewall_sniffer",
                "log.fortiguard_override-setting",
                "firewall_internet-service",
                "firewall_vipgrp46",
                "log.webtrends_filter",
                "webfilter_ips-urlfilter-setting6",
                "router_prefix-list6",
                "log_setting",
                "firewall_address6-template",
                "wireless-controller.hotspot20_h2qp-wan-metric",
                "system_automation-action",
                "system.autoupdate_tunneling",
                "webfilter_ips-urlfilter-setting",
                "switch-controller_network-monitor-settings",
                "system_alias",
                "switch-controller_mac-sync-settings",
                "web-proxy_forward-server-group",
                "system_session-helper",
                "router_community-list",
                "wireless-controller_qos-profile",
                "firewall_dnstranslation",
                "vpn.ssl.web_portal",
                "system_vdom-property",
                "system.replacemsg_device-detection-portal",
                "log.syslogd2_setting",
                "firewall_internet-service-custom-group",
                "firewall_profile-group",
                "firewall.service_group",
                "system.autoupdate_push-update",
                "firewall_address6",
                "endpoint-control_profile",
                "wireless-controller_wids-profile",
                "log.fortiguard_filter",
                "firewall_ipv6-eh-filter",
                "user_device-category",
                "firewall_identity-based-route",
                "system_console",
                "system_ntp",
                "system_nat64",
                "system.3g-modem_custom",
                "report_layout",
                "wireless-controller_timers",
                "wireless-controller.hotspot20_icon",
                "log.memory_global-setting",
                "router_multicast-flow",
                "ssh-filter_profile",
                "system_fortisandbox",
                "system_virtual-wan-link",
                "ips_sensor",
                "firewall.wildcard-fqdn_custom",
                "router_static",
                "alertemail_setting",
                "user_fortitoken",
                "web-proxy_debug-url",
                "webfilter_override",
                "system_fsso-polling",
                "user_peer",
                "vpn.ssl.web_host-check-software",
                "switch-controller_lldp-profile",
                "vpn.ssl.web_realm",
                "system_stp",
                "switch-controller.security-policy_captive-portal",
                "firewall_shaping-policy",
                "log_custom-field",
                "firewall_address",
                "certificate_crl",
                "firewall.ssh_setting",
                "router_access-list",
                "log.memory_setting",
                "system_alarm",
                "system_ipv6-neighbor-cache",
                "system_cluster-sync",
                "wanopt_settings",
                "endpoint-control_registered-forticlient",
                "system_dedicated-mgmt",
                "firewall_policy46",
                "system_modem",
                "antivirus_settings",
                "switch-controller_802-1X-settings",
                "system_session-ttl",
                "system_storage",
                "log.memory_filter",
                "firewall_auth-portal",
                "system_sflow",
                "user_ldap",
                "ips_global",
                "wanopt_remote-storage",
                "wireless-controller.hotspot20_qos-map",
                "vpn_l2tp",
                "system_npu",
                "firewall_vip46",
                "authentication_setting",
                "vpn.certificate_ocsp-server",
                "antivirus_heuristic",
                "spamfilter_bword",
                "system_custom-language",
                "web-proxy_explicit",
                "wireless-controller_wtp-group",
                "system_vdom-sflow",
                "switch-controller_igmp-snooping",
                "waf_signature",
                "log.null-device_setting",
                "ips_rule-settings",
                "log.syslogd_setting",
                "switch-controller.security-policy_802-1X",
                "report_setting",
                "user_setting",
                "icap_profile",
                "system_geoip-override",
                "vpn.ipsec_phase1",
                "vpn.ipsec_phase2",
                "wireless-controller.hotspot20_anqp-network-auth-type",
                "webfilter_ips-urlfilter-cache-setting",
                "firewall.ipmacbinding_setting",
                "log.fortianalyzer2_filter",
                "application_rule-settings",
                "log.syslogd4_filter",
                "system_proxy-arp",
                "webfilter_ftgd-local-rating",
                "ips_custom",
                "switch-controller_switch-interface-tag",
                "router_policy6",
                "switch-controller.qos_ip-dscp-map",
                "log_eventfilter",
                "firewall_internet-service-custom",
                "router_auth-path",
                "system_external-resource",
                "system_ips-urlfilter-dns6",
                "report_style",
                "wireless-controller_wtp",
                "system_ipip-tunnel",
                "system.dhcp6_server",
                "firewall_multicast-policy",
                "vpn_ocvpn",
                "router_rip",
                "system_password-policy",
                "switch-controller_virtual-port-pool",
                "wireless-controller_setting",
                "router_static6",
                "wireless-controller.hotspot20_anqp-ip-address-type",
                "firewall_vipgrp",
                "switch-controller_switch-profile",
                "system_switch-interface",
                "router_isis",
                "firewall_policy",
                "log.syslogd_override-setting",
                "system_lte-modem",
                "webfilter_content",
                "firewall_vipgrp6",
                "firewall.schedule_onetime",
                "antivirus_profile",
                "log.fortianalyzer_setting",
                "firewall_ippool6",
                "system_central-management",
                "system.replacemsg_http",
                "system_zone",
                "system_vdom-dns",
                "firewall_multicast-address",
                "wireless-controller_wtp-profile",
                "vpn.ssl_settings",
                "router_ospf",
                "switch-controller.qos_queue-policy",
                "endpoint-control_forticlient-ems",
                "ftp-proxy_explicit",
                "user_device-group",
                "vpn.certificate_crl",
                "user_local",
                "webfilter_profile",
                "switch-controller_storm-control",
                "firewall_ssl-ssh-profile",
                "log.disk_setting",
                "dlp_filepattern",
                "firewall_ippool",
                "web-proxy_url-match",
                "dlp_fp-sensitivity",
                "system_interface",
                "router_bfd",
                "system_virtual-wire-pair",
                "system.replacemsg_webproxy",
                "user_password-policy",
                "wireless-controller_inter-controller",
                "log.syslogd4_setting",
                "switch-controller_switch-group",
                "user_fsso",
                "firewall_vipgrp64",
                "user_quarantine",
                "system_ips-urlfilter-dns",
                "system_fm",
                "system_global",
                "wireless-controller.hotspot20_anqp-nai-realm",
                "system_physical-switch",
                "log.fortianalyzer3_setting",
                "firewall_vip",
                "system_virtual-switch",
                "wanopt_auth-group",
                "wanopt_webcache",
                "system.snmp_user",
                "firewall_ip-translation",
                "system_settings",
                "log.fortianalyzer2_setting",
                "wireless-controller_vap",
                "wanopt_cache-service",
                "switch-controller_switch-log",
                "firewall_internet-service-group",
                "system.replacemsg_mail",
                "system_replacemsg-image",
                "antivirus_quarantine",
                "vpn.certificate_ca",
                "endpoint-control_forticlient-registration-sync",
                "system_sdn-connector",
                "vpn.ssl.web_user-group-bookmark",
                "endpoint-control_settings",
                "log.null-device_filter",
                "dlp_settings",
                "wireless-controller_utm-profile",
                "router_aspath-list",
                "firewall.schedule_group",
                "system_dscp-based-priority",
                "icap_server",
                "vpn.ipsec_phase1-interface",
                "authentication_scheme",
                "log.fortianalyzer3_filter",
                "system_email-server",
                "wireless-controller_ap-status",
                "application_list",
                "vpn.ssl.web_user-bookmark",
                "firewall.shaper_traffic-shaper",
                "system_management-tunnel",
                "system_csf",
                "firewall.shaper_per-ip-shaper",
                "dnsfilter_profile",
                "user_device-access-list",
                "system_ha-monitor",
                "wireless-controller.hotspot20_anqp-venue-name",
                "system.snmp_sysinfo",
                "application_custom",
                "system_api-user",
                "ips_rule",
                "spamfilter_fortishield",
                "system_netflow",
                "vpn.ipsec_forticlient",
                "system_automation-trigger",
                "firewall_policy64",
                "wireless-controller.hotspot20_h2qp-osu-provider",
                "application_name",
                "firewall.service_custom",
                "spamfilter_iptrust",
                "system_mobile-tunnel",
                "firewall_ttl-policy",
                "system.replacemsg_utm",
                "vpn_pptp",
                "wireless-controller.hotspot20_hs-profile",
                "log.webtrends_setting",
                "firewall_local-in-policy",
                "router_policy",
                "switch-controller.qos_dot1p-map",
                "firewall_multicast-policy6",
                "wanopt_content-delivery-network-rule",
                "system_dns-database",
                "waf_main-class",
                "system.replacemsg_nac-quar",
                "system_vdom-radius-server",
                "system_vdom",
                "user_tacacs+",
                "wanopt_peer",
                "log.syslogd3_setting",
                "report_dataset",
                "webfilter_ftgd-local-cat",
                "router_multicast6",
                "vpn.certificate_remote",
                "system_fips-cc",
                "system_ha",
                "log.syslogd3_filter",
                "user_radius",
                "firewall_DoS-policy6",
                "system_tos-based-priority",
                "vpn.certificate_local",
                "system_accprofile",
                "wireless-controller_global",
                "log.syslogd_filter",
                "dlp_sensor",
                "log.syslogd2_filter",
                "wireless-controller_ble-profile",
                "system_password-policy-guest-admin",
                "user_pop3",
                "switch-controller_system",
                "voip_profile",
                "vpn.ipsec_manualkey-interface",
                "system_vdom-netflow",
                "firewall.ipmacbinding_table",
                "system_automation-destination",
                "dlp_fp-doc-source",
                "firewall_ldb-monitor",
                "firewall.ssh_host-key",
                "system_vdom-link",
                "system_admin",
                "router_ospf6",
                "user_device",
                "log.fortiguard_setting",
                "system.snmp_community",
                "ips_settings",
                "log.syslogd_override-filter",
                "system_vdom-exception",
                "system_wccp",
                "system_automation-stitch",
                "firewall_profile-protocol-options",
                "report_theme",
                "firewall.ssh_local-key",
                "firewall_vip64",
                "web-proxy_wisp",
                "spamfilter_options",
                "system_dns-server",
                "system.replacemsg_alertmail",
                "log.fortiguard_override-filter",
                "endpoint-control_client",
                "system_fortiguard",
                "web-proxy_global",
                "wanopt_profile",
                "wireless-controller.hotspot20_anqp-3gpp-cellular",
                "system.replacemsg_ec",
                "switch-controller_vlan",
                "system_vxlan",
                "webfilter_search-engine",
                "system_ipv6-tunnel",
                "certificate_local",
                "user_fsso-polling",
                "system.dhcp_server",
                "report_chart",
                "vpn.certificate_setting",
                "router_bfd6",
                "system.replacemsg_nntp",
                "firewall_proxy-policy",
                "system_dns",
                "user_peergrp",
                "vpn.ipsec_concentrator",
                "ips_decoder",
                "dnsfilter_domain-filter",
                "wireless-controller_vap-group",
                "system_affinity-interrupt",
                "firewall_shaping-profile",
                "firewall_interface-policy6",
                "vpn.ipsec_manualkey",
                "switch-controller_global",
                "router_setting",
                "system.replacemsg_admin",
                "firewall.schedule_recurring",
                "system_sit-tunnel",
                "system_arp-table",
                "switch-controller_lldp-settings",
                "webfilter_content-header",
                "system_auto-install",
                "user_domain-controller",
                "router_multicast",
                "firewall_ssl-server",
                "system.replacemsg_traffic-quota",
                "system_fortimanager",
                "system_mac-address-table",
                "log.fortianalyzer_filter",
                "system_network-visibility",
                "firewall_interface-policy",
                "system.replacemsg_fortiguard-wf",
                "wireless-controller_bonjour-profile",
                "webfilter_urlfilter",
                "system_probe-response",
                "wireless-controller.hotspot20_h2qp-operator-name",
                "switch-controller_sflow",
                "webfilter_fortiguard",
                "wireless-controller.hotspot20_anqp-roaming-consortium",
                "firewall_DoS-policy",
                "firewall_proxy-addrgrp",
                "firewall_addrgrp",
                "firewall_policy6",
                "router_ripng",
                "firewall_vip6",
                "web-proxy_forward-server",
                "system.replacemsg_spam",
                "certificate_ca",
                "firewall.ssh_local-ca",
                "spamfilter_dnsbl",
                "router_access-list6",
                "waf_profile",
                "firewall.wildcard-fqdn_group",
                "switch-controller_managed-switch",
                "user_group",
                "user_krb-keytab",
                "application_group",
                "system.replacemsg_ftp",
                "log_threat-weight",
                "extender-controller_extender",
                "wireless-controller.hotspot20_h2qp-conn-capability",
                "router_prefix-list",
                "system_gre-tunnel",
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
