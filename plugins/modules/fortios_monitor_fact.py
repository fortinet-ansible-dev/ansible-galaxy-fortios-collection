#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
# Copyright 2020 Fortinet, Inc.
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
module: fortios_monitor_fact
version_added: "2.10"
short_description: Retrieve Facts of FortiOS Monitor Objects.
description:
    - Collects monitor facts from network devices running the fortios operating system.
      This facts module will only collect those facts which user specified in playbook.
author:
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@fshen01)
notes:
    - Different selector may have different parameters, users are expected to look up them for a specific selector.
    - For some selectors, the objects are global, no params are allowed to appear.
    - Not all parameters are required for a slector.
    - This module is exclusivly for FortiOS monitor API.
    - The result of API request is stored in results.
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
    selector:
        description:
            - selector of the retrieved fortimanager facts
        type: str
        required: true
        choices:
         - firewall_acl6
         - firewall_ippool
         - webfilter_malicious-urls
         - fortiguard_redirect-portal
         - firewall_policy-lookup
         - system_acquired-dns
         - wifi_interfering_ap
         - system_interface
         - firewall_address-dynamic
         - vpn_ocvpn_status
         - wifi_vlan-probe
         - system_sandbox_status
         - endpoint-control_ems_status
         - system_storage
         - router_ipv4
         - log_historic-daily-remote-logs
         - webfilter_malicious-urls_stat
         - ips_anomaly
         - wanopt_peer_stats
         - wifi_network_status
         - log_hourly-disk-usage
         - nsx_service_status
         - wifi_region-image
         - wifi_euclid
         - system_current-admins
         - system_sandbox_test-connect
         - system_interface_speed-test-status
         - user_info_query
         - wifi_rogue_ap
         - system_config-revision_info
         - utm_antivirus_stats
         - system_3g-modem
         - log_forticloud-report_download
         - firewall_address-fqdns
         - system_security-rating
         - user_fsso
         - system_botnet-domains
         - endpoint-control_installer
         - utm_app-lookup
         - system_firmware
         - system_interface_dhcp-status
         - wifi_client
         - system_botnet-domains_stat
         - firewall_address6-dynamic
         - webfilter_fortiguard-categories
         - firewall_shaper
         - firewall_internet-service-match
         - virtual-wan_sla-log
         - wifi_firmware
         - switch-controller_managed-switch_dhcp-snooping
         - system_time
         - system_fortimanager_backup-details
         - system_available-interfaces
         - system_fortimanager_status
         - system_sensor-info
         - system_status
         - nsx_instance
         - web-ui_custom-language_download
         - wanopt_history
         - log_forticloud
         - system_vdom-link
         - utm_blacklisted-certificates
         - webcache_stats
         - system_config-revision_file
         - user_device
         - system_dhcp
         - router_lookup
         - log_device_state
         - system_sniffer
         - system_firmware_upgrade-paths
         - system_sandbox_stats
         - wanopt_webcache
         - network_lldp_neighbors
         - log_local-report_download
         - firewall_load-balance
         - vpn_ocvpn_meta
         - system_sandbox_cloud-regions
         - firewall_address-fqdns6
         - firewall_acl
         - system_link-monitor
         - system_com-log_download
         - vpn_ocvpn_members
         - fortiguard_service-communication-stats
         - fortiview_sandbox-file-details
         - system_available-certificates
         - registration_forticloud_domains
         - switch-controller_fsw-firmware
         - fortiview_statistics
         - router_ipv6
         - firewall_uuid-list
         - router_statistics
         - system_config_usb-filelist
         - endpoint-control_ems_cert-status
         - system_config-script
         - user_banned
         - system_sdn-connector_nsx-security-tags
         - system_com-log_update
         - system_global-resources
         - firewall_per-ip-shaper
         - wifi_network_list
         - system_check-port-availability
         - log_current-disk-usage
         - license_status
         - firewall_session
         - virtual-wan_members
         - switch-controller_managed-switch_faceplate-xml
         - firewall_security-policy
         - endpoint-control_record-list
         - webfilter_category-quota
         - log_forticloud-report-list
         - log_policy-archive_download
         - system_ha-checksums
         - system_debug_download
         - log_fortianalyzer-queue
         - system_ipconf
         - system_nat46-ippools
         - system_vdom-resource
         - system_modem
         - firewall_proxy-policy
         - network_ddns_servers
         - endpoint-control_installer_download
         - system_fortiguard_server-info
         - user_info_thumbnail
         - system_sdn-connector_status
         - vpn_ipsec
         - switch-controller_validate-switch-prefix
         - system_security-rating_history
         - endpoint-control_summary
         - system_csf
         - license_forticare-resellers
         - wifi_ap_status
         - utm_application-categories
         - router_lookup-policy
         - system_ha-history
         - webproxy_pacfile_download
         - system_security-rating_lang
         - system_interface_poe
         - system_timezone
         - firewall_sdn-connector-filters
         - webfilter_trusted-urls
         - system_usb-log
         - router_policy6
         - firewall_policy
         - system_ha-statistics
         - network_dns_latency
         - system_fortimanager_backup-summary
         - system_sniffer_download
         - user_detected-device
         - system_botnet_stat
         - system_vm-information
         - system_security-rating_supported-reports
         - user_fortitoken
         - system_botnet
         - vpn_ssl_stats
         - switch-controller_managed-switch_transceivers
         - webfilter_override
         - log_stats
         - system_csf_pending-authorizations
         - system_resolve-fqdn
         - log_fortianalyzer
         - log_ips-archive_download
         - network_ddns_lookup
         - system_config-revision
         - user_collected-email
         - ips_rate-based
         - switch-controller_detected-device
         - license_forticare-org-list
         - registration_forticloud_device-status
         - router_policy
         - user_firewall
         - system_automation-stitch_stats
         - wifi_managed_ap
         - system_interface_transceivers
         - system_config_backup
         - firewall_uuid-type-lookup
         - virtual-wan_interface-log
         - utm_blacklisted-certificates_statistics
         - firewall_health
         - system_security-rating_status
         - registration_forticloud_disclaimer
         - system_botnet-domains_hits
         - firewall_internet-service-details
         - log_event
         - system_config-sync_status
         - network_fortiguard_live-services-latency
         - fortiview_sandbox-file-list
         - system_trusted-cert-authorities
         - vpn_ssl
         - log_av-archive_download
         - license_fortianalyzer-status
         - virtual-wan_health-check
         - log_local-report-list
         - endpoint-control_avatar_download
         - system_resource_usage
         - system_certificate_download
         - system_ha-peer
         - network_lldp_ports
         - ips_metadata
         - extender-controller_extender
         - firewall_local-in
         - wifi_spectrum
         - network_reverse-ip-lookup
         - switch-controller_managed-switch
         - system_object_usage

    params:
        description:
            - the parameter for each selector, see definition in above list.
        type: dict
        required: false
'''

EXAMPLES = '''
- hosts: fortigate03
  connection: httpapi
  collections:
  - fortinet.fortios
  vars:
   vdom: "root"
   ansible_httpapi_use_ssl: yes
   ansible_httpapi_validate_certs: no
   ansible_httpapi_port: 443
  tasks:

  - name: fact gathering
    fortios_monitor_fact:
       vdom: ""
       access_token: ""
       selector: 'firewall_acl'

  - name: fact gathering
    fortios_monitor_fact:
       vdom: ""
       access_token: ""
       selector: 'firewall_security-policy'
       params:
           policyid: '1'
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

'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import FortiOSHandler
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import check_legacy_fortiosapi
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import FAIL_SOCKET_MSG

module_selectors_defs = {
    "firewall_acl6": {
        "url": "firewall/acl6",
        "params": {
        }
    },
    "firewall_ippool": {
        "url": "firewall/ippool",
        "params": {
        }
    },
    "webfilter_malicious-urls": {
        "url": "webfilter/malicious-urls",
        "params": {
        }
    },
    "fortiguard_redirect-portal": {
        "url": "fortiguard/redirect-portal",
        "params": {
        }
    },
    "firewall_policy-lookup": {
        "url": "firewall/policy-lookup",
        "params": {
            "protocol": {
                "type": "string"
            },
            "dest": {
                "type": "string"
            },
            "icmpcode": {
                "type": "int"
            },
            "icmptype": {
                "type": "int"
            },
            "srcintf": {
                "type": "string"
            },
            "ipv6": {
                "type": "boolean"
            },
            "sourceport": {
                "type": "int"
            },
            "sourceip": {
                "type": "string"
            },
            "destport": {
                "type": "int"
            }
        }
    },
    "system_acquired-dns": {
        "url": "system/acquired-dns",
        "params": {
        }
    },
    "wifi_interfering_ap": {
        "url": "wifi/interfering_ap",
        "params": {
            "wtp": {
                "type": "string"
            },
            "start": {
                "type": "int"
            },
            "radio": {
                "type": "int"
            },
            "count": {
                "type": "int"
            }
        }
    },
    "system_interface": {
        "url": "system/interface",
        "params": {
            "scope": {
                "type": "string"
            },
            "interface_name": {
                "type": "string"
            },
            "include_vlan": {
                "type": "boolean"
            },
            "include_aggregate": {
                "type": "boolean"
            }
        }
    },
    "firewall_address-dynamic": {
        "url": "firewall/address-dynamic",
        "params": {
        }
    },
    "vpn_ocvpn_status": {
        "url": "vpn/ocvpn/status",
        "params": {
        }
    },
    "wifi_vlan-probe": {
        "url": "wifi/vlan-probe",
        "params": {
            "wtp": {
                "type": "string"
            },
            "ap_interface": {
                "type": "int"
            }
        }
    },
    "system_sandbox_status": {
        "url": "system/sandbox/status",
        "params": {
        }
    },
    "endpoint-control_ems_status": {
        "url": "endpoint-control/ems/status",
        "params": {
            "ems_name": {
                "type": "string"
            }
        }
    },
    "system_storage": {
        "url": "system/storage",
        "params": {
        }
    },
    "router_ipv4": {
        "url": "router/ipv4",
        "params": {
            "count": {
                "type": "int"
            },
            "ip_mask": {
                "type": "string"
            },
            "start": {
                "type": "int"
            },
            "interface": {
                "type": "string"
            },
            "type": {
                "type": "string"
            },
            "gateway": {
                "type": "string"
            }
        }
    },
    "log_historic-daily-remote-logs": {
        "url": "log/historic-daily-remote-logs",
        "params": {
            "server": {
                "type": "string"
            }
        }
    },
    "webfilter_malicious-urls_stat": {
        "url": "webfilter/malicious-urls/stat",
        "params": {
        }
    },
    "ips_anomaly": {
        "url": "ips/anomaly",
        "params": {
        }
    },
    "wanopt_peer_stats": {
        "url": "wanopt/peer_stats",
        "params": {
        }
    },
    "wifi_network_status": {
        "url": "wifi/network/status",
        "params": {
        }
    },
    "log_hourly-disk-usage": {
        "url": "log/hourly-disk-usage",
        "params": {
        }
    },
    "nsx_service_status": {
        "url": "nsx/service/status",
        "params": {
            "mkey": {
                "type": "string"
            }
        }
    },
    "wifi_region-image": {
        "url": "wifi/region-image",
        "params": {
            "region_name": {
                "type": "string"
            }
        }
    },
    "wifi_euclid": {
        "url": "wifi/euclid",
        "params": {
        }
    },
    "system_current-admins": {
        "url": "system/current-admins",
        "params": {
        }
    },
    "system_sandbox_test-connect": {
        "url": "system/sandbox/test-connect",
        "params": {
            "server": {
                "type": "string"
            }
        }
    },
    "system_interface_speed-test-status": {
        "url": "system/interface/speed-test-status",
        "params": {
            "id": {
                "type": "int"
            }
        }
    },
    "user_info_query": {
        "url": "user/info/query",
        "params": {
            "keys": {
                "type": "array"
            },
            "start": {
                "type": "int"
            },
            "number": {
                "type": "int"
            },
            "filters": {
                "type": "array"
            }
        }
    },
    "wifi_rogue_ap": {
        "url": "wifi/rogue_ap",
        "params": {
            "count": {
                "type": "int"
            },
            "start": {
                "type": "int"
            }
        }
    },
    "system_config-revision_info": {
        "url": "system/config-revision/info",
        "params": {
            "config_id": {
                "type": "int"
            }
        }
    },
    "utm_antivirus_stats": {
        "url": "utm/antivirus/stats",
        "params": {
        }
    },
    "system_3g-modem": {
        "url": "system/3g-modem",
        "params": {
        }
    },
    "log_forticloud-report_download": {
        "url": "log/forticloud-report/download",
        "params": {
            "inline": {
                "type": "int"
            },
            "mkey": {
                "type": "int"
            }
        }
    },
    "firewall_address-fqdns": {
        "url": "firewall/address-fqdns",
        "params": {
        }
    },
    "system_security-rating": {
        "url": "system/security-rating",
        "params": {
            "scope": {
                "type": "string"
            },
            "id": {
                "type": "int"
            },
            "report_type": {
                "type": "string"
            }
        }
    },
    "user_fsso": {
        "url": "user/fsso",
        "params": {
            "type": {
                "type": "string"
            },
            "mkey": {
                "type": "string"
            }
        }
    },
    "system_botnet-domains": {
        "url": "system/botnet-domains",
        "params": {
            "count": {
                "type": "int"
            },
            "start": {
                "type": "int"
            }
        }
    },
    "endpoint-control_installer": {
        "url": "endpoint-control/installer",
        "params": {
            "min_version": {
                "type": "string"
            }
        }
    },
    "utm_app-lookup": {
        "url": "utm/app-lookup",
        "params": {
            "hosts": {
                "type": "array"
            }
        }
    },
    "system_firmware": {
        "url": "system/firmware",
        "params": {
        }
    },
    "system_interface_dhcp-status": {
        "url": "system/interface/dhcp-status",
        "params": {
            "mkey": {
                "type": "string"
            }
        }
    },
    "wifi_client": {
        "url": "wifi/client",
        "params": {
            "count": {
                "type": "int"
            },
            "start": {
                "type": "int"
            },
            "type": {
                "type": "string"
            }
        }
    },
    "system_botnet-domains_stat": {
        "url": "system/botnet-domains/stat",
        "params": {
        }
    },
    "firewall_address6-dynamic": {
        "url": "firewall/address6-dynamic",
        "params": {
        }
    },
    "webfilter_fortiguard-categories": {
        "url": "webfilter/fortiguard-categories",
        "params": {
            "convert_unrated_id": {
                "type": "boolean"
            },
            "include_unrated": {
                "type": "boolean"
            }
        }
    },
    "firewall_shaper": {
        "url": "firewall/shaper",
        "params": {
        }
    },
    "firewall_internet-service-match": {
        "url": "firewall/internet-service-match",
        "params": {
            "ip": {
                "type": "string"
            },
            "mask": {
                "type": "string"
            }
        }
    },
    "virtual-wan_sla-log": {
        "url": "virtual-wan/sla-log",
        "params": {
            "interface": {
                "type": "string"
            },
            "seconds": {
                "type": "int"
            },
            "since": {
                "type": "int"
            },
            "sla": {
                "type": "string"
            }
        }
    },
    "wifi_firmware": {
        "url": "wifi/firmware",
        "params": {
            "timeout": {
                "type": "string"
            }
        }
    },
    "switch-controller_managed-switch_dhcp-snooping": {
        "url": "switch-controller/managed-switch/dhcp-snooping",
        "params": {
        }
    },
    "system_time": {
        "url": "system/time",
        "params": {
        }
    },
    "system_fortimanager_backup-details": {
        "url": "system/fortimanager/backup-details",
        "params": {
            "datasource": {
                "type": "string"
            },
            "mkey": {
                "type": "string"
            }
        }
    },
    "system_available-interfaces": {
        "url": "system/available-interfaces",
        "params": {
            "scope": {
                "type": "string"
            },
            "view_type": {
                "type": "string"
            }
        }
    },
    "system_fortimanager_status": {
        "url": "system/fortimanager/status",
        "params": {
        }
    },
    "system_sensor-info": {
        "url": "system/sensor-info",
        "params": {
        }
    },
    "system_status": {
        "url": "system/status",
        "params": {
        }
    },
    "nsx_instance": {
        "url": "nsx/instance",
        "params": {
            "mkey": {
                "type": "string"
            }
        }
    },
    "web-ui_custom-language_download": {
        "url": "web-ui/custom-language/download",
        "params": {
            "filename": {
                "type": "string"
            }
        }
    },
    "wanopt_history": {
        "url": "wanopt/history",
        "params": {
            "period": {
                "type": "string"
            }
        }
    },
    "log_forticloud": {
        "url": "log/forticloud",
        "params": {
        }
    },
    "system_vdom-link": {
        "url": "system/vdom-link",
        "params": {
            "scope": {
                "type": "string"
            }
        }
    },
    "utm_blacklisted-certificates": {
        "url": "utm/blacklisted-certificates",
        "params": {
            "count": {
                "type": "int"
            },
            "start": {
                "type": "int"
            }
        }
    },
    "webcache_stats": {
        "url": "webcache/stats",
        "params": {
            "period": {
                "type": "string"
            }
        }
    },
    "system_config-revision_file": {
        "url": "system/config-revision/file",
        "params": {
            "config_id": {
                "type": "int"
            }
        }
    },
    "user_device": {
        "url": "user/device",
        "params": {
            "master_mac": {
                "type": "string"
            },
            "master_only": {
                "type": "boolean"
            }
        }
    },
    "system_dhcp": {
        "url": "system/dhcp",
        "params": {
            "interface": {
                "type": "string"
            },
            "scope": {
                "type": "string"
            },
            "ipv6": {
                "type": "boolean"
            }
        }
    },
    "router_lookup": {
        "url": "router/lookup",
        "params": {
            "destination": {
                "type": "string"
            },
            "ipv6": {
                "type": "boolean"
            }
        }
    },
    "log_device_state": {
        "url": "log/device/state",
        "params": {
        }
    },
    "system_sniffer": {
        "url": "system/sniffer",
        "params": {
        }
    },
    "system_firmware_upgrade-paths": {
        "url": "system/firmware/upgrade-paths",
        "params": {
        }
    },
    "system_sandbox_stats": {
        "url": "system/sandbox/stats",
        "params": {
        }
    },
    "wanopt_webcache": {
        "url": "wanopt/webcache",
        "params": {
            "period": {
                "type": "string"
            }
        }
    },
    "network_lldp_neighbors": {
        "url": "network/lldp/neighbors",
        "params": {
        }
    },
    "log_local-report_download": {
        "url": "log/local-report/download",
        "params": {
            "mkey": {
                "type": "string"
            }
        }
    },
    "firewall_load-balance": {
        "url": "firewall/load-balance",
        "params": {
            "count": {
                "type": "int"
            },
            "start": {
                "type": "int"
            }
        }
    },
    "vpn_ocvpn_meta": {
        "url": "vpn/ocvpn/meta",
        "params": {
        }
    },
    "system_sandbox_cloud-regions": {
        "url": "system/sandbox/cloud-regions",
        "params": {
        }
    },
    "firewall_address-fqdns6": {
        "url": "firewall/address-fqdns6",
        "params": {
        }
    },
    "firewall_acl": {
        "url": "firewall/acl",
        "params": {
        }
    },
    "system_link-monitor": {
        "url": "system/link-monitor",
        "params": {
            "mkey": {
                "type": "string"
            }
        }
    },
    "system_com-log_download": {
        "url": "system/com-log/download",
        "params": {
        }
    },
    "vpn_ocvpn_members": {
        "url": "vpn/ocvpn/members",
        "params": {
        }
    },
    "fortiguard_service-communication-stats": {
        "url": "fortiguard/service-communication-stats",
        "params": {
            "service_type": {
                "type": "string"
            },
            "timeslot": {
                "type": "string"
            }
        }
    },
    "fortiview_sandbox-file-details": {
        "url": "fortiview/sandbox-file-details",
        "params": {
            "checksum": {
                "type": "string"
            }
        }
    },
    "system_available-certificates": {
        "url": "system/available-certificates",
        "params": {
            "scope": {
                "type": "string"
            },
            "with_remote": {
                "type": "boolean"
            },
            "with_ca": {
                "type": "boolean"
            },
            "with_crl": {
                "type": "boolean"
            }
        }
    },
    "registration_forticloud_domains": {
        "url": "registration/forticloud/domains",
        "params": {
        }
    },
    "switch-controller_fsw-firmware": {
        "url": "switch-controller/fsw-firmware",
        "params": {
            "timeout": {
                "type": "string"
            },
            "mkey": {
                "type": "string"
            }
        }
    },
    "fortiview_statistics": {
        "url": "fortiview/statistics",
        "params": {
            "count": {
                "type": "int"
            },
            "end": {
                "type": "int"
            },
            "realtime": {
                "type": "boolean"
            },
            "chart_only": {
                "type": "boolean"
            },
            "sort_by": {
                "type": "string"
            },
            "filter": {
                "type": "object"
            },
            "start": {
                "type": "int"
            },
            "sessionid": {
                "type": "int"
            },
            "report_by": {
                "type": "string"
            },
            "device": {
                "type": "string"
            },
            "ip_version": {
                "type": "string"
            }
        }
    },
    "router_ipv6": {
        "url": "router/ipv6",
        "params": {
            "count": {
                "type": "int"
            },
            "ip_mask": {
                "type": "string"
            },
            "start": {
                "type": "int"
            },
            "interface": {
                "type": "string"
            },
            "type": {
                "type": "string"
            },
            "gateway": {
                "type": "string"
            }
        }
    },
    "firewall_uuid-list": {
        "url": "firewall/uuid-list",
        "params": {
        }
    },
    "router_statistics": {
        "url": "router/statistics",
        "params": {
            "ip_version": {
                "type": "int"
            },
            "ip_mask": {
                "type": "string"
            },
            "interface": {
                "type": "string"
            },
            "type": {
                "type": "string"
            },
            "gateway": {
                "type": "string"
            }
        }
    },
    "system_config_usb-filelist": {
        "url": "system/config/usb-filelist",
        "params": {
        }
    },
    "endpoint-control_ems_cert-status": {
        "url": "endpoint-control/ems/cert-status",
        "params": {
            "with_cert": {
                "type": "boolean"
            },
            "ems_name": {
                "type": "string"
            }
        }
    },
    "system_config-script": {
        "url": "system/config-script",
        "params": {
        }
    },
    "user_banned": {
        "url": "user/banned",
        "params": {
        }
    },
    "system_sdn-connector_nsx-security-tags": {
        "url": "system/sdn-connector/nsx-security-tags",
        "params": {
            "mkey": {
                "type": "string"
            }
        }
    },
    "system_com-log_update": {
        "url": "system/com-log/update",
        "params": {
        }
    },
    "system_global-resources": {
        "url": "system/global-resources",
        "params": {
        }
    },
    "firewall_per-ip-shaper": {
        "url": "firewall/per-ip-shaper",
        "params": {
        }
    },
    "wifi_network_list": {
        "url": "wifi/network/list",
        "params": {
        }
    },
    "system_check-port-availability": {
        "url": "system/check-port-availability",
        "params": {
            "port_ranges": {
                "type": "array"
            },
            "service": {
                "type": "string"
            }
        }
    },
    "log_current-disk-usage": {
        "url": "log/current-disk-usage",
        "params": {
        }
    },
    "license_status": {
        "url": "license/status",
        "params": {
        }
    },
    "firewall_session": {
        "url": "firewall/session",
        "params": {
            "since": {
                "type": "int"
            },
            "protocol": {
                "type": "string"
            },
            "nturbo": {
                "type": "int"
            },
            "srcintfrole": {
                "type": "array"
            },
            "owner": {
                "type": "string"
            },
            "srcuuid": {
                "type": "string"
            },
            "dstintfrole": {
                "type": "array"
            },
            "natsourceaddress": {
                "type": "string"
            },
            "source": {
                "type": "string"
            },
            "destination": {
                "type": "string"
            },
            "application": {
                "type": "string"
            },
            "sourceport": {
                "type": "int"
            },
            "natsourceport": {
                "type": "int"
            },
            "start": {
                "type": "int"
            },
            "dstuuid": {
                "type": "string"
            },
            "username": {
                "type": "string"
            },
            "seconds": {
                "type": "int"
            },
            "policyid": {
                "type": "int"
            },
            "srcintf": {
                "type": "string"
            },
            "fortiasic": {
                "type": "int"
            },
            "destport": {
                "type": "int"
            },
            "count": {
                "type": "int"
            },
            "filter-csf": {
                "type": "boolean"
            },
            "country": {
                "type": "string"
            },
            "summary": {
                "type": "boolean"
            },
            "shaper": {
                "type": "string"
            },
            "ip_version": {
                "type": "string"
            },
            "dstintf": {
                "type": "string"
            }
        }
    },
    "virtual-wan_members": {
        "url": "virtual-wan/members",
        "params": {
        }
    },
    "switch-controller_managed-switch_faceplate-xml": {
        "url": "switch-controller/managed-switch/faceplate-xml",
        "params": {
            "mkey": {
                "type": "string"
            }
        }
    },
    "firewall_security-policy": {
        "url": "firewall/security-policy",
        "params": {
            "policyid": {
                "type": "int"
            }
        }
    },
    "endpoint-control_record-list": {
        "url": "endpoint-control/record-list",
        "params": {
            "intf_name": {
                "type": "string"
            }
        }
    },
    "webfilter_category-quota": {
        "url": "webfilter/category-quota",
        "params": {
            "profile": {
                "type": "string"
            },
            "user": {
                "type": "string"
            }
        }
    },
    "log_forticloud-report-list": {
        "url": "log/forticloud-report-list",
        "params": {
        }
    },
    "log_policy-archive_download": {
        "url": "log/policy-archive/download",
        "params": {
            "srcip": {
                "type": "string"
            },
            "dstip": {
                "type": "string"
            },
            "mkey": {
                "type": "int"
            }
        }
    },
    "system_ha-checksums": {
        "url": "system/ha-checksums",
        "params": {
        }
    },
    "system_debug_download": {
        "url": "system/debug/download",
        "params": {
        }
    },
    "log_fortianalyzer-queue": {
        "url": "log/fortianalyzer-queue",
        "params": {
            "scope": {
                "type": "string"
            }
        }
    },
    "system_ipconf": {
        "url": "system/ipconf",
        "params": {
            "devs": {
                "type": "array"
            },
            "ipaddr": {
                "type": "string"
            }
        }
    },
    "system_nat46-ippools": {
        "url": "system/nat46-ippools",
        "params": {
        }
    },
    "system_vdom-resource": {
        "url": "system/vdom-resource",
        "params": {
        }
    },
    "system_modem": {
        "url": "system/modem",
        "params": {
        }
    },
    "firewall_proxy-policy": {
        "url": "firewall/proxy-policy",
        "params": {
            "policyid": {
                "type": "int"
            }
        }
    },
    "network_ddns_servers": {
        "url": "network/ddns/servers",
        "params": {
        }
    },
    "endpoint-control_installer_download": {
        "url": "endpoint-control/installer/download",
        "params": {
            "mkey": {
                "type": "string"
            }
        }
    },
    "system_fortiguard_server-info": {
        "url": "system/fortiguard/server-info",
        "params": {
        }
    },
    "user_info_thumbnail": {
        "url": "user/info/thumbnail",
        "params": {
            "filters": {
                "type": "array"
            }
        }
    },
    "system_sdn-connector_status": {
        "url": "system/sdn-connector/status",
        "params": {
            "type": {
                "type": "string"
            },
            "mkey": {
                "type": "string"
            }
        }
    },
    "vpn_ipsec": {
        "url": "vpn/ipsec",
        "params": {
            "tunnel": {
                "type": "string"
            },
            "start": {
                "type": "int"
            },
            "count": {
                "type": "int"
            }
        }
    },
    "switch-controller_validate-switch-prefix": {
        "url": "switch-controller/validate-switch-prefix",
        "params": {
            "prefix": {
                "type": "string"
            }
        }
    },
    "system_security-rating_history": {
        "url": "system/security-rating/history",
        "params": {
            "report_type": {
                "type": "string"
            }
        }
    },
    "endpoint-control_summary": {
        "url": "endpoint-control/summary",
        "params": {
        }
    },
    "system_csf": {
        "url": "system/csf",
        "params": {
            "scope": {
                "type": "string"
            }
        }
    },
    "license_forticare-resellers": {
        "url": "license/forticare-resellers",
        "params": {
            "country_code": {
                "type": "int"
            }
        }
    },
    "wifi_ap_status": {
        "url": "wifi/ap_status",
        "params": {
        }
    },
    "utm_application-categories": {
        "url": "utm/application-categories",
        "params": {
        }
    },
    "router_lookup-policy": {
        "url": "router/lookup-policy",
        "params": {
            "protocol_number": {
                "type": "int"
            },
            "destination": {
                "type": "string"
            },
            "source": {
                "type": "string"
            },
            "ipv6": {
                "type": "boolean"
            },
            "destination_port": {
                "type": "int"
            },
            "interface_name": {
                "type": "string"
            }
        }
    },
    "system_ha-history": {
        "url": "system/ha-history",
        "params": {
        }
    },
    "webproxy_pacfile_download": {
        "url": "webproxy/pacfile/download",
        "params": {
        }
    },
    "system_security-rating_lang": {
        "url": "system/security-rating/lang",
        "params": {
            "key": {
                "type": "string"
            }
        }
    },
    "system_interface_poe": {
        "url": "system/interface/poe",
        "params": {
            "scope": {
                "type": "string"
            },
            "mkey": {
                "type": "string"
            }
        }
    },
    "system_timezone": {
        "url": "system/timezone",
        "params": {
        }
    },
    "firewall_sdn-connector-filters": {
        "url": "firewall/sdn-connector-filters",
        "params": {
            "connector": {
                "type": "string"
            }
        }
    },
    "webfilter_trusted-urls": {
        "url": "webfilter/trusted-urls",
        "params": {
        }
    },
    "system_usb-log": {
        "url": "system/usb-log",
        "params": {
        }
    },
    "router_policy6": {
        "url": "router/policy6",
        "params": {
            "count": {
                "type": "int"
            },
            "start": {
                "type": "int"
            },
            "count_only": {
                "type": "boolean"
            }
        }
    },
    "firewall_policy": {
        "url": "firewall/policy",
        "params": {
            "ip_version": {
                "type": "string"
            },
            "policyid": {
                "type": "int"
            }
        }
    },
    "system_ha-statistics": {
        "url": "system/ha-statistics",
        "params": {
        }
    },
    "network_dns_latency": {
        "url": "network/dns/latency",
        "params": {
        }
    },
    "system_fortimanager_backup-summary": {
        "url": "system/fortimanager/backup-summary",
        "params": {
        }
    },
    "system_sniffer_download": {
        "url": "system/sniffer/download",
        "params": {
            "mkey": {
                "type": "int"
            }
        }
    },
    "user_detected-device": {
        "url": "user/detected-device",
        "params": {
            "with_fortiap": {
                "type": "boolean"
            },
            "with_user": {
                "type": "boolean"
            },
            "with_endpoint": {
                "type": "boolean"
            },
            "with_dhcp": {
                "type": "boolean"
            },
            "expand_child_macs": {
                "type": "boolean"
            },
            "with_fortilink": {
                "type": "boolean"
            }
        }
    },
    "system_botnet_stat": {
        "url": "system/botnet/stat",
        "params": {
        }
    },
    "system_vm-information": {
        "url": "system/vm-information",
        "params": {
        }
    },
    "system_security-rating_supported-reports": {
        "url": "system/security-rating/supported-reports",
        "params": {
        }
    },
    "user_fortitoken": {
        "url": "user/fortitoken",
        "params": {
        }
    },
    "system_botnet": {
        "url": "system/botnet",
        "params": {
            "count": {
                "type": "int"
            },
            "start": {
                "type": "int"
            },
            "include_hit_only": {
                "type": "boolean"
            }
        }
    },
    "vpn_ssl_stats": {
        "url": "vpn/ssl/stats",
        "params": {
        }
    },
    "switch-controller_managed-switch_transceivers": {
        "url": "switch-controller/managed-switch/transceivers",
        "params": {
        }
    },
    "webfilter_override": {
        "url": "webfilter/override",
        "params": {
        }
    },
    "log_stats": {
        "url": "log/stats",
        "params": {
            "dev": {
                "type": "string"
            }
        }
    },
    "system_csf_pending-authorizations": {
        "url": "system/csf/pending-authorizations",
        "params": {
        }
    },
    "system_resolve-fqdn": {
        "url": "system/resolve-fqdn",
        "params": {
            "fqdn": {
                "type": "array"
            },
            "ipv6": {
                "type": "boolean"
            }
        }
    },
    "log_fortianalyzer": {
        "url": "log/fortianalyzer",
        "params": {
            "srcip": {
                "type": "string"
            },
            "scope": {
                "type": "string"
            },
            "server": {
                "type": "string"
            }
        }
    },
    "log_ips-archive_download": {
        "url": "log/ips-archive/download",
        "params": {
            "pcap_no": {
                "type": "int"
            },
            "pcap_category": {
                "type": "int"
            },
            "mkey": {
                "type": "int"
            }
        }
    },
    "network_ddns_lookup": {
        "url": "network/ddns/lookup",
        "params": {
            "domain": {
                "type": "string"
            }
        }
    },
    "system_config-revision": {
        "url": "system/config-revision",
        "params": {
        }
    },
    "user_collected-email": {
        "url": "user/collected-email",
        "params": {
            "ipv6": {
                "type": "boolean"
            }
        }
    },
    "ips_rate-based": {
        "url": "ips/rate-based",
        "params": {
        }
    },
    "switch-controller_detected-device": {
        "url": "switch-controller/detected-device",
        "params": {
        }
    },
    "license_forticare-org-list": {
        "url": "license/forticare-org-list",
        "params": {
        }
    },
    "registration_forticloud_device-status": {
        "url": "registration/forticloud/device-status",
        "params": {
            "serials": {
                "type": "array"
            },
            "update_cache": {
                "type": "array"
            }
        }
    },
    "router_policy": {
        "url": "router/policy",
        "params": {
            "count": {
                "type": "int"
            },
            "start": {
                "type": "int"
            },
            "count_only": {
                "type": "boolean"
            }
        }
    },
    "user_firewall": {
        "url": "user/firewall",
        "params": {
            "count": {
                "type": "int"
            },
            "start": {
                "type": "int"
            },
            "ipv4": {
                "type": "boolean"
            },
            "ipv6": {
                "type": "boolean"
            }
        }
    },
    "system_automation-stitch_stats": {
        "url": "system/automation-stitch/stats",
        "params": {
            "mkey": {
                "type": "string"
            }
        }
    },
    "wifi_managed_ap": {
        "url": "wifi/managed_ap",
        "params": {
            "incl_local": {
                "type": "boolean"
            },
            "wtp_id": {
                "type": "string"
            }
        }
    },
    "system_interface_transceivers": {
        "url": "system/interface/transceivers",
        "params": {
            "scope": {
                "type": "string"
            }
        }
    },
    "system_config_backup": {
        "url": "system/config/backup",
        "params": {
            "password": {
                "type": "string"
            },
            "usb_filename": {
                "type": "string"
            },
            "destination": {
                "type": "string"
            },
            "vdom": {
                "type": "string"
            },
            "scope": {
                "type": "string"
            }
        }
    },
    "firewall_uuid-type-lookup": {
        "url": "firewall/uuid-type-lookup",
        "params": {
            "uuids": {
                "type": "array"
            }
        }
    },
    "virtual-wan_interface-log": {
        "url": "virtual-wan/interface-log",
        "params": {
            "interface": {
                "type": "string"
            },
            "seconds": {
                "type": "int"
            },
            "since": {
                "type": "int"
            }
        }
    },
    "utm_blacklisted-certificates_statistics": {
        "url": "utm/blacklisted-certificates/statistics",
        "params": {
        }
    },
    "firewall_health": {
        "url": "firewall/health",
        "params": {
        }
    },
    "system_security-rating_status": {
        "url": "system/security-rating/status",
        "params": {
            "progress": {
                "type": "boolean"
            },
            "id": {
                "type": "int"
            },
            "report_type": {
                "type": "string"
            }
        }
    },
    "registration_forticloud_disclaimer": {
        "url": "registration/forticloud/disclaimer",
        "params": {
        }
    },
    "system_botnet-domains_hits": {
        "url": "system/botnet-domains/hits",
        "params": {
        }
    },
    "firewall_internet-service-details": {
        "url": "firewall/internet-service-details",
        "params": {
            "count": {
                "type": "int"
            },
            "region_id": {
                "type": "int"
            },
            "summary_only": {
                "type": "boolean"
            },
            "city_id": {
                "type": "int"
            },
            "country_id": {
                "type": "int"
            },
            "start": {
                "type": "int"
            },
            "id": {
                "type": "int"
            }
        }
    },
    "log_event": {
        "url": "log/event",
        "params": {
        }
    },
    "system_config-sync_status": {
        "url": "system/config-sync/status",
        "params": {
        }
    },
    "network_fortiguard_live-services-latency": {
        "url": "network/fortiguard/live-services-latency",
        "params": {
        }
    },
    "fortiview_sandbox-file-list": {
        "url": "fortiview/sandbox-file-list",
        "params": {
        }
    },
    "system_trusted-cert-authorities": {
        "url": "system/trusted-cert-authorities",
        "params": {
            "scope": {
                "type": "string"
            }
        }
    },
    "vpn_ssl": {
        "url": "vpn/ssl",
        "params": {
        }
    },
    "log_av-archive_download": {
        "url": "log/av-archive/download",
        "params": {
            "mkey": {
                "type": "string"
            }
        }
    },
    "license_fortianalyzer-status": {
        "url": "license/fortianalyzer-status",
        "params": {
        }
    },
    "virtual-wan_health-check": {
        "url": "virtual-wan/health-check",
        "params": {
        }
    },
    "log_local-report-list": {
        "url": "log/local-report-list",
        "params": {
        }
    },
    "endpoint-control_avatar_download": {
        "url": "endpoint-control/avatar/download",
        "params": {
            "default": {
                "type": "string"
            },
            "uid": {
                "type": "string"
            },
            "user": {
                "type": "string"
            }
        }
    },
    "system_resource_usage": {
        "url": "system/resource/usage",
        "params": {
            "scope": {
                "type": "string"
            },
            "interval": {
                "type": "string"
            },
            "resource": {
                "type": "string"
            }
        }
    },
    "system_certificate_download": {
        "url": "system/certificate/download",
        "params": {
            "scope": {
                "type": "string"
            },
            "type": {
                "type": "string"
            },
            "mkey": {
                "type": "string"
            }
        }
    },
    "system_ha-peer": {
        "url": "system/ha-peer",
        "params": {
            "serial_no": {
                "type": "string"
            },
            "vcluster_id": {
                "type": "int"
            }
        }
    },
    "network_lldp_ports": {
        "url": "network/lldp/ports",
        "params": {
            "mkey": {
                "type": "string"
            }
        }
    },
    "ips_metadata": {
        "url": "ips/metadata",
        "params": {
        }
    },
    "extender-controller_extender": {
        "url": "extender-controller/extender",
        "params": {
            "type": {
                "type": "string"
            },
            "id": {
                "type": "array"
            }
        }
    },
    "firewall_local-in": {
        "url": "firewall/local-in",
        "params": {
        }
    },
    "wifi_spectrum": {
        "url": "wifi/spectrum",
        "params": {
            "wtp_id": {
                "type": "string"
            }
        }
    },
    "network_reverse-ip-lookup": {
        "url": "network/reverse-ip-lookup",
        "params": {
            "ip": {
                "type": "string"
            }
        }
    },
    "switch-controller_managed-switch": {
        "url": "switch-controller/managed-switch",
        "params": {
            "fsw_id": {
                "type": "string"
            },
            "port_stats": {
                "type": "boolean"
            },
            "stp_status": {
                "type": "boolean"
            },
            "igmp_snooping_group": {
                "type": "boolean"
            },
            "qos_stats": {
                "type": "boolean"
            },
            "transceiver": {
                "type": "boolean"
            },
            "poe": {
                "type": "boolean"
            },
            "mkey": {
                "type": "string"
            }
        }
    },
    "system_object_usage": {
        "url": "system/object/usage",
        "params": {
            "scope": {
                "type": "string"
            },
            "q_name": {
                "type": "string"
            },
            "mkey": {
                "type": "string"
            },
            "qtypes": {
                "type": "array"
            },
            "q_path": {
                "type": "string"
            }
        }
    }
}


def is_successful_status(status):
    return status['status'] == "success" or \
        'http_method' in status and status['http_method'] == "DELETE" and status['http_status'] == 404


def validate_parameters(fos):
    # parameter validation will not block task, warning will be provided in case of parameters validation.
    mod_params = fos._module.params
    selector = mod_params['selector']
    params = mod_params['params']

    if params:
        for param_key, param_value in params.items():
            if type(param_value) not in [bool, int, str]:
                return False, {'message': 'value of param:%s must be atomic' % (param_key)}

    required_param_names = list(module_selectors_defs[selector]['params'].keys())
    provided_param_names = list(params.keys() if params else [])

    params_valid = True
    for param_name in required_param_names:
        if param_name not in provided_param_names:
            params_valid = False
            break
    if params_valid:
        for param_name in provided_param_names:
            if param_name not in required_param_names:
                params_valid = False
                break
    if not params_valid:
        param_summary = ['%s(%s)' % (param_name, param['type']) for param_name, param in module_selectors_defs[selector]['params'].items()]
        fos._module.warn("selector:%s expects params:%s" % (selector, str(param_summary)))
    return True, {}


def fortios_monitor_fact(fos):
    validate_parameters(fos)
    valid, result = validate_parameters(fos)
    if not valid:
        return True, False, result

    params = fos._module.params

    selector = params['selector']
    selector_params = params['params']

    fact = fos.monitor_get(module_selectors_defs[selector]['url'], params['vdom'], selector_params)

    return not is_successful_status(fact), False, fact


def main():
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "enable_log": {"required": False, "type": bool},
        "params": {"required": False, "type": "dict"},
        "selector": {
            "required": True,
            "type": "str",
            "options": [
                "firewall_acl6",
                "firewall_ippool",
                "webfilter_malicious-urls",
                "fortiguard_redirect-portal",
                "firewall_policy-lookup",
                "system_acquired-dns",
                "wifi_interfering_ap",
                "system_interface",
                "firewall_address-dynamic",
                "vpn_ocvpn_status",
                "wifi_vlan-probe",
                "system_sandbox_status",
                "endpoint-control_ems_status",
                "system_storage",
                "router_ipv4",
                "log_historic-daily-remote-logs",
                "webfilter_malicious-urls_stat",
                "ips_anomaly",
                "wanopt_peer_stats",
                "wifi_network_status",
                "log_hourly-disk-usage",
                "nsx_service_status",
                "wifi_region-image",
                "wifi_euclid",
                "system_current-admins",
                "system_sandbox_test-connect",
                "system_interface_speed-test-status",
                "user_info_query",
                "wifi_rogue_ap",
                "system_config-revision_info",
                "utm_antivirus_stats",
                "system_3g-modem",
                "log_forticloud-report_download",
                "firewall_address-fqdns",
                "system_security-rating",
                "user_fsso",
                "system_botnet-domains",
                "endpoint-control_installer",
                "utm_app-lookup",
                "system_firmware",
                "system_interface_dhcp-status",
                "wifi_client",
                "system_botnet-domains_stat",
                "firewall_address6-dynamic",
                "webfilter_fortiguard-categories",
                "firewall_shaper",
                "firewall_internet-service-match",
                "virtual-wan_sla-log",
                "wifi_firmware",
                "switch-controller_managed-switch_dhcp-snooping",
                "system_time",
                "system_fortimanager_backup-details",
                "system_available-interfaces",
                "system_fortimanager_status",
                "system_sensor-info",
                "system_status",
                "nsx_instance",
                "web-ui_custom-language_download",
                "wanopt_history",
                "log_forticloud",
                "system_vdom-link",
                "utm_blacklisted-certificates",
                "webcache_stats",
                "system_config-revision_file",
                "user_device",
                "system_dhcp",
                "router_lookup",
                "log_device_state",
                "system_sniffer",
                "system_firmware_upgrade-paths",
                "system_sandbox_stats",
                "wanopt_webcache",
                "network_lldp_neighbors",
                "log_local-report_download",
                "firewall_load-balance",
                "vpn_ocvpn_meta",
                "system_sandbox_cloud-regions",
                "firewall_address-fqdns6",
                "firewall_acl",
                "system_link-monitor",
                "system_com-log_download",
                "vpn_ocvpn_members",
                "fortiguard_service-communication-stats",
                "fortiview_sandbox-file-details",
                "system_available-certificates",
                "registration_forticloud_domains",
                "switch-controller_fsw-firmware",
                "fortiview_statistics",
                "router_ipv6",
                "firewall_uuid-list",
                "router_statistics",
                "system_config_usb-filelist",
                "endpoint-control_ems_cert-status",
                "system_config-script",
                "user_banned",
                "system_sdn-connector_nsx-security-tags",
                "system_com-log_update",
                "system_global-resources",
                "firewall_per-ip-shaper",
                "wifi_network_list",
                "system_check-port-availability",
                "log_current-disk-usage",
                "license_status",
                "firewall_session",
                "virtual-wan_members",
                "switch-controller_managed-switch_faceplate-xml",
                "firewall_security-policy",
                "endpoint-control_record-list",
                "webfilter_category-quota",
                "log_forticloud-report-list",
                "log_policy-archive_download",
                "system_ha-checksums",
                "system_debug_download",
                "log_fortianalyzer-queue",
                "system_ipconf",
                "system_nat46-ippools",
                "system_vdom-resource",
                "system_modem",
                "firewall_proxy-policy",
                "network_ddns_servers",
                "endpoint-control_installer_download",
                "system_fortiguard_server-info",
                "user_info_thumbnail",
                "system_sdn-connector_status",
                "vpn_ipsec",
                "switch-controller_validate-switch-prefix",
                "system_security-rating_history",
                "endpoint-control_summary",
                "system_csf",
                "license_forticare-resellers",
                "wifi_ap_status",
                "utm_application-categories",
                "router_lookup-policy",
                "system_ha-history",
                "webproxy_pacfile_download",
                "system_security-rating_lang",
                "system_interface_poe",
                "system_timezone",
                "firewall_sdn-connector-filters",
                "webfilter_trusted-urls",
                "system_usb-log",
                "router_policy6",
                "firewall_policy",
                "system_ha-statistics",
                "network_dns_latency",
                "system_fortimanager_backup-summary",
                "system_sniffer_download",
                "user_detected-device",
                "system_botnet_stat",
                "system_vm-information",
                "system_security-rating_supported-reports",
                "user_fortitoken",
                "system_botnet",
                "vpn_ssl_stats",
                "switch-controller_managed-switch_transceivers",
                "webfilter_override",
                "log_stats",
                "system_csf_pending-authorizations",
                "system_resolve-fqdn",
                "log_fortianalyzer",
                "log_ips-archive_download",
                "network_ddns_lookup",
                "system_config-revision",
                "user_collected-email",
                "ips_rate-based",
                "switch-controller_detected-device",
                "license_forticare-org-list",
                "registration_forticloud_device-status",
                "router_policy",
                "user_firewall",
                "system_automation-stitch_stats",
                "wifi_managed_ap",
                "system_interface_transceivers",
                "system_config_backup",
                "firewall_uuid-type-lookup",
                "virtual-wan_interface-log",
                "utm_blacklisted-certificates_statistics",
                "firewall_health",
                "system_security-rating_status",
                "registration_forticloud_disclaimer",
                "system_botnet-domains_hits",
                "firewall_internet-service-details",
                "log_event",
                "system_config-sync_status",
                "network_fortiguard_live-services-latency",
                "fortiview_sandbox-file-list",
                "system_trusted-cert-authorities",
                "vpn_ssl",
                "log_av-archive_download",
                "license_fortianalyzer-status",
                "virtual-wan_health-check",
                "log_local-report-list",
                "endpoint-control_avatar_download",
                "system_resource_usage",
                "system_certificate_download",
                "system_ha-peer",
                "network_lldp_ports",
                "ips_metadata",
                "extender-controller_extender",
                "firewall_local-in",
                "wifi_spectrum",
                "network_reverse-ip-lookup",
                "switch-controller_managed-switch",
                "system_object_usage",
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

        # Logging for fact module could be disabled/enabled.
        if 'enable_log' in module.params:
            connection.set_option('enable_log', module.params['enable_log'])
        else:
            connection.set_option('enable_log', False)

        fos = FortiOSHandler(connection, module)

        is_error, has_changed, result = fortios_monitor_fact(fos)
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
