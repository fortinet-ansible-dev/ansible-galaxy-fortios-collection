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
module: fortios_monitor
version_added: "2.10"
short_description: Ansible Module for FortiOS Monitor API
description:
    - Request FortiOS appliances to perform specific actions or procedures.
      This module contain all the FortiOS monitor API.
author:
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@fshen01)
notes:
    - Different selector may have different parameters, users are expected to look up them for a specific selector.
    - For some selectors, the objects are global, no params are allowed to appear.
    - Not all parameters are required for a selector.
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
         - format.system.logdisk
         - update.switch-controller.managed-switch
         - update.system.ha-peer
         - add-license.registration.vdom
         - geoip.geoip-query
         - clear-statistics.system.fortiguard
         - enable-app-bandwidth-tracking.system.traffic-history
         - upgrade.license.database
         - run.system.compliance
         - clear_counters.firewall.policy
         - test-availability.system.fortiguard
         - download.wifi.firmware
         - provision.user.fortitoken
         - reset.firewall.per-ip-shaper
         - clear-counters.firewall.central-snat-map
         - update.system.modem
         - update.web-ui.custom-language
         - stop.wifi.vlan-probe
         - import.vpn-certificate.local
         - create.registration.forticare
         - save.system.config
         - tunnel_reset_stats.vpn.ipsec
         - toggle-vdom-mode.system.admin
         - register-device.registration.forticloud
         - quarantine.endpoint-control.registration
         - set_status.wifi.rogue_ap
         - email.user.guest
         - add.firewall.clearpass-address
         - transfer.registration.forticare
         - import.vpn-certificate.crl
         - reset.firewall.dnat
         - disassociate.wifi.client
         - reset.webfilter.category-quota
         - upgrade.system.firmware
         - tunnel_up.vpn.ipsec
         - read-info.system.certificate
         - deregister.endpoint-control.registration
         - clear-soft-out.router.bgp
         - factory-reset.switch-controller.managed-switch
         - clear-soft-in.router.bgp
         - stop.system.sniffer
         - delete.log.local-report
         - add-license.registration.forticare
         - verify-cert.endpoint-control.ems
         - cancel.fortiview.session
         - restart.wifi.managed_ap
         - delete.webfilter.override
         - unblock.endpoint-control.registration
         - stop.system.usb-log
         - close.firewall.session
         - reset.firewall.shaper
         - clear_all.firewall.session
         - clear_counters.firewall.acl
         - reset.wifi.euclid
         - revoke.system.dhcp
         - add_users.user.banned
         - start.system.fsck
         - clear_counters.firewall.multicast-policy6
         - clear_counters.firewall.policy6
         - change-vdom-mode.system.admin
         - refresh-server.user.fsso
         - clear_counters.firewall.consolidated-policy
         - trigger.system.security-rating
         - webhook.system.automation-stitch
         - generate.vpn-certificate.csr
         - upload.system.vmlicense
         - reset.firewall.multicast-policy6
         - push.wifi.firmware
         - eject.system.usb-device
         - start.system.sniffer
         - reboot.system.os
         - reset.firewall.consolidated-policy
         - set.system.time
         - remove.user.device
         - import.vpn-certificate.remote
         - upload.webproxy.pacfile
         - push.switch-controller.fsw-firmware
         - reset.wanopt.peer_stats
         - delete.vpn.ssl
         - block.endpoint-control.registration
         - backup-action.system.fortimanager
         - start.system.usb-log
         - system.change-password
         - reset.firewall.multicast-policy
         - tunnel_down.vpn.ipsec
         - clear_all.wifi.rogue_ap
         - import-seed.user.fortitoken
         - poe-reset.switch-controller.managed-switch
         - logout.registration.forticloud
         - clear_counters.firewall.acl6
         - restore.system.config
         - import.vpn-certificate.ca
         - upload.switch-controller.fsw-firmware
         - test.user.tacacs-plus
         - upload.system.config-script
         - system.password-policy-conform
         - sms.user.guest
         - delete.system.config-script
         - reset.wanopt.history
         - reset.firewall.policy6
         - import-mobile.user.fortitoken
         - download.switch-controller.fsw-firmware
         - stop.wifi.spectrum
         - reset.firewall.central-snat-map
         - login.registration.forticare
         - create.registration.forticloud
         - upload.wifi.firmware
         - start.wifi.spectrum
         - disconnect.system.modem
         - disconnect.system.ha-peer
         - keep-alive.wifi.spectrum
         - reset.system.modem
         - activate.user.fortitoken
         - register-appliance.system.csf
         - refresh.azure.application-list
         - start.wifi.vlan-probe
         - clear.system.sniffer
         - reset.extender-controller.extender
         - validate-gcp-key.system.sdn-connector
         - restart.system.sniffer
         - import.web-ui.language
         - import-trial.user.fortitoken
         - dump.system.com-log
         - diagnose.extender-controller.extender
         - update-comments.system.config-revision
         - refresh.user.fortitoken
         - reset.firewall.policy
         - shutdown.system.os
         - reset.log.stats
         - revoke.system.dhcp6
         - login.registration.forticloud
         - reset.wanopt.webcache
         - save.system.config-revision
         - set_status.wifi.managed_ap
         - deauth.user.firewall
         - upgrade.extender-controller.extender
         - delete.system.config-revision
         - clear_users.user.banned
         - send-activation.user.fortitoken
         - reset.webcache.stats
         - clear_counters.firewall.proxy-policy
         - utm.rating-lookup
         - test.system.automation-stitch
         - refresh.system.external-resource
         - auth.user.firewall
         - dhcp-renew.system.interface
         - migrate.registration.forticloud
         - clear_counters.firewall.multicast-policy
         - connect.wifi.network
         - test-connect.user.radius
         - speed-test-trigger.system.interface
         - generate-key.system.api-user
         - upload.wifi.region-image
         - run.system.config-script
         - clear_tunnel.vpn.ssl
         - add.nsx.service
         - update.system.fortiguard
         - restart.switch-controller.managed-switch
         - unquarantine.endpoint-control.registration
         - led-blink.wifi.managed_ap
         - update.system.sdn-connector
         - config.system.fortimanager
         - system.disconnect-admins
         - provision-user.vpn.ssl
         - create.web-ui.custom-language
         - check.endpoint-control.registration-password
         - clear-counters.firewall.dnat
         - scan.wifi.network
         - clear.vpn.ike
         - clear_counters.firewall.security-policy
         - clear_all.user.banned
         - delete.firewall.clearpass-address
         - connect.system.modem
         - generate-keys.wifi.ssid

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

  - name: Activate FortiToken
    fortios_monitor:
       vdom: "root"
       access_token: "<fortios_access_token>"
       selector: 'activate.user.fortitoken'
       params:
           tokens: '<token string>'

  - name: Reboot This Device
    fortios_monitor:
       vdom: "root"
       access_token: "<fortios_access_token>"
       selector: 'reboot.system.os'
       params:
           event_log_message: 'Reboot Request From Ansible'
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
    "format.system.logdisk": {
        "url": "system/logdisk/format",
        "params": {
        }
    },
    "update.switch-controller.managed-switch": {
        "url": "switch-controller/managed-switch/update",
        "params": {
            "admin": {
                "type": "string",
                "required": "False"
            },
            "mkey": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "update.system.ha-peer": {
        "url": "system/ha-peer/update",
        "params": {
            "priority": {
                "type": "int",
                "required": "False"
            },
            "serial_no": {
                "type": "string",
                "required": "True"
            },
            "hostname": {
                "type": "string",
                "required": "False"
            },
            "vcluster_id": {
                "type": "int",
                "required": "False"
            }
        }
    },
    "add-license.registration.vdom": {
        "url": "registration/vdom/add-license",
        "params": {
            "license": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "geoip.geoip-query": {
        "url": "geoip/geoip-query/select",
        "params": {
            "ip_addresses": {
                "type": "array",
                "required": "True"
            }
        }
    },
    "clear-statistics.system.fortiguard": {
        "url": "system/fortiguard/clear-statistics",
        "params": {
        }
    },
    "enable-app-bandwidth-tracking.system.traffic-history": {
        "url": "system/traffic-history/enable-app-bandwidth-tracking",
        "params": {
        }
    },
    "upgrade.license.database": {
        "url": "license/database/upgrade",
        "params": {
            "file_content": {
                "type": "string",
                "required": "False"
            },
            "db_name": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "run.system.compliance": {
        "url": "system/compliance/run",
        "params": {
        }
    },
    "clear_counters.firewall.policy": {
        "url": "firewall/policy/clear_counters",
        "params": {
            "policy": {
                "type": "int",
                "required": "False"
            }
        }
    },
    "test-availability.system.fortiguard": {
        "url": "system/fortiguard/test-availability",
        "params": {
            "protocol": {
                "type": "string",
                "required": "True"
            },
            "port": {
                "type": "int",
                "required": "True"
            },
            "service": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "download.wifi.firmware": {
        "url": "wifi/firmware/download",
        "params": {
            "image_id": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "provision.user.fortitoken": {
        "url": "user/fortitoken/provision",
        "params": {
            "tokens": {
                "type": "array",
                "required": "False"
            }
        }
    },
    "reset.firewall.per-ip-shaper": {
        "url": "firewall/per-ip-shaper/reset",
        "params": {
        }
    },
    "clear-counters.firewall.central-snat-map": {
        "url": "firewall/central-snat-map/clear-counters",
        "params": {
            "policy": {
                "type": "int",
                "required": "False"
            }
        }
    },
    "update.system.modem": {
        "url": "system/modem/update",
        "params": {
        }
    },
    "update.web-ui.custom-language": {
        "url": "web-ui/custom-language/update",
        "params": {
            "file_content": {
                "type": "string",
                "required": "False"
            },
            "filename": {
                "type": "string",
                "required": "False"
            },
            "lang_comments": {
                "type": "string",
                "required": "False"
            },
            "mkey": {
                "type": "string",
                "required": "True"
            },
            "lang_name": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "stop.wifi.vlan-probe": {
        "url": "wifi/vlan-probe/stop",
        "params": {
            "wtp": {
                "type": "string",
                "required": "True"
            },
            "ap_interface": {
                "type": "int",
                "required": "True"
            }
        }
    },
    "import.vpn-certificate.local": {
        "url": "vpn-certificate/local/import",
        "params": {
            "acme-email": {
                "type": "string",
                "required": "False"
            },
            "acme-ca-url": {
                "type": "string",
                "required": "False"
            },
            "acme-rsa-key-size": {
                "type": "int",
                "required": "False"
            },
            "certname": {
                "type": "string",
                "required": "False"
            },
            "file_content": {
                "type": "string",
                "required": "False"
            },
            "acme-domain": {
                "type": "string",
                "required": "False"
            },
            "acme-renew-window": {
                "type": "int",
                "required": "False"
            },
            "scope": {
                "type": "string",
                "required": "False"
            },
            "key_file_content": {
                "type": "string",
                "required": "False"
            },
            "password": {
                "type": "string",
                "required": "False"
            },
            "type": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "create.registration.forticare": {
        "url": "registration/forticare/create",
        "params": {
            "city": {
                "type": "string",
                "required": "True"
            },
            "first_name": {
                "type": "string",
                "required": "True"
            },
            "last_name": {
                "type": "string",
                "required": "True"
            },
            "industry_id": {
                "type": "int",
                "required": "True"
            },
            "orgsize_id": {
                "type": "int",
                "required": "True"
            },
            "title": {
                "type": "string",
                "required": "False"
            },
            "industry": {
                "type": "string",
                "required": "True"
            },
            "company": {
                "type": "string",
                "required": "True"
            },
            "reseller_id": {
                "type": "int",
                "required": "True"
            },
            "state_code": {
                "type": "string",
                "required": "False"
            },
            "phone": {
                "type": "string",
                "required": "True"
            },
            "state": {
                "type": "string",
                "required": "True"
            },
            "postal_code": {
                "type": "string",
                "required": "True"
            },
            "country_code": {
                "type": "int",
                "required": "True"
            },
            "address": {
                "type": "string",
                "required": "True"
            },
            "reseller_name": {
                "type": "string",
                "required": "True"
            },
            "password": {
                "type": "string",
                "required": "True"
            },
            "email": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "save.system.config": {
        "url": "system/config/save",
        "params": {
        }
    },
    "tunnel_reset_stats.vpn.ipsec": {
        "url": "vpn/ipsec/tunnel_reset_stats",
        "params": {
            "p1name": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "toggle-vdom-mode.system.admin": {
        "url": "system/admin/toggle-vdom-mode",
        "params": {
        }
    },
    "register-device.registration.forticloud": {
        "url": "registration/forticloud/register-device",
        "params": {
            "country": {
                "type": "string",
                "required": "True"
            },
            "serial": {
                "type": "string",
                "required": "True"
            },
            "password": {
                "type": "string",
                "required": "True"
            },
            "email": {
                "type": "string",
                "required": "True"
            },
            "reseller": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "quarantine.endpoint-control.registration": {
        "url": "endpoint-control/registration/quarantine",
        "params": {
            "mac": {
                "type": "string",
                "required": "False"
            },
            "uid": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "set_status.wifi.rogue_ap": {
        "url": "wifi/rogue_ap/set_status",
        "params": {
            "status": {
                "type": "string",
                "required": "False"
            },
            "ssid": {
                "type": "array",
                "required": "False"
            },
            "bssid": {
                "type": "array",
                "required": "False"
            }
        }
    },
    "email.user.guest": {
        "url": "user/guest/email",
        "params": {
            "group": {
                "type": "string",
                "required": "True"
            },
            "guest": {
                "type": "array",
                "required": "True"
            }
        }
    },
    "add.firewall.clearpass-address": {
        "url": "firewall/clearpass-address/add",
        "params": {
            "endpoint_ip": {
                "type": "array",
                "required": "True"
            },
            "spt": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "transfer.registration.forticare": {
        "url": "registration/forticare/transfer",
        "params": {
            "password": {
                "type": "string",
                "required": "True"
            },
            "old_password": {
                "type": "string",
                "required": "True"
            },
            "email": {
                "type": "string",
                "required": "True"
            },
            "old_email": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "import.vpn-certificate.crl": {
        "url": "vpn-certificate/crl/import",
        "params": {
            "file_content": {
                "type": "string",
                "required": "False"
            },
            "scope": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "reset.firewall.dnat": {
        "url": "firewall/dnat/reset",
        "params": {
        }
    },
    "disassociate.wifi.client": {
        "url": "wifi/client/disassociate",
        "params": {
            "mac": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "reset.webfilter.category-quota": {
        "url": "webfilter/category-quota/reset",
        "params": {
            "profile": {
                "type": "string",
                "required": "False"
            },
            "user": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "upgrade.system.firmware": {
        "url": "system/firmware/upgrade",
        "params": {
            "file_content": {
                "type": "string",
                "required": "False"
            },
            "source": {
                "type": "string",
                "required": "True"
            },
            "ignore_invalid_signature": {
                "type": "boolean",
                "required": "False"
            },
            "format_partition": {
                "type": "boolean",
                "required": "False"
            },
            "filename": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "tunnel_up.vpn.ipsec": {
        "url": "vpn/ipsec/tunnel_up",
        "params": {
            "p2name": {
                "type": "string",
                "required": "True"
            },
            "p2serial": {
                "type": "int",
                "required": "False"
            },
            "p1name": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "read-info.system.certificate": {
        "url": "system/certificate/read-info",
        "params": {
            "value": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "deregister.endpoint-control.registration": {
        "url": "endpoint-control/registration/deregister",
        "params": {
            "mac": {
                "type": "string",
                "required": "False"
            },
            "uid": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "clear-soft-out.router.bgp": {
        "url": "router/bgp/clear-soft-out",
        "params": {
        }
    },
    "factory-reset.switch-controller.managed-switch": {
        "url": "switch-controller/managed-switch/factory-reset",
        "params": {
            "mkey": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "clear-soft-in.router.bgp": {
        "url": "router/bgp/clear-soft-in",
        "params": {
        }
    },
    "stop.system.sniffer": {
        "url": "system/sniffer/stop",
        "params": {
            "mkey": {
                "type": "int",
                "required": "True"
            }
        }
    },
    "delete.log.local-report": {
        "url": "log/local-report/delete",
        "params": {
            "mkeys": {
                "type": "array",
                "required": "True"
            }
        }
    },
    "add-license.registration.forticare": {
        "url": "registration/forticare/add-license",
        "params": {
            "registration_code": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "verify-cert.endpoint-control.ems": {
        "url": "endpoint-control/ems/verify-cert",
        "params": {
            "ems_name": {
                "type": "string",
                "required": "True"
            },
            "fingerprint": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "cancel.fortiview.session": {
        "url": "fortiview/session/cancel",
        "params": {
            "device": {
                "type": "string",
                "required": "False"
            },
            "sessionid": {
                "type": "int",
                "required": "False"
            },
            "view_level": {
                "type": "string",
                "required": "False"
            },
            "report_by": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "restart.wifi.managed_ap": {
        "url": "wifi/managed_ap/restart",
        "params": {
            "wtpname": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "delete.webfilter.override": {
        "url": "webfilter/override/delete",
        "params": {
            "mkey": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "unblock.endpoint-control.registration": {
        "url": "endpoint-control/registration/unblock",
        "params": {
            "mac": {
                "type": "string",
                "required": "False"
            },
            "uid": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "stop.system.usb-log": {
        "url": "system/usb-log/stop",
        "params": {
        }
    },
    "close.firewall.session": {
        "url": "firewall/session/close",
        "params": {
            "daddr": {
                "type": "string",
                "required": "True"
            },
            "dport": {
                "type": "int",
                "required": "True"
            },
            "pro": {
                "type": "string",
                "required": "True"
            },
            "sport": {
                "type": "int",
                "required": "True"
            },
            "saddr": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "reset.firewall.shaper": {
        "url": "firewall/shaper/reset",
        "params": {
        }
    },
    "clear_all.firewall.session": {
        "url": "firewall/session/clear_all",
        "params": {
        }
    },
    "clear_counters.firewall.acl": {
        "url": "firewall/acl/clear_counters",
        "params": {
            "policy": {
                "type": "int",
                "required": "False"
            }
        }
    },
    "reset.wifi.euclid": {
        "url": "wifi/euclid/reset",
        "params": {
        }
    },
    "revoke.system.dhcp": {
        "url": "system/dhcp/revoke",
        "params": {
            "ip": {
                "type": "array",
                "required": "False"
            }
        }
    },
    "add_users.user.banned": {
        "url": "user/banned/add_users",
        "params": {
            "ip_addresses": {
                "type": "array",
                "required": "True"
            },
            "expiry": {
                "type": "int",
                "required": "False"
            }
        }
    },
    "start.system.fsck": {
        "url": "system/fsck/start",
        "params": {
        }
    },
    "clear_counters.firewall.multicast-policy6": {
        "url": "firewall/multicast-policy6/clear_counters",
        "params": {
            "policy": {
                "type": "int",
                "required": "False"
            }
        }
    },
    "clear_counters.firewall.policy6": {
        "url": "firewall/policy6/clear_counters",
        "params": {
            "policy": {
                "type": "int",
                "required": "False"
            }
        }
    },
    "change-vdom-mode.system.admin": {
        "url": "system/admin/change-vdom-mode",
        "params": {
            "vdom-mode": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "refresh-server.user.fsso": {
        "url": "user/fsso/refresh-server",
        "params": {
        }
    },
    "clear_counters.firewall.consolidated-policy": {
        "url": "firewall/consolidated-policy/clear_counters",
        "params": {
            "policy": {
                "type": "int",
                "required": "False"
            }
        }
    },
    "trigger.system.security-rating": {
        "url": "system/security-rating/trigger",
        "params": {
            "report_types": {
                "type": "array",
                "required": "False"
            },
            "report_type": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "webhook.system.automation-stitch": {
        "url": "system/automation-stitch/webhook",
        "params": {
            "mkey": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "generate.vpn-certificate.csr": {
        "url": "vpn-certificate/csr/generate",
        "params": {
            "city": {
                "type": "string",
                "required": "False"
            },
            "orgunits": {
                "type": "array",
                "required": "False"
            },
            "countrycode": {
                "type": "string",
                "required": "False"
            },
            "scep_url": {
                "type": "string",
                "required": "False"
            },
            "curvename": {
                "type": "string",
                "required": "False"
            },
            "keytype": {
                "type": "string",
                "required": "True"
            },
            "certname": {
                "type": "string",
                "required": "True"
            },
            "scep_password": {
                "type": "string",
                "required": "False"
            },
            "state": {
                "type": "string",
                "required": "False"
            },
            "keysize": {
                "type": "int",
                "required": "False"
            },
            "scope": {
                "type": "string",
                "required": "False"
            },
            "sub_alt_name": {
                "type": "string",
                "required": "False"
            },
            "org": {
                "type": "string",
                "required": "False"
            },
            "password": {
                "type": "string",
                "required": "False"
            },
            "email": {
                "type": "string",
                "required": "False"
            },
            "subject": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "upload.system.vmlicense": {
        "url": "system/vmlicense/upload",
        "params": {
            "file_content": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "reset.firewall.multicast-policy6": {
        "url": "firewall/multicast-policy6/reset",
        "params": {
        }
    },
    "push.wifi.firmware": {
        "url": "wifi/firmware/push",
        "params": {
            "image_id": {
                "type": "string",
                "required": "True"
            },
            "serial": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "eject.system.usb-device": {
        "url": "system/usb-device/eject",
        "params": {
        }
    },
    "start.system.sniffer": {
        "url": "system/sniffer/start",
        "params": {
            "mkey": {
                "type": "int",
                "required": "True"
            }
        }
    },
    "reboot.system.os": {
        "url": "system/os/reboot",
        "params": {
            "event_log_message": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "reset.firewall.consolidated-policy": {
        "url": "firewall/consolidated-policy/reset",
        "params": {
        }
    },
    "set.system.time": {
        "url": "system/time/set",
        "params": {
            "hour": {
                "type": "int",
                "required": "True"
            },
            "month": {
                "type": "int",
                "required": "True"
            },
            "second": {
                "type": "int",
                "required": "True"
            },
            "year": {
                "type": "int",
                "required": "True"
            },
            "day": {
                "type": "int",
                "required": "True"
            },
            "minute": {
                "type": "int",
                "required": "True"
            }
        }
    },
    "remove.user.device": {
        "url": "user/device/remove",
        "params": {
            "macs": {
                "type": "array",
                "required": "False"
            }
        }
    },
    "import.vpn-certificate.remote": {
        "url": "vpn-certificate/remote/import",
        "params": {
            "file_content": {
                "type": "string",
                "required": "False"
            },
            "scope": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "upload.webproxy.pacfile": {
        "url": "webproxy/pacfile/upload",
        "params": {
            "file_content": {
                "type": "string",
                "required": "False"
            },
            "filename": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "push.switch-controller.fsw-firmware": {
        "url": "switch-controller/fsw-firmware/push",
        "params": {
            "image_id": {
                "type": "string",
                "required": "True"
            },
            "serial": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "reset.wanopt.peer_stats": {
        "url": "wanopt/peer_stats/reset",
        "params": {
        }
    },
    "delete.vpn.ssl": {
        "url": "vpn/ssl/delete",
        "params": {
            "index": {
                "type": "int",
                "required": "True"
            },
            "type": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "block.endpoint-control.registration": {
        "url": "endpoint-control/registration/block",
        "params": {
            "mac": {
                "type": "string",
                "required": "False"
            },
            "uid": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "backup-action.system.fortimanager": {
        "url": "system/fortimanager/backup-action",
        "params": {
            "operation": {
                "type": "string",
                "required": "True"
            },
            "objects": {
                "type": "array",
                "required": "True"
            }
        }
    },
    "start.system.usb-log": {
        "url": "system/usb-log/start",
        "params": {
        }
    },
    "system.change-password": {
        "url": "system/change-password/select",
        "params": {
            "new_password": {
                "type": "string",
                "required": "True"
            },
            "old_password": {
                "type": "string",
                "required": "False"
            },
            "mkey": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "reset.firewall.multicast-policy": {
        "url": "firewall/multicast-policy/reset",
        "params": {
        }
    },
    "tunnel_down.vpn.ipsec": {
        "url": "vpn/ipsec/tunnel_down",
        "params": {
            "p2name": {
                "type": "string",
                "required": "True"
            },
            "p2serial": {
                "type": "int",
                "required": "False"
            },
            "p1name": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "clear_all.wifi.rogue_ap": {
        "url": "wifi/rogue_ap/clear_all",
        "params": {
        }
    },
    "import-seed.user.fortitoken": {
        "url": "user/fortitoken/import-seed",
        "params": {
            "file_content": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "poe-reset.switch-controller.managed-switch": {
        "url": "switch-controller/managed-switch/poe-reset",
        "params": {
            "port": {
                "type": "string",
                "required": "True"
            },
            "mkey": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "logout.registration.forticloud": {
        "url": "registration/forticloud/logout",
        "params": {
        }
    },
    "clear_counters.firewall.acl6": {
        "url": "firewall/acl6/clear_counters",
        "params": {
            "policy": {
                "type": "int",
                "required": "False"
            }
        }
    },
    "restore.system.config": {
        "url": "system/config/restore",
        "params": {
            "config_id": {
                "type": "int",
                "required": "False"
            },
            "file_content": {
                "type": "string",
                "required": "False"
            },
            "usb_filename": {
                "type": "string",
                "required": "False"
            },
            "source": {
                "type": "string",
                "required": "True"
            },
            "scope": {
                "type": "string",
                "required": "True"
            },
            "password": {
                "type": "string",
                "required": "False"
            },
            "vdom": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "import.vpn-certificate.ca": {
        "url": "vpn-certificate/ca/import",
        "params": {
            "file_content": {
                "type": "string",
                "required": "False"
            },
            "scope": {
                "type": "string",
                "required": "False"
            },
            "import_method": {
                "type": "string",
                "required": "True"
            },
            "scep_ca_id": {
                "type": "string",
                "required": "False"
            },
            "scep_url": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "upload.switch-controller.fsw-firmware": {
        "url": "switch-controller/fsw-firmware/upload",
        "params": {
            "serials": {
                "type": "string",
                "required": "False"
            },
            "file_content": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "test.user.tacacs-plus": {
        "url": "user/tacacs-plus/test",
        "params": {
            "ordinal": {
                "type": "string",
                "required": "False"
            },
            "source_ip": {
                "type": "string",
                "required": "False"
            },
            "server": {
                "type": "string",
                "required": "False"
            },
            "secret": {
                "type": "string",
                "required": "False"
            },
            "port": {
                "type": "int",
                "required": "False"
            },
            "mkey": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "upload.system.config-script": {
        "url": "system/config-script/upload",
        "params": {
            "file_content": {
                "type": "string",
                "required": "False"
            },
            "filename": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "system.password-policy-conform": {
        "url": "system/password-policy-conform/select",
        "params": {
            "apply_to": {
                "type": "string",
                "required": "False"
            },
            "password": {
                "type": "string",
                "required": "False"
            },
            "old_password": {
                "type": "string",
                "required": "False"
            },
            "mkey": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "sms.user.guest": {
        "url": "user/guest/sms",
        "params": {
            "group": {
                "type": "string",
                "required": "True"
            },
            "guest": {
                "type": "array",
                "required": "True"
            }
        }
    },
    "delete.system.config-script": {
        "url": "system/config-script/delete",
        "params": {
            "id_list": {
                "type": "array",
                "required": "True"
            }
        }
    },
    "reset.wanopt.history": {
        "url": "wanopt/history/reset",
        "params": {
        }
    },
    "reset.firewall.policy6": {
        "url": "firewall/policy6/reset",
        "params": {
        }
    },
    "import-mobile.user.fortitoken": {
        "url": "user/fortitoken/import-mobile",
        "params": {
            "code": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "download.switch-controller.fsw-firmware": {
        "url": "switch-controller/fsw-firmware/download",
        "params": {
            "image_id": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "stop.wifi.spectrum": {
        "url": "wifi/spectrum/stop",
        "params": {
            "radio_id": {
                "type": "int",
                "required": "True"
            },
            "wtp_id": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "reset.firewall.central-snat-map": {
        "url": "firewall/central-snat-map/reset",
        "params": {
        }
    },
    "login.registration.forticare": {
        "url": "registration/forticare/login",
        "params": {
            "reseller_name": {
                "type": "string",
                "required": "True"
            },
            "password": {
                "type": "string",
                "required": "True"
            },
            "email": {
                "type": "string",
                "required": "True"
            },
            "reseller_id": {
                "type": "int",
                "required": "True"
            }
        }
    },
    "create.registration.forticloud": {
        "url": "registration/forticloud/create",
        "params": {
            "send_logs": {
                "type": "boolean",
                "required": "False"
            },
            "password": {
                "type": "string",
                "required": "True"
            },
            "email": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "upload.wifi.firmware": {
        "url": "wifi/firmware/upload",
        "params": {
            "serials": {
                "type": "string",
                "required": "False"
            },
            "file_content": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "start.wifi.spectrum": {
        "url": "wifi/spectrum/start",
        "params": {
            "radio_id": {
                "type": "int",
                "required": "True"
            },
            "channels": {
                "type": "array",
                "required": "True"
            },
            "duration": {
                "type": "int",
                "required": "True"
            },
            "wtp_id": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "disconnect.system.modem": {
        "url": "system/modem/disconnect",
        "params": {
        }
    },
    "disconnect.system.ha-peer": {
        "url": "system/ha-peer/disconnect",
        "params": {
            "interface": {
                "type": "string",
                "required": "True"
            },
            "ip": {
                "type": "string",
                "required": "True"
            },
            "serial_no": {
                "type": "string",
                "required": "True"
            },
            "mask": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "keep-alive.wifi.spectrum": {
        "url": "wifi/spectrum/keep-alive",
        "params": {
            "radio_id": {
                "type": "int",
                "required": "True"
            },
            "duration": {
                "type": "int",
                "required": "True"
            },
            "wtp_id": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "reset.system.modem": {
        "url": "system/modem/reset",
        "params": {
        }
    },
    "activate.user.fortitoken": {
        "url": "user/fortitoken/activate",
        "params": {
            "tokens": {
                "type": "array",
                "required": "False"
            }
        }
    },
    "register-appliance.system.csf": {
        "url": "system/csf/register-appliance",
        "params": {
            "mgmt_ip": {
                "type": "string",
                "required": "True"
            },
            "mgmt_port": {
                "type": "int",
                "required": "False"
            },
            "hostname": {
                "type": "string",
                "required": "False"
            },
            "mgmt_url_parameters": {
                "type": "array",
                "required": "False"
            },
            "serial": {
                "type": "string",
                "required": "True"
            },
            "type": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "refresh.azure.application-list": {
        "url": "azure/application-list/refresh",
        "params": {
            "last_update_time": {
                "type": "int",
                "required": "False"
            }
        }
    },
    "start.wifi.vlan-probe": {
        "url": "wifi/vlan-probe/start",
        "params": {
            "wtp": {
                "type": "string",
                "required": "True"
            },
            "retries": {
                "type": "int",
                "required": "True"
            },
            "start_vlan_id": {
                "type": "int",
                "required": "True"
            },
            "end_vlan_id": {
                "type": "int",
                "required": "True"
            },
            "timeout": {
                "type": "int",
                "required": "True"
            },
            "ap_interface": {
                "type": "int",
                "required": "True"
            }
        }
    },
    "clear.system.sniffer": {
        "url": "system/sniffer/clear",
        "params": {
            "mkey": {
                "type": "int",
                "required": "True"
            }
        }
    },
    "reset.extender-controller.extender": {
        "url": "extender-controller/extender/reset",
        "params": {
            "id": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "validate-gcp-key.system.sdn-connector": {
        "url": "system/sdn-connector/validate-gcp-key",
        "params": {
            "private-key": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "restart.system.sniffer": {
        "url": "system/sniffer/restart",
        "params": {
            "mkey": {
                "type": "int",
                "required": "True"
            }
        }
    },
    "import.web-ui.language": {
        "url": "web-ui/language/import",
        "params": {
            "file_content": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "import-trial.user.fortitoken": {
        "url": "user/fortitoken/import-trial",
        "params": {
        }
    },
    "dump.system.com-log": {
        "url": "system/com-log/dump",
        "params": {
        }
    },
    "diagnose.extender-controller.extender": {
        "url": "extender-controller/extender/diagnose",
        "params": {
            "cmd": {
                "type": "string",
                "required": "True"
            },
            "id": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "update-comments.system.config-revision": {
        "url": "system/config-revision/update-comments",
        "params": {
            "config_id": {
                "type": "int",
                "required": "False"
            },
            "comments": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "refresh.user.fortitoken": {
        "url": "user/fortitoken/refresh",
        "params": {
            "tokens": {
                "type": "array",
                "required": "False"
            }
        }
    },
    "reset.firewall.policy": {
        "url": "firewall/policy/reset",
        "params": {
        }
    },
    "shutdown.system.os": {
        "url": "system/os/shutdown",
        "params": {
            "event_log_message": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "reset.log.stats": {
        "url": "log/stats/reset",
        "params": {
        }
    },
    "revoke.system.dhcp6": {
        "url": "system/dhcp6/revoke",
        "params": {
            "ip": {
                "type": "array",
                "required": "False"
            }
        }
    },
    "login.registration.forticloud": {
        "url": "registration/forticloud/login",
        "params": {
            "send_logs": {
                "type": "boolean",
                "required": "False"
            },
            "domain": {
                "type": "string",
                "required": "False"
            },
            "password": {
                "type": "string",
                "required": "True"
            },
            "email": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "reset.wanopt.webcache": {
        "url": "wanopt/webcache/reset",
        "params": {
        }
    },
    "save.system.config-revision": {
        "url": "system/config-revision/save",
        "params": {
            "comments": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "set_status.wifi.managed_ap": {
        "url": "wifi/managed_ap/set_status",
        "params": {
            "admin": {
                "type": "string",
                "required": "False"
            },
            "wtpname": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "deauth.user.firewall": {
        "url": "user/firewall/deauth",
        "params": {
            "all": {
                "type": "boolean",
                "required": "False"
            },
            "users": {
                "type": "array",
                "required": "False"
            },
            "ip": {
                "type": "string",
                "required": "False"
            },
            "user_type": {
                "type": "string",
                "required": "False"
            },
            "id": {
                "type": "int",
                "required": "False"
            },
            "ip_version": {
                "type": "string",
                "required": "False"
            },
            "method": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "upgrade.extender-controller.extender": {
        "url": "extender-controller/extender/upgrade",
        "params": {
            "file_content": {
                "type": "string",
                "required": "False"
            },
            "id": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "delete.system.config-revision": {
        "url": "system/config-revision/delete",
        "params": {
            "config_ids": {
                "type": "array",
                "required": "True"
            }
        }
    },
    "clear_users.user.banned": {
        "url": "user/banned/clear_users",
        "params": {
            "ip_addresses": {
                "type": "array",
                "required": "True"
            }
        }
    },
    "send-activation.user.fortitoken": {
        "url": "user/fortitoken/send-activation",
        "params": {
            "token": {
                "type": "string",
                "required": "True"
            },
            "sms_phone": {
                "type": "string",
                "required": "False"
            },
            "method": {
                "type": "string",
                "required": "False"
            },
            "email": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "reset.webcache.stats": {
        "url": "webcache/stats/reset",
        "params": {
        }
    },
    "clear_counters.firewall.proxy-policy": {
        "url": "firewall/proxy-policy/clear_counters",
        "params": {
            "policy": {
                "type": "int",
                "required": "False"
            }
        }
    },
    "utm.rating-lookup": {
        "url": "utm/rating-lookup/select",
        "params": {
            "url": {
                "type": "array",
                "required": "False"
            },
            "lang": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "test.system.automation-stitch": {
        "url": "system/automation-stitch/test",
        "params": {
            "log": {
                "type": "string",
                "required": "False"
            },
            "mkey": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "refresh.system.external-resource": {
        "url": "system/external-resource/refresh",
        "params": {
            "last_connection_time": {
                "type": "int",
                "required": "False"
            },
            "mkey": {
                "type": "string",
                "required": "True"
            },
            "check_status_only": {
                "type": "boolean",
                "required": "False"
            }
        }
    },
    "auth.user.firewall": {
        "url": "user/firewall/auth",
        "params": {
            "username": {
                "type": "string",
                "required": "True"
            },
            "ip": {
                "type": "string",
                "required": "True"
            },
            "ip_version": {
                "type": "string",
                "required": "False"
            },
            "server": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "dhcp-renew.system.interface": {
        "url": "system/interface/dhcp-renew",
        "params": {
            "mkey": {
                "type": "string",
                "required": "True"
            },
            "ipv6": {
                "type": "boolean",
                "required": "False"
            }
        }
    },
    "migrate.registration.forticloud": {
        "url": "registration/forticloud/migrate",
        "params": {
            "password": {
                "type": "string",
                "required": "True"
            },
            "email": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "clear_counters.firewall.multicast-policy": {
        "url": "firewall/multicast-policy/clear_counters",
        "params": {
            "policy": {
                "type": "int",
                "required": "False"
            }
        }
    },
    "connect.wifi.network": {
        "url": "wifi/network/connect",
        "params": {
            "ssid": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "test-connect.user.radius": {
        "url": "user/radius/test-connect",
        "params": {
            "ordinal": {
                "type": "string",
                "required": "False"
            },
            "auth_type": {
                "type": "string",
                "required": "False"
            },
            "server": {
                "type": "string",
                "required": "False"
            },
            "secret": {
                "type": "string",
                "required": "False"
            },
            "user": {
                "type": "string",
                "required": "False"
            },
            "password": {
                "type": "string",
                "required": "False"
            },
            "mkey": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "speed-test-trigger.system.interface": {
        "url": "system/interface/speed-test-trigger",
        "params": {
            "mkey": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "generate-key.system.api-user": {
        "url": "system/api-user/generate-key",
        "params": {
            "api-user": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "upload.wifi.region-image": {
        "url": "wifi/region-image/upload",
        "params": {
            "image_type": {
                "type": "string",
                "required": "True"
            },
            "file_content": {
                "type": "string",
                "required": "False"
            },
            "region_name": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "run.system.config-script": {
        "url": "system/config-script/run",
        "params": {
            "remote_script": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "clear_tunnel.vpn.ssl": {
        "url": "vpn/ssl/clear_tunnel",
        "params": {
        }
    },
    "add.nsx.service": {
        "url": "nsx/service/add",
        "params": {
            "mkey": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "update.system.fortiguard": {
        "url": "system/fortiguard/update",
        "params": {
        }
    },
    "restart.switch-controller.managed-switch": {
        "url": "switch-controller/managed-switch/restart",
        "params": {
            "mkey": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "unquarantine.endpoint-control.registration": {
        "url": "endpoint-control/registration/unquarantine",
        "params": {
            "mac": {
                "type": "string",
                "required": "False"
            },
            "uid": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "led-blink.wifi.managed_ap": {
        "url": "wifi/managed_ap/led-blink",
        "params": {
            "serials": {
                "type": "array",
                "required": "True"
            },
            "duration": {
                "type": "int",
                "required": "False"
            },
            "blink": {
                "type": "boolean",
                "required": "True"
            }
        }
    },
    "update.system.sdn-connector": {
        "url": "system/sdn-connector/update",
        "params": {
            "mkey": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "config.system.fortimanager": {
        "url": "system/fortimanager/config",
        "params": {
            "unregister": {
                "type": "boolean",
                "required": "False"
            },
            "fortimanager_ip": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "system.disconnect-admins": {
        "url": "system/disconnect-admins/select",
        "params": {
            "admins": {
                "type": "array",
                "required": "False"
            },
            "id": {
                "type": "int",
                "required": "False"
            },
            "method": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "provision-user.vpn.ssl": {
        "url": "vpn/ssl/provision-user",
        "params": {
            "sms_server": {
                "type": "string",
                "required": "False"
            },
            "vpn_name": {
                "type": "string",
                "required": "True"
            },
            "phone_user_list": {
                "type": "string",
                "required": "False"
            },
            "method": {
                "type": "string",
                "required": "False"
            },
            "email_list": {
                "type": "string",
                "required": "False"
            },
            "host": {
                "type": "string",
                "required": "True"
            },
            "sms_method": {
                "type": "string",
                "required": "False"
            },
            "port": {
                "type": "int",
                "required": "True"
            },
            "phone_number_list": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "create.web-ui.custom-language": {
        "url": "web-ui/custom-language/create",
        "params": {
            "file_content": {
                "type": "string",
                "required": "False"
            },
            "lang_name": {
                "type": "string",
                "required": "True"
            },
            "lang_comments": {
                "type": "string",
                "required": "False"
            },
            "filename": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "check.endpoint-control.registration-password": {
        "url": "endpoint-control/registration-password/check",
        "params": {
            "password": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "clear-counters.firewall.dnat": {
        "url": "firewall/dnat/clear-counters",
        "params": {
            "id": {
                "type": "int",
                "required": "False"
            }
        }
    },
    "scan.wifi.network": {
        "url": "wifi/network/scan",
        "params": {
        }
    },
    "clear.vpn.ike": {
        "url": "vpn/ike/clear",
        "params": {
            "mkey": {
                "type": "string",
                "required": "True"
            }
        }
    },
    "clear_counters.firewall.security-policy": {
        "url": "firewall/security-policy/clear_counters",
        "params": {
            "policy": {
                "type": "int",
                "required": "False"
            }
        }
    },
    "clear_all.user.banned": {
        "url": "user/banned/clear_all",
        "params": {
        }
    },
    "delete.firewall.clearpass-address": {
        "url": "firewall/clearpass-address/delete",
        "params": {
            "endpoint_ip": {
                "type": "array",
                "required": "True"
            },
            "spt": {
                "type": "string",
                "required": "False"
            }
        }
    },
    "connect.system.modem": {
        "url": "system/modem/connect",
        "params": {
        }
    },
    "generate-keys.wifi.ssid": {
        "url": "wifi/ssid/generate-keys",
        "params": {
            "count": {
                "type": "int",
                "required": "True"
            },
            "prefix": {
                "type": "string",
                "required": "True"
            },
            "group": {
                "type": "string",
                "required": "True"
            },
            "key_length": {
                "type": "int",
                "required": "True"
            },
            "mpsk_profile": {
                "type": "string",
                "required": "True"
            }
        }
    }
}


def is_successful_status(resp):
    return 'status' in resp and resp['status'] == 'success' or \
        'http_status' in resp and resp['http_status'] == 200 or \
        'http_method' in resp and resp['http_method'] == "DELETE" and resp['http_status'] == 404


def validate_parameters(fos):
    # parameter validation will not block task, warning will be provided in case of parameters validation.
    mod_params = fos._module.params
    selector = mod_params['selector']
    params = mod_params['params']

    if params:
        for param_key, param_value in params.items():
            if type(param_value) not in [bool, int, str, list]:
                return False, {'message': 'value of param:%s must be atomic' % (param_key)}

    acceptable_param_names = list(module_selectors_defs[selector]['params'].keys())
    provided_param_names = list(params.keys() if params else [])

    params_valid = True
    for param_name in acceptable_param_names:
        if param_name not in provided_param_names and eval(module_selectors_defs[selector]['params'][param_name]['required']):
            params_valid = False
            break
    if params_valid:
        for param_name in provided_param_names:
            if param_name not in acceptable_param_names:
                params_valid = False
                break
    if not params_valid:
        param_summary = ['%s(%s, %s)' % (param_name, param['type'], 'required' if eval(param['required']) else 'optional')
                         for param_name, param in module_selectors_defs[selector]['params'].items()]
        fos._module.warn("selector:%s expects params:%s" % (selector, str(param_summary)))
    return True, {}


def fortios_monitor(fos):
    valid, result = validate_parameters(fos)
    if not valid:
        return True, False, result

    params = fos._module.params

    selector = params['selector']
    selector_params = params['params']

    resp = fos.monitor_post(module_selectors_defs[selector]['url'], vdom=params['vdom'], data=selector_params)

    return not is_successful_status(resp), False, resp


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
                "format.system.logdisk",
                "update.switch-controller.managed-switch",
                "update.system.ha-peer",
                "add-license.registration.vdom",
                "geoip.geoip-query",
                "clear-statistics.system.fortiguard",
                "enable-app-bandwidth-tracking.system.traffic-history",
                "upgrade.license.database",
                "run.system.compliance",
                "clear_counters.firewall.policy",
                "test-availability.system.fortiguard",
                "download.wifi.firmware",
                "provision.user.fortitoken",
                "reset.firewall.per-ip-shaper",
                "clear-counters.firewall.central-snat-map",
                "update.system.modem",
                "update.web-ui.custom-language",
                "stop.wifi.vlan-probe",
                "import.vpn-certificate.local",
                "create.registration.forticare",
                "save.system.config",
                "tunnel_reset_stats.vpn.ipsec",
                "toggle-vdom-mode.system.admin",
                "register-device.registration.forticloud",
                "quarantine.endpoint-control.registration",
                "set_status.wifi.rogue_ap",
                "email.user.guest",
                "add.firewall.clearpass-address",
                "transfer.registration.forticare",
                "import.vpn-certificate.crl",
                "reset.firewall.dnat",
                "disassociate.wifi.client",
                "reset.webfilter.category-quota",
                "upgrade.system.firmware",
                "tunnel_up.vpn.ipsec",
                "read-info.system.certificate",
                "deregister.endpoint-control.registration",
                "clear-soft-out.router.bgp",
                "factory-reset.switch-controller.managed-switch",
                "clear-soft-in.router.bgp",
                "stop.system.sniffer",
                "delete.log.local-report",
                "add-license.registration.forticare",
                "verify-cert.endpoint-control.ems",
                "cancel.fortiview.session",
                "restart.wifi.managed_ap",
                "delete.webfilter.override",
                "unblock.endpoint-control.registration",
                "stop.system.usb-log",
                "close.firewall.session",
                "reset.firewall.shaper",
                "clear_all.firewall.session",
                "clear_counters.firewall.acl",
                "reset.wifi.euclid",
                "revoke.system.dhcp",
                "add_users.user.banned",
                "start.system.fsck",
                "clear_counters.firewall.multicast-policy6",
                "clear_counters.firewall.policy6",
                "change-vdom-mode.system.admin",
                "refresh-server.user.fsso",
                "clear_counters.firewall.consolidated-policy",
                "trigger.system.security-rating",
                "webhook.system.automation-stitch",
                "generate.vpn-certificate.csr",
                "upload.system.vmlicense",
                "reset.firewall.multicast-policy6",
                "push.wifi.firmware",
                "eject.system.usb-device",
                "start.system.sniffer",
                "reboot.system.os",
                "reset.firewall.consolidated-policy",
                "set.system.time",
                "remove.user.device",
                "import.vpn-certificate.remote",
                "upload.webproxy.pacfile",
                "push.switch-controller.fsw-firmware",
                "reset.wanopt.peer_stats",
                "delete.vpn.ssl",
                "block.endpoint-control.registration",
                "backup-action.system.fortimanager",
                "start.system.usb-log",
                "system.change-password",
                "reset.firewall.multicast-policy",
                "tunnel_down.vpn.ipsec",
                "clear_all.wifi.rogue_ap",
                "import-seed.user.fortitoken",
                "poe-reset.switch-controller.managed-switch",
                "logout.registration.forticloud",
                "clear_counters.firewall.acl6",
                "restore.system.config",
                "import.vpn-certificate.ca",
                "upload.switch-controller.fsw-firmware",
                "test.user.tacacs-plus",
                "upload.system.config-script",
                "system.password-policy-conform",
                "sms.user.guest",
                "delete.system.config-script",
                "reset.wanopt.history",
                "reset.firewall.policy6",
                "import-mobile.user.fortitoken",
                "download.switch-controller.fsw-firmware",
                "stop.wifi.spectrum",
                "reset.firewall.central-snat-map",
                "login.registration.forticare",
                "create.registration.forticloud",
                "upload.wifi.firmware",
                "start.wifi.spectrum",
                "disconnect.system.modem",
                "disconnect.system.ha-peer",
                "keep-alive.wifi.spectrum",
                "reset.system.modem",
                "activate.user.fortitoken",
                "register-appliance.system.csf",
                "refresh.azure.application-list",
                "start.wifi.vlan-probe",
                "clear.system.sniffer",
                "reset.extender-controller.extender",
                "validate-gcp-key.system.sdn-connector",
                "restart.system.sniffer",
                "import.web-ui.language",
                "import-trial.user.fortitoken",
                "dump.system.com-log",
                "diagnose.extender-controller.extender",
                "update-comments.system.config-revision",
                "refresh.user.fortitoken",
                "reset.firewall.policy",
                "shutdown.system.os",
                "reset.log.stats",
                "revoke.system.dhcp6",
                "login.registration.forticloud",
                "reset.wanopt.webcache",
                "save.system.config-revision",
                "set_status.wifi.managed_ap",
                "deauth.user.firewall",
                "upgrade.extender-controller.extender",
                "delete.system.config-revision",
                "clear_users.user.banned",
                "send-activation.user.fortitoken",
                "reset.webcache.stats",
                "clear_counters.firewall.proxy-policy",
                "utm.rating-lookup",
                "test.system.automation-stitch",
                "refresh.system.external-resource",
                "auth.user.firewall",
                "dhcp-renew.system.interface",
                "migrate.registration.forticloud",
                "clear_counters.firewall.multicast-policy",
                "connect.wifi.network",
                "test-connect.user.radius",
                "speed-test-trigger.system.interface",
                "generate-key.system.api-user",
                "upload.wifi.region-image",
                "run.system.config-script",
                "clear_tunnel.vpn.ssl",
                "add.nsx.service",
                "update.system.fortiguard",
                "restart.switch-controller.managed-switch",
                "unquarantine.endpoint-control.registration",
                "led-blink.wifi.managed_ap",
                "update.system.sdn-connector",
                "config.system.fortimanager",
                "system.disconnect-admins",
                "provision-user.vpn.ssl",
                "create.web-ui.custom-language",
                "check.endpoint-control.registration-password",
                "clear-counters.firewall.dnat",
                "scan.wifi.network",
                "clear.vpn.ike",
                "clear_counters.firewall.security-policy",
                "clear_all.user.banned",
                "delete.firewall.clearpass-address",
                "connect.system.modem",
                "generate-keys.wifi.ssid",
            ],
        }
    }

    check_legacy_fortiosapi()
    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        # Checking system status prevents upload.system.vmlicense from uploading a licence to a newly installed machine.
        connection.set_option('check_system_status', False)

        if 'access_token' in module.params:
            connection.set_option('access_token', module.params['access_token'])

        # Logging for fact module could be disabled/enabled.
        if 'enable_log' in module.params:
            connection.set_option('enable_log', module.params['enable_log'])
        else:
            connection.set_option('enable_log', False)

        fos = FortiOSHandler(connection, module)

        is_error, has_changed, result = fortios_monitor(fos)
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
