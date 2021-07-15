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
module: fortios_extender_controller_extender
short_description: Extender controller configuration in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify extender_controller feature and extender category.
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
    extender_controller_extender:
        description:
            - Extender controller configuration.
        default: null
        type: dict
        suboptions:
            aaa_shared_secret:
                description:
                    - AAA shared secret.
                type: str
            access_point_name:
                description:
                    - Access point name(APN).
                type: str
            admin:
                description:
                    - FortiExtender Administration (enable or disable).
                type: str
                choices:
                    - disable
                    - discovered
                    - enable
            at_dial_script:
                description:
                    - Initialization AT commands specific to the MODEM.
                type: str
            authorized:
                description:
                    - FortiExtender Administration (enable or disable).
                type: str
                choices:
                    - disable
                    - enable
            billing_start_day:
                description:
                    - Billing start day.
                type: int
            cdma_aaa_spi:
                description:
                    - CDMA AAA SPI.
                type: str
            cdma_ha_spi:
                description:
                    - CDMA HA SPI.
                type: str
            cdma_nai:
                description:
                    - NAI for CDMA MODEMS.
                type: str
            conn_status:
                description:
                    - Connection status.
                type: int
            controller_report:
                description:
                    - FortiExtender controller report configuration.
                type: dict
                suboptions:
                    interval:
                        description:
                            - Controller report interval.
                        type: int
                    signal_threshold:
                        description:
                            - Controller report signal threshold.
                        type: int
                    status:
                        description:
                            - FortiExtender controller report status.
                        type: str
                        choices:
                            - disable
                            - enable
            description:
                description:
                    - Description.
                type: str
            dial_mode:
                description:
                    - Dial mode (dial-on-demand or always-connect).
                type: str
                choices:
                    - dial-on-demand
                    - always-connect
            dial_status:
                description:
                    - Dial status.
                type: int
            ext_name:
                description:
                    - FortiExtender name.
                type: str
            ha_shared_secret:
                description:
                    - HA shared secret.
                type: str
            id:
                description:
                    - FortiExtender serial number.
                required: true
                type: str
            ifname:
                description:
                    - FortiExtender interface name. Source system.interface.name.
                type: str
            initiated_update:
                description:
                    - Allow/disallow network initiated updates to the MODEM.
                type: str
                choices:
                    - enable
                    - disable
            login_password:
                description:
                    - FortiExtender login password.
                type: str
            mode:
                description:
                    - FortiExtender mode.
                type: str
                choices:
                    - standalone
                    - redundant
            modem_passwd:
                description:
                    - MODEM password.
                type: str
            modem_type:
                description:
                    - MODEM type (CDMA, GSM/LTE or WIMAX).
                type: str
                choices:
                    - cdma
                    - gsm/lte
                    - wimax
            modem1:
                description:
                    - Configuration options for modem 1.
                type: dict
                suboptions:
                    auto_switch:
                        description:
                            - FortiExtender auto switch configuration.
                        type: dict
                        suboptions:
                            dataplan:
                                description:
                                    - Automatically switch based on data usage.
                                type: str
                                choices:
                                    - disable
                                    - enable
                            disconnect:
                                description:
                                    - Auto switch by disconnect.
                                type: str
                                choices:
                                    - disable
                                    - enable
                            disconnect_period:
                                description:
                                    - Automatically switch based on disconnect period.
                                type: int
                            disconnect_threshold:
                                description:
                                    - Automatically switch based on disconnect threshold.
                                type: int
                            signal:
                                description:
                                    - Automatically switch based on signal strength.
                                type: str
                                choices:
                                    - disable
                                    - enable
                            switch_back:
                                description:
                                    - Auto switch with switch back multi-options.
                                type: str
                                choices:
                                    - time
                                    - timer
                            switch_back_time:
                                description:
                                    - 'Automatically switch over to preferred SIM/carrier at a specified time in UTC (HH:MM).'
                                type: str
                            switch_back_timer:
                                description:
                                    - Automatically switch over to preferred SIM/carrier after the given time (3600 - 2147483647 sec).
                                type: int
                    conn_status:
                        description:
                            - Connection status.
                        type: int
                    default_sim:
                        description:
                            - Default SIM selection.
                        type: str
                        choices:
                            - sim1
                            - sim2
                            - carrier
                            - cost
                    gps:
                        description:
                            - FortiExtender GPS enable/disable.
                        type: str
                        choices:
                            - disable
                            - enable
                    ifname:
                        description:
                            - FortiExtender interface name. Source system.interface.name.
                        type: str
                    preferred_carrier:
                        description:
                            - Preferred carrier.
                        type: str
                    redundant_intf:
                        description:
                            - Redundant interface.
                        type: str
                    redundant_mode:
                        description:
                            - FortiExtender mode.
                        type: str
                        choices:
                            - disable
                            - enable
                    sim1_pin:
                        description:
                            - SIM #1 PIN status.
                        type: str
                        choices:
                            - disable
                            - enable
                    sim1_pin_code:
                        description:
                            - SIM #1 PIN password.
                        type: str
                    sim2_pin:
                        description:
                            - SIM #2 PIN status.
                        type: str
                        choices:
                            - disable
                            - enable
                    sim2_pin_code:
                        description:
                            - SIM #2 PIN password.
                        type: str
            modem2:
                description:
                    - Configuration options for modem 2.
                type: dict
                suboptions:
                    auto_switch:
                        description:
                            - FortiExtender auto switch configuration.
                        type: dict
                        suboptions:
                            dataplan:
                                description:
                                    - Automatically switch based on data usage.
                                type: str
                                choices:
                                    - disable
                                    - enable
                            disconnect:
                                description:
                                    - Auto switch by disconnect.
                                type: str
                                choices:
                                    - disable
                                    - enable
                            disconnect_period:
                                description:
                                    - Automatically switch based on disconnect period.
                                type: int
                            disconnect_threshold:
                                description:
                                    - Automatically switch based on disconnect threshold.
                                type: int
                            signal:
                                description:
                                    - Automatically switch based on signal strength.
                                type: str
                                choices:
                                    - disable
                                    - enable
                            switch_back:
                                description:
                                    - Auto switch with switch back multi-options.
                                type: str
                                choices:
                                    - time
                                    - timer
                            switch_back_time:
                                description:
                                    - 'Automatically switch over to preferred SIM/carrier at a specified time in UTC (HH:MM).'
                                type: str
                            switch_back_timer:
                                description:
                                    - Automatically switch over to preferred SIM/carrier after the given time (3600 - 2147483647 sec).
                                type: int
                    conn_status:
                        description:
                            - Connection status.
                        type: int
                    default_sim:
                        description:
                            - Default SIM selection.
                        type: str
                        choices:
                            - sim1
                            - sim2
                            - carrier
                            - cost
                    gps:
                        description:
                            - FortiExtender GPS enable/disable.
                        type: str
                        choices:
                            - disable
                            - enable
                    ifname:
                        description:
                            - FortiExtender interface name. Source system.interface.name.
                        type: str
                    preferred_carrier:
                        description:
                            - Preferred carrier.
                        type: str
                    redundant_intf:
                        description:
                            - Redundant interface.
                        type: str
                    redundant_mode:
                        description:
                            - FortiExtender mode.
                        type: str
                        choices:
                            - disable
                            - enable
                    sim1_pin:
                        description:
                            - SIM #1 PIN status.
                        type: str
                        choices:
                            - disable
                            - enable
                    sim1_pin_code:
                        description:
                            - SIM #1 PIN password.
                        type: str
                    sim2_pin:
                        description:
                            - SIM #2 PIN status.
                        type: str
                        choices:
                            - disable
                            - enable
                    sim2_pin_code:
                        description:
                            - SIM #2 PIN password.
                        type: str
            multi_mode:
                description:
                    - MODEM mode of operation(3G,LTE,etc).
                type: str
                choices:
                    - auto
                    - auto-3g
                    - force-lte
                    - force-3g
                    - force-2g
            name:
                description:
                    - FortiExtender entry name.
                type: str
            ppp_auth_protocol:
                description:
                    - PPP authentication protocol (PAP,CHAP or auto).
                type: str
                choices:
                    - auto
                    - pap
                    - chap
            ppp_echo_request:
                description:
                    - Enable/disable PPP echo request.
                type: str
                choices:
                    - enable
                    - disable
            ppp_password:
                description:
                    - PPP password.
                type: str
            ppp_username:
                description:
                    - PPP username.
                type: str
            primary_ha:
                description:
                    - Primary HA.
                type: str
            quota_limit_mb:
                description:
                    - Monthly quota limit (MB).
                type: int
            redial:
                description:
                    - Number of redials allowed based on failed attempts.
                type: str
                choices:
                    - none
                    - 1
                    - 2
                    - 3
                    - 4
                    - 5
                    - 6
                    - 7
                    - 8
                    - 9
                    - 10
            redundant_intf:
                description:
                    - Redundant interface.
                type: str
            roaming:
                description:
                    - Enable/disable MODEM roaming.
                type: str
                choices:
                    - enable
                    - disable
            role:
                description:
                    - FortiExtender work role(Primary, Secondary, None).
                type: str
                choices:
                    - none
                    - primary
                    - secondary
            secondary_ha:
                description:
                    - Secondary HA.
                type: str
            sim_pin:
                description:
                    - SIM PIN.
                type: str
            vdom:
                description:
                    - VDOM
                type: int
            wimax_auth_protocol:
                description:
                    - WiMax authentication protocol(TLS or TTLS).
                type: str
                choices:
                    - tls
                    - ttls
            wimax_carrier:
                description:
                    - WiMax carrier.
                type: str
            wimax_realm:
                description:
                    - WiMax realm.
                type: str
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
  - name: Extender controller configuration.
    fortios_extender_controller_extender:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      extender_controller_extender:
        aaa_shared_secret: "<your_own_value>"
        access_point_name: "<your_own_value>"
        admin: "disable"
        at_dial_script: "<your_own_value>"
        authorized: "disable"
        billing_start_day: "8"
        cdma_aaa_spi: "<your_own_value>"
        cdma_ha_spi: "<your_own_value>"
        cdma_nai: "<your_own_value>"
        conn_status: "12"
        controller_report:
            interval: "14"
            signal_threshold: "15"
            status: "disable"
        description: "<your_own_value>"
        dial_mode: "dial-on-demand"
        dial_status: "19"
        ext_name: "<your_own_value>"
        ha_shared_secret: "<your_own_value>"
        id:  "22"
        ifname: "<your_own_value> (source system.interface.name)"
        initiated_update: "enable"
        login_password: "<your_own_value>"
        mode: "standalone"
        modem_passwd: "<your_own_value>"
        modem_type: "cdma"
        modem1:
            auto_switch:
                dataplan: "disable"
                disconnect: "disable"
                disconnect_period: "33"
                disconnect_threshold: "34"
                signal: "disable"
                switch_back: "time"
                switch_back_time: "<your_own_value>"
                switch_back_timer: "38"
            conn_status: "39"
            default_sim: "sim1"
            gps: "disable"
            ifname: "<your_own_value> (source system.interface.name)"
            preferred_carrier: "<your_own_value>"
            redundant_intf: "<your_own_value>"
            redundant_mode: "disable"
            sim1_pin: "disable"
            sim1_pin_code: "<your_own_value>"
            sim2_pin: "disable"
            sim2_pin_code: "<your_own_value>"
        modem2:
            auto_switch:
                dataplan: "disable"
                disconnect: "disable"
                disconnect_period: "54"
                disconnect_threshold: "55"
                signal: "disable"
                switch_back: "time"
                switch_back_time: "<your_own_value>"
                switch_back_timer: "59"
            conn_status: "60"
            default_sim: "sim1"
            gps: "disable"
            ifname: "<your_own_value> (source system.interface.name)"
            preferred_carrier: "<your_own_value>"
            redundant_intf: "<your_own_value>"
            redundant_mode: "disable"
            sim1_pin: "disable"
            sim1_pin_code: "<your_own_value>"
            sim2_pin: "disable"
            sim2_pin_code: "<your_own_value>"
        multi_mode: "auto"
        name: "default_name_72"
        ppp_auth_protocol: "auto"
        ppp_echo_request: "enable"
        ppp_password: "<your_own_value>"
        ppp_username: "<your_own_value>"
        primary_ha: "<your_own_value>"
        quota_limit_mb: "78"
        redial: "none"
        redundant_intf: "<your_own_value>"
        roaming: "enable"
        role: "none"
        secondary_ha: "<your_own_value>"
        sim_pin: "<your_own_value>"
        vdom: "85"
        wimax_auth_protocol: "tls"
        wimax_carrier: "<your_own_value>"
        wimax_realm: "<your_own_value>"

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


def filter_extender_controller_extender_data(json):
    option_list = ['aaa_shared_secret', 'access_point_name', 'admin',
                   'at_dial_script', 'authorized', 'billing_start_day',
                   'cdma_aaa_spi', 'cdma_ha_spi', 'cdma_nai',
                   'conn_status', 'controller_report', 'description',
                   'dial_mode', 'dial_status', 'ext_name',
                   'ha_shared_secret', 'id', 'ifname',
                   'initiated_update', 'login_password', 'mode',
                   'modem_passwd', 'modem_type', 'modem1',
                   'modem2', 'multi_mode', 'name',
                   'ppp_auth_protocol', 'ppp_echo_request', 'ppp_password',
                   'ppp_username', 'primary_ha', 'quota_limit_mb',
                   'redial', 'redundant_intf', 'roaming',
                   'role', 'secondary_ha', 'sim_pin',
                   'vdom', 'wimax_auth_protocol', 'wimax_carrier',
                   'wimax_realm']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def flatten_single_path(data, path, index):
    if not data or index == len(path) or path[index] not in data or not data[path[index]]:
        return

    if index == len(path) - 1:
        data[path[index]] = ' '.join(str(elem) for elem in data[path[index]])
    elif isinstance(data[path[index]], list):
        for value in data[path[index]]:
            flatten_single_path(value, path, index + 1)
    else:
        flatten_single_path(data[path[index]], path, index + 1)


def flatten_multilists_attributes(data):
    multilist_attrs = [[u'modem1', u'auto_switch', u'switch_back'], [u'modem2', u'auto_switch', u'switch_back']]

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
            new_data[k.replace('_', '-')] = underscore_to_hyphen(v)
        data = new_data

    return data


def extender_controller_extender(data, fos, check_mode=False):

    vdom = data['vdom']

    state = data['state']

    extender_controller_extender_data = data['extender_controller_extender']
    extender_controller_extender_data = flatten_multilists_attributes(extender_controller_extender_data)
    filtered_data = underscore_to_hyphen(filter_extender_controller_extender_data(extender_controller_extender_data))

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
        return fos.set('extender-controller',
                       'extender',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('extender-controller',
                          'extender',
                          mkey=filtered_data['id'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_extender_controller(data, fos, check_mode):

    if data['extender_controller_extender']:
        resp = extender_controller_extender(data, fos, check_mode)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('extender_controller_extender'))
    if check_mode:
        return resp
    return not is_successful_status(resp), \
        resp['status'] == "success" and \
        (resp['revision_changed'] if 'revision_changed' in resp else True), \
        resp


versioned_schema = {
    "type": "list",
    "children": {
        "controller_report": {
            "type": "dict",
            "children": {
                "status": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                },
                "interval": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                },
                "signal_threshold": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                }
            },
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": False
            }
        },
        "cdma_nai": {
            "type": "string",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": False,
                "v6.0.5": True,
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "wimax_auth_protocol": {
            "type": "string",
            "options": [
                {
                    "value": "tls",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "ttls",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
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
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "secondary_ha": {
            "type": "string",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": False,
                "v6.0.5": True,
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "wimax_realm": {
            "type": "string",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": False,
                "v6.0.5": True,
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "cdma_aaa_spi": {
            "type": "string",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": False,
                "v6.0.5": True,
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "redial": {
            "type": "string",
            "options": [
                {
                    "value": "none",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "1",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "2",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "3",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "4",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "5",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "6",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "7",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "8",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "9",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "10",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
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
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "id": {
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
        "ppp_auth_protocol": {
            "type": "string",
            "options": [
                {
                    "value": "auto",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "pap",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "chap",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
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
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "initiated_update": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
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
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "multi_mode": {
            "type": "string",
            "options": [
                {
                    "value": "auto",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "auto-3g",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "force-lte",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "force-3g",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "force-2g",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
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
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "ppp_echo_request": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
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
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "ext_name": {
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
        "role": {
            "type": "string",
            "options": [
                {
                    "value": "none",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "primary",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "secondary",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
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
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "authorized": {
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                }
            ],
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": False
            }
        },
        "ppp_username": {
            "type": "string",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": False,
                "v6.0.5": True,
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "quota_limit_mb": {
            "type": "integer",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": False,
                "v6.0.5": True,
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "ifname": {
            "type": "string",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": False,
                "v6.0.5": True,
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "dial_status": {
            "type": "integer",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": False,
                "v6.0.5": True,
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "wimax_carrier": {
            "type": "string",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": False,
                "v6.0.5": True,
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "description": {
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
        "ha_shared_secret": {
            "type": "string",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": False,
                "v6.0.5": True,
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "at_dial_script": {
            "type": "string",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": False,
                "v6.0.5": True,
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "ppp_password": {
            "type": "string",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": False,
                "v6.0.5": True,
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "modem_type": {
            "type": "string",
            "options": [
                {
                    "value": "cdma",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "gsm/lte",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "wimax",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
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
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "conn_status": {
            "type": "integer",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": False,
                "v6.0.5": True,
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "modem1": {
            "type": "dict",
            "children": {
                "sim1_pin": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                },
                "auto_switch": {
                    "type": "dict",
                    "children": {
                        "dataplan": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v6.4.4": True,
                                        "v7.0.0": True,
                                        "v6.4.0": True
                                    }
                                },
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v6.4.4": True,
                                        "v7.0.0": True,
                                        "v6.4.0": True
                                    }
                                }
                            ],
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        "disconnect": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v6.4.4": True,
                                        "v7.0.0": True,
                                        "v6.4.0": True
                                    }
                                },
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v6.4.4": True,
                                        "v7.0.0": True,
                                        "v6.4.0": True
                                    }
                                }
                            ],
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        "switch_back_time": {
                            "type": "string",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        "switch_back_timer": {
                            "type": "integer",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        "switch_back": {
                            "multiple_values": True,
                            "type": "list",
                            "options": [
                                {
                                    "value": "time",
                                    "revisions": {
                                        "v6.4.4": True,
                                        "v7.0.0": True,
                                        "v6.4.0": True
                                    }
                                },
                                {
                                    "value": "timer",
                                    "revisions": {
                                        "v6.4.4": True,
                                        "v7.0.0": True,
                                        "v6.4.0": True
                                    }
                                }
                            ],
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        "signal": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v6.4.4": True,
                                        "v7.0.0": True,
                                        "v6.4.0": True
                                    }
                                },
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v6.4.4": True,
                                        "v7.0.0": True,
                                        "v6.4.0": True
                                    }
                                }
                            ],
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        "disconnect_period": {
                            "type": "integer",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        "disconnect_threshold": {
                            "type": "integer",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        }
                    },
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                },
                "sim2_pin_code": {
                    "type": "string",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                },
                "conn_status": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                },
                "sim1_pin_code": {
                    "type": "string",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                },
                "default_sim": {
                    "type": "string",
                    "options": [
                        {
                            "value": "sim1",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        {
                            "value": "sim2",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        {
                            "value": "carrier",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        {
                            "value": "cost",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                },
                "redundant_intf": {
                    "type": "string",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                },
                "redundant_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                },
                "ifname": {
                    "type": "string",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                },
                "preferred_carrier": {
                    "type": "string",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                },
                "sim2_pin": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                },
                "gps": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                }
            },
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": False
            }
        },
        "modem2": {
            "type": "dict",
            "children": {
                "sim1_pin": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                },
                "auto_switch": {
                    "type": "dict",
                    "children": {
                        "dataplan": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v6.4.4": True,
                                        "v7.0.0": True,
                                        "v6.4.0": True
                                    }
                                },
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v6.4.4": True,
                                        "v7.0.0": True,
                                        "v6.4.0": True
                                    }
                                }
                            ],
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        "disconnect": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v6.4.4": True,
                                        "v7.0.0": True,
                                        "v6.4.0": True
                                    }
                                },
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v6.4.4": True,
                                        "v7.0.0": True,
                                        "v6.4.0": True
                                    }
                                }
                            ],
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        "switch_back_time": {
                            "type": "string",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        "switch_back_timer": {
                            "type": "integer",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        "switch_back": {
                            "multiple_values": True,
                            "type": "list",
                            "options": [
                                {
                                    "value": "time",
                                    "revisions": {
                                        "v6.4.4": True,
                                        "v7.0.0": True,
                                        "v6.4.0": True
                                    }
                                },
                                {
                                    "value": "timer",
                                    "revisions": {
                                        "v6.4.4": True,
                                        "v7.0.0": True,
                                        "v6.4.0": True
                                    }
                                }
                            ],
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        "signal": {
                            "type": "string",
                            "options": [
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v6.4.4": True,
                                        "v7.0.0": True,
                                        "v6.4.0": True
                                    }
                                },
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v6.4.4": True,
                                        "v7.0.0": True,
                                        "v6.4.0": True
                                    }
                                }
                            ],
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        "disconnect_period": {
                            "type": "integer",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        "disconnect_threshold": {
                            "type": "integer",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        }
                    },
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                },
                "sim2_pin_code": {
                    "type": "string",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                },
                "conn_status": {
                    "type": "integer",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                },
                "sim1_pin_code": {
                    "type": "string",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                },
                "default_sim": {
                    "type": "string",
                    "options": [
                        {
                            "value": "sim1",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        {
                            "value": "sim2",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        {
                            "value": "carrier",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        {
                            "value": "cost",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                },
                "redundant_intf": {
                    "type": "string",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                },
                "redundant_mode": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                },
                "ifname": {
                    "type": "string",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                },
                "preferred_carrier": {
                    "type": "string",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                },
                "sim2_pin": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                },
                "gps": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        },
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.4.4": True,
                                "v7.0.0": True,
                                "v6.4.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True
                    }
                }
            },
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": False
            }
        },
        "login_password": {
            "type": "string",
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": False
            }
        },
        "roaming": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
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
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "billing_start_day": {
            "type": "integer",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": False,
                "v6.0.5": True,
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "access_point_name": {
            "type": "string",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": False,
                "v6.0.5": True,
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "cdma_ha_spi": {
            "type": "string",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": False,
                "v6.0.5": True,
                "v6.4.4": False,
                "v6.4.0": False,
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
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": False
            }
        },
        "modem_passwd": {
            "type": "string",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": False,
                "v6.0.5": True,
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "admin": {
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "discovered",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
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
                        "v6.0.5": True,
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
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "dial_mode": {
            "type": "string",
            "options": [
                {
                    "value": "dial-on-demand",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "always-connect",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
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
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "primary_ha": {
            "type": "string",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": False,
                "v6.0.5": True,
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "vdom": {
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
        "mode": {
            "type": "string",
            "options": [
                {
                    "value": "standalone",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
                        "v6.4.1": True,
                        "v6.2.0": True,
                        "v6.2.3": True,
                        "v6.2.5": True,
                        "v6.2.7": True,
                        "v6.0.11": True
                    }
                },
                {
                    "value": "redundant",
                    "revisions": {
                        "v6.0.0": True,
                        "v6.0.5": True,
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
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "redundant_intf": {
            "type": "string",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": False,
                "v6.0.5": True,
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "aaa_shared_secret": {
            "type": "string",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": False,
                "v6.0.5": True,
                "v6.4.4": False,
                "v6.4.0": False,
                "v6.4.1": True,
                "v6.2.0": True,
                "v6.2.3": True,
                "v6.2.5": True,
                "v6.2.7": True,
                "v6.0.11": True
            }
        },
        "sim_pin": {
            "type": "string",
            "revisions": {
                "v6.0.0": True,
                "v7.0.0": False,
                "v6.0.5": True,
                "v6.4.4": False,
                "v6.4.0": False,
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
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = 'id'
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "enable_log": {"required": False, "type": bool},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "state": {"required": True, "type": "str",
                  "choices": ["present", "absent"]},
        "extender_controller_extender": {
            "required": False, "type": "dict", "default": None,
            "options": {
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["extender_controller_extender"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["extender_controller_extender"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "extender_controller_extender")

        is_error, has_changed, result = fortios_extender_controller(module.params, fos, module.check_mode)

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
