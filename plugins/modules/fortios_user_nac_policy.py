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
module: fortios_user_nac_policy
short_description: Configure NAC policy matching pattern to identify matching NAC devices in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify user feature and nac_policy category.
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
    user_nac_policy:
        description:
            - Configure NAC policy matching pattern to identify matching NAC devices.
        default: null
        type: dict
        suboptions:
            category:
                description:
                    - Category of NAC policy.
                type: str
                choices:
                    - device
                    - firewall-user
                    - ems-tag
            description:
                description:
                    - Description for the NAC policy matching pattern.
                type: str
            ems_tag:
                description:
                    - NAC policy matching EMS tag. Source firewall.address.name.
                type: str
            family:
                description:
                    - NAC policy matching family.
                type: str
            host:
                description:
                    - NAC policy matching host.
                type: str
            hw_vendor:
                description:
                    - NAC policy matching hardware vendor.
                type: str
            hw_version:
                description:
                    - NAC policy matching hardware version.
                type: str
            mac:
                description:
                    - NAC policy matching MAC address.
                type: str
            name:
                description:
                    - NAC policy name.
                required: true
                type: str
            os:
                description:
                    - NAC policy matching operating system.
                type: str
            src:
                description:
                    - NAC policy matching source.
                type: str
            ssid_policy:
                description:
                    - SSID policy to be applied on the matched NAC policy. Source wireless-controller.ssid-policy.name.
                type: str
            status:
                description:
                    - Enable/disable NAC policy.
                type: str
                choices:
                    - enable
                    - disable
            sw_version:
                description:
                    - NAC policy matching software version.
                type: str
            switch_auto_auth:
                description:
                    - NAC device auto authorization when discovered and nac-policy matched.
                type: str
                choices:
                    - global
                    - disable
                    - enable
            switch_fortilink:
                description:
                    - FortiLink interface for which this NAC policy belongs to. Source system.interface.name.
                type: str
            switch_mac_policy:
                description:
                    - switch-mac-policy to be applied on the matched NAC policy. Source switch-controller.mac-policy.name.
                type: str
            switch_port_policy:
                description:
                    - switch-port-policy to be applied on the matched NAC policy. Source switch-controller.port-policy.name.
                type: str
            switch_scope:
                description:
                    - List of managed FortiSwitches on which NAC policy can be applied.
                type: list
                suboptions:
                    switch_id:
                        description:
                            - Managed FortiSwitch name from available options. Source switch-controller.managed-switch.switch-id.
                        type: str
            type:
                description:
                    - NAC policy matching type.
                type: str
            user:
                description:
                    - NAC policy matching user.
                type: str
            user_group:
                description:
                    - NAC policy matching user group. Source user.group.name.
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
  - name: Configure NAC policy matching pattern to identify matching NAC devices.
    fortios_user_nac_policy:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      user_nac_policy:
        category: "device"
        description: "<your_own_value>"
        ems_tag: "<your_own_value> (source firewall.address.name)"
        family: "<your_own_value>"
        host: "myhostname"
        hw_vendor: "<your_own_value>"
        hw_version: "<your_own_value>"
        mac: "<your_own_value>"
        name: "default_name_11"
        os: "<your_own_value>"
        src: "<your_own_value>"
        ssid_policy: "<your_own_value> (source wireless-controller.ssid-policy.name)"
        status: "enable"
        sw_version: "<your_own_value>"
        switch_auto_auth: "global"
        switch_fortilink: "<your_own_value> (source system.interface.name)"
        switch_mac_policy: "<your_own_value> (source switch-controller.mac-policy.name)"
        switch_port_policy: "<your_own_value> (source switch-controller.port-policy.name)"
        switch_scope:
         -
            switch_id: "<your_own_value> (source switch-controller.managed-switch.switch-id)"
        type: "<your_own_value>"
        user: "<your_own_value>"
        user_group: "<your_own_value> (source user.group.name)"

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


def filter_user_nac_policy_data(json):
    option_list = ['category', 'description', 'ems_tag',
                   'family', 'host', 'hw_vendor',
                   'hw_version', 'mac', 'name',
                   'os', 'src', 'ssid_policy',
                   'status', 'sw_version', 'switch_auto_auth',
                   'switch_fortilink', 'switch_mac_policy', 'switch_port_policy',
                   'switch_scope', 'type', 'user',
                   'user_group']
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


def user_nac_policy(data, fos, check_mode=False):

    vdom = data['vdom']

    state = data['state']

    user_nac_policy_data = data['user_nac_policy']
    filtered_data = underscore_to_hyphen(filter_user_nac_policy_data(user_nac_policy_data))

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
        return fos.set('user',
                       'nac-policy',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('user',
                          'nac-policy',
                          mkey=filtered_data['name'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_user(data, fos, check_mode):

    if data['user_nac_policy']:
        resp = user_nac_policy(data, fos, check_mode)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('user_nac_policy'))
    if check_mode:
        return resp
    return not is_successful_status(resp), \
        resp['status'] == "success" and \
        (resp['revision_changed'] if 'revision_changed' in resp else True), \
        resp


versioned_schema = {
    "type": "list",
    "children": {
        "ssid_policy": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "family": {
            "type": "string",
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "user_group": {
            "type": "string",
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "switch_fortilink": {
            "type": "string",
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "switch_scope": {
            "type": "list",
            "children": {
                "switch_id": {
                    "type": "string",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            },
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "hw_vendor": {
            "type": "string",
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "category": {
            "type": "string",
            "options": [
                {
                    "value": "device",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "firewall-user",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "ems-tag",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": False
                    }
                }
            ],
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "switch_mac_policy": {
            "type": "string",
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "type": {
            "type": "string",
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "status": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.4": True,
                        "v7.0.0": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "description": {
            "type": "string",
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "src": {
            "type": "string",
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "mac": {
            "type": "string",
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "user": {
            "type": "string",
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "ems_tag": {
            "type": "string",
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": False
            }
        },
        "sw_version": {
            "type": "string",
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "hw_version": {
            "type": "string",
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "name": {
            "type": "string",
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "switch_auto_auth": {
            "type": "string",
            "options": [
                {
                    "value": "global",
                    "revisions": {
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v6.4.4": True,
                        "v6.4.0": True,
                        "v6.4.1": True
                    }
                }
            ],
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": False,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "host": {
            "type": "string",
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "switch_port_policy": {
            "type": "string",
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": False,
                "v6.4.0": True,
                "v6.4.1": True
            }
        },
        "os": {
            "type": "string",
            "revisions": {
                "v6.4.4": True,
                "v7.0.0": True,
                "v6.4.0": True,
                "v6.4.1": True
            }
        }
    },
    "revisions": {
        "v6.4.4": True,
        "v7.0.0": True,
        "v6.4.0": True,
        "v6.4.1": True
    }
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = 'name'
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "enable_log": {"required": False, "type": bool},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "state": {"required": True, "type": "str",
                  "choices": ["present", "absent"]},
        "user_nac_policy": {
            "required": False, "type": "dict", "default": None,
            "options": {
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["user_nac_policy"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["user_nac_policy"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "user_nac_policy")

        is_error, has_changed, result = fortios_user(module.params, fos, module.check_mode)

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
