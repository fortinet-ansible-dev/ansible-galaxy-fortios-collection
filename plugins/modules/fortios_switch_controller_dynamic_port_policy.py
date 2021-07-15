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
module: fortios_switch_controller_dynamic_port_policy
short_description: Configure Dynamic port policy to be applied on the managed FortiSwitch ports through DPP device in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify switch_controller feature and dynamic_port_policy category.
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
    switch_controller_dynamic_port_policy:
        description:
            - Configure Dynamic port policy to be applied on the managed FortiSwitch ports through DPP device.
        default: null
        type: dict
        suboptions:
            description:
                description:
                    - Description for the Dynamic port policy.
                type: str
            fortilink:
                description:
                    - FortiLink interface for which this Dynamic port policy belongs to. Source system.interface.name.
                type: str
            name:
                description:
                    - Dynamic port policy name.
                required: true
                type: str
            policy:
                description:
                    - Port policies with matching criteria and actions.
                type: list
                suboptions:
                    802_1x:
                        description:
                            - 802.1x security policy to be applied when using this policy. Source switch-controller.security-policy.802-1X.name
                               switch-controller.security-policy.captive-portal.name.
                        type: str
                    bounce_port_link:
                        description:
                            - Enable/disable bouncing (administratively bring the link down, up) of a switch port where this policy is applied. Helps to clear
                               and reassign VLAN from lldp-profile.
                        type: str
                        choices:
                            - disable
                            - enable
                    category:
                        description:
                            - Category of Dynamic port policy.
                        type: str
                        choices:
                            - device
                            - interface-tag
                    description:
                        description:
                            - Description for the policy.
                        type: str
                    family:
                        description:
                            - Policy matching family.
                        type: str
                    host:
                        description:
                            - Policy matching host.
                        type: str
                    interface_tags:
                        description:
                            - Policy matching the FortiSwitch interface object tags.
                        type: list
                        suboptions:
                            tag_name:
                                description:
                                    - FortiSwitch port tag name. Source switch-controller.switch-interface-tag.name.
                                type: str
                    lldp_profile:
                        description:
                            - LLDP profile to be applied when using this policy. Source switch-controller.lldp-profile.name.
                        type: str
                    mac:
                        description:
                            - Policy matching MAC address.
                        type: str
                    name:
                        description:
                            - Policy name.
                        required: true
                        type: str
                    qos_policy:
                        description:
                            - QoS policy to be applied when using this policy. Source switch-controller.qos.qos-policy.name.
                        type: str
                    status:
                        description:
                            - Enable/disable policy.
                        type: str
                        choices:
                            - enable
                            - disable
                    type:
                        description:
                            - Policy matching type.
                        type: str
                    vlan_policy:
                        description:
                            - VLAN policy to be applied when using this policy. Source switch-controller.vlan-policy.name.
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
  - name: Configure Dynamic port policy to be applied on the managed FortiSwitch ports through DPP device.
    fortios_switch_controller_dynamic_port_policy:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      switch_controller_dynamic_port_policy:
        description: "<your_own_value>"
        fortilink: "<your_own_value> (source system.interface.name)"
        name: "default_name_5"
        policy:
         -
            802_1x: "<your_own_value> (source switch-controller.security-policy.802-1X.name switch-controller.security-policy.captive-portal.name)"
            bounce_port_link: "disable"
            category: "device"
            description: "<your_own_value>"
            family: "<your_own_value>"
            host: "myhostname"
            interface_tags:
             -
                tag_name: "<your_own_value> (source switch-controller.switch-interface-tag.name)"
            lldp_profile: "<your_own_value> (source switch-controller.lldp-profile.name)"
            mac: "<your_own_value>"
            name: "default_name_17"
            qos_policy: "<your_own_value> (source switch-controller.qos.qos-policy.name)"
            status: "enable"
            type: "<your_own_value>"
            vlan_policy: "<your_own_value> (source switch-controller.vlan-policy.name)"

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


def filter_switch_controller_dynamic_port_policy_data(json):
    option_list = ['description', 'fortilink', 'name',
                   'policy']
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


def switch_controller_dynamic_port_policy(data, fos):
    vdom = data['vdom']

    state = data['state']

    switch_controller_dynamic_port_policy_data = data['switch_controller_dynamic_port_policy']
    filtered_data = underscore_to_hyphen(filter_switch_controller_dynamic_port_policy_data(switch_controller_dynamic_port_policy_data))

    if state == "present" or state is True:
        return fos.set('switch-controller',
                       'dynamic-port-policy',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('switch-controller',
                          'dynamic-port-policy',
                          mkey=filtered_data['name'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_switch_controller(data, fos):

    if data['switch_controller_dynamic_port_policy']:
        resp = switch_controller_dynamic_port_policy(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('switch_controller_dynamic_port_policy'))

    return not is_successful_status(resp), \
        resp['status'] == "success" and \
        (resp['revision_changed'] if 'revision_changed' in resp else True), \
        resp


versioned_schema = {
    "type": "list",
    "children": {
        "policy": {
            "type": "list",
            "children": {
                "status": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "category": {
                    "type": "string",
                    "options": [
                        {
                            "value": "device",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "interface-tag",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "lldp_profile": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "name": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "family": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "interface_tags": {
                    "type": "list",
                    "children": {
                        "tag_name": {
                            "type": "string",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    },
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "host": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "mac": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "vlan_policy": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "bounce_port_link": {
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "802_1x": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "qos_policy": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "type": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "description": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            },
            "revisions": {
                "v7.0.0": True
            }
        },
        "fortilink": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "name": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        },
        "description": {
            "type": "string",
            "revisions": {
                "v7.0.0": True
            }
        }
    },
    "revisions": {
        "v7.0.0": True
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
        "switch_controller_dynamic_port_policy": {
            "required": False, "type": "dict", "default": None,
            "options": {
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["switch_controller_dynamic_port_policy"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["switch_controller_dynamic_port_policy"]['options'][attribute_name]['required'] = True

    check_legacy_fortiosapi()
    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "switch_controller_dynamic_port_policy")

        is_error, has_changed, result = fortios_switch_controller(module.params, fos)

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
