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
module: fortios_system_federated_upgrade
short_description: Coordinate federated upgrades within the Security Fabric in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and federated_upgrade category.
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

    system_federated_upgrade:
        description:
            - Coordinate federated upgrades within the Security Fabric.
        default: null
        type: dict
        suboptions:
            node_list:
                description:
                    - Nodes which will be included in the upgrade.
                type: list
                suboptions:
                    coordinating_fortigate:
                        description:
                            - The serial of the FortiGate that controls this device
                        type: str
                    device_type:
                        description:
                            - What type of device this node represents.
                        type: str
                        choices:
                            - fortigate
                            - fortiswitch
                            - fortiap
                    serial:
                        description:
                            - Serial number of the node to include.
                        required: true
                        type: str
                    setup_time:
                        description:
                            - 'When the upgrade was configured. Format hh:mm yyyy/mm/dd UTC.'
                        type: str
                    time:
                        description:
                            - 'Scheduled time for the upgrade. Format hh:mm yyyy/mm/dd UTC.'
                        type: str
                    timing:
                        description:
                            - Whether the upgrade should be run immediately, or at a scheduled time.
                        type: str
                        choices:
                            - immediate
                            - scheduled
                    upgrade_path:
                        description:
                            - Image IDs to upgrade through.
                        type: str
            status:
                description:
                    - Current status of the upgrade.
                type: str
                choices:
                    - disabled
                    - initialized
                    - downloading
                    - download-failed
                    - device-disconnected
                    - ready
                    - staging
                    - cancelled
                    - confirmed
                    - done
                    - failed
            upgrade_id:
                description:
                    - Unique identifier for this upgrade.
                type: int
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
  - name: Coordinate federated upgrades within the Security Fabric.
    fortios_system_federated_upgrade:
      vdom:  "{{ vdom }}"
      system_federated_upgrade:
        node_list:
         -
            coordinating_fortigate: "<your_own_value>"
            device_type: "fortigate"
            serial: "<your_own_value>"
            setup_time: "<your_own_value>"
            time: "<your_own_value>"
            timing: "immediate"
            upgrade_path: "<your_own_value>"
        status: "disabled"
        upgrade_id: "12"

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


def filter_system_federated_upgrade_data(json):
    option_list = ['node_list', 'status', 'upgrade_id']
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


def system_federated_upgrade(data, fos):
    vdom = data['vdom']
    system_federated_upgrade_data = data['system_federated_upgrade']
    filtered_data = underscore_to_hyphen(filter_system_federated_upgrade_data(system_federated_upgrade_data))

    return fos.set('system',
                   'federated-upgrade',
                   data=filtered_data,
                   vdom=vdom)


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_system(data, fos):

    if data['system_federated_upgrade']:
        resp = system_federated_upgrade(data, fos)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('system_federated_upgrade'))

    return not is_successful_status(resp), \
        resp['status'] == "success" and \
        (resp['revision_changed'] if 'revision_changed' in resp else True), \
        resp


versioned_schema = {
    "type": "dict",
    "children": {
        "status": {
            "type": "string",
            "options": [
                {
                    "value": "disabled",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "initialized",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "downloading",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "download-failed",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "device-disconnected",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "ready",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "staging",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "cancelled",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "confirmed",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "done",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                {
                    "value": "failed",
                    "revisions": {
                        "v7.0.0": True
                    }
                }
            ],
            "revisions": {
                "v7.0.0": True
            }
        },
        "node_list": {
            "type": "list",
            "children": {
                "coordinating_fortigate": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "upgrade_path": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "setup_time": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "device_type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "fortigate",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "fortiswitch",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "fortiap",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "time": {
                    "type": "string",
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "timing": {
                    "type": "string",
                    "options": [
                        {
                            "value": "immediate",
                            "revisions": {
                                "v7.0.0": True
                            }
                        },
                        {
                            "value": "scheduled",
                            "revisions": {
                                "v7.0.0": True
                            }
                        }
                    ],
                    "revisions": {
                        "v7.0.0": True
                    }
                },
                "serial": {
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
        "upgrade_id": {
            "type": "integer",
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
    mkeyname = None
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "enable_log": {"required": False, "type": bool},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "system_federated_upgrade": {
            "required": False, "type": "dict", "default": None,
            "options": {
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["system_federated_upgrade"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_federated_upgrade"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "system_federated_upgrade")

        is_error, has_changed, result = fortios_system(module.params, fos)

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
