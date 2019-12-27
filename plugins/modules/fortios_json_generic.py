#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
# Copyright 2019 Fortinet, Inc.
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
module: fortios_json_generic
short_description: Config Fortinet's FortiOS and FortiGate with json generic method.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify json feature and generic category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.4
version_added: "2.9"
author:
    - Frank Shen (@frankshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Requires fortiosapi library developed by Fortinet
    - Run as a local_action in your playbook
requirements:
    - fortiosapi>=0.9.8
options:
    host:
        description:
            - FortiOS or FortiGate IP address.
        type: str
        required: false
    username:
        description:
            - FortiOS or FortiGate username.
        type: str
        required: false
    password:
        description:
            - FortiOS or FortiGate password.
        type: str
        default: ""
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root
    https:
        description:
            - Indicates if the requests towards FortiGate must use HTTPS protocol.
        type: bool
        default: true
    ssl_verify:
        description:
            - Ensures FortiGate certificate must be verified by a proper CA.
        type: bool
        default: true
    json_generic:
        description:
            - json generic
        default: null
        type: dict
        suboptions:
            dictbody:
                description:
                    - Body with YAML list of key/value format
                type: dict
            jsonbody:
                description:
                    - Body with JSON string format, will always give priority to jsonbody
                type: str
            method:
                description:
                    - HTTP methods
                type: str
                choices:
                    - GET
                    - PUT
                    - POST
                    - DELETE
            path:
                description:
                    - URL path, e.g./api/v2/cmdb/firewall/address
                type: str
            specialparams:
                description:
                    - Extra URL parameters, e.g.start=1&count=10
                type: str
'''

EXAMPLES = '''
---
# host
[fortigates]
fortigate01 ansible_host=192.168.52.177 ansible_user="admin" ansible_password="admin"

[fortigates:vars]
ansible_network_os=fortinet.fortios.fortios

# sample1.yml
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
  - name: test add with string
    fortios_json_generic:
      vdom:  "{{ vdom }}"
      json_generic:
        method: "POST"
        path: "/api/v2/cmdb/firewall/address"
        jsonbody: |
          {
          "name": "111",
          "type": "geography",
          "fqdn": "",
          "country": "AL",
          "comment": "ccc",
          "visibility": "enable",
          "associated-interface": "port1",
          "allow-routing": "disable"
          }
    register: info
    
  - name: display vars
    debug: msg="{{info}}" 
    
# sample2.yml
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
  - name: test delete
    fortios_json_generic:
      vdom:  "{{ vdom }}"
      json_generic:
        method: "DELETE"
        path: "/api/v2/cmdb/firewall/address/111"
    register: info
    
  - name: display vars
    debug: msg="{{info}}"

  - name: test add with dict
    fortios_json_generic:
      vdom:  "{{ vdom }}"
      json_generic:
        method: "POST"
        path: "/api/v2/cmdb/firewall/address"
        dictbody:
          name: "111"
          type: "geography"
          fqdn: ""
          country: "AL"
          comment: "ccc"
          visibility: "enable"
          associated-interface: "port1"
          allow-routing: "disable"
    register: info
    
  - name: display vars
    debug: msg="{{info}}"    
    
  - name: test delete
    fortios_json_generic:
      vdom:  "{{ vdom }}"
      json_generic:
        method: "DELETE"
        path: "/api/v2/cmdb/firewall/address/111"
    register: info
    
  - name: display vars
    debug: msg="{{info}}"

  - name: test add with string
    fortios_json_generic:
      vdom:  "{{ vdom }}"
      json_generic:
        method: "POST"
        path: "/api/v2/cmdb/firewall/address"
        jsonbody: |
          {
          "name": "111",
          "type": "geography",
          "fqdn": "",
          "country": "AL",
          "comment": "ccc",
          "visibility": "enable",
          "associated-interface": "port1",
          "allow-routing": "disable"
          }
    register: info
    
  - name: display vars
    debug: msg="{{info}}" 
    
  - name: test speical params
    fortios_json_generic:
      vdom:  "{{ vdom }}"
      json_generic:
        method: "PUT"
        path: "/api/v2/cmdb/firewall/policy/1"
        specialparams: "action=move&after=2"
    register: info
    
  - name: display vars
    debug: msg="{{info}}"


    
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
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import FAIL_SOCKET_MSG
import json
import os

def login(data, fos):
    host = data['host']
    username = data['username']
    password = data['password']
    ssl_verify = data['ssl_verify']

    fos.debug('on')
    if 'https' in data and not data['https']:
        fos.https('off')
    else:
        fos.https('on')

    fos.login(host, username, password, verify=ssl_verify)

def json_generic(data, fos):
    vdom = data['vdom']
    json_generic_data = data['json_generic']

    # Give priority to jsonbody
    data = "";
    if json_generic_data['jsonbody']:
        data = json.loads(json_generic_data['jsonbody'])
    else:
        if json_generic_data['dictbody']:
            data = json_generic_data['dictbody']

    return fos.jsonraw(json_generic_data['method'],
                json_generic_data['path'],
                data=data,
                specific_params=json_generic_data['specialparams'],
                vdom=vdom)


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_json(data, fos):

    if data['json_generic']:
        resp = json_generic(data, fos)

    return not is_successful_status(resp), \
        resp['status'] == "success", \
        resp


def main():
    fields = {
        "host": {"required": False, "type": "str"},
        "username": {"required": False, "type": "str"},
        "password": {"required": False, "type": "str", "default": "", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "ssl_verify": {"required": False, "type": "bool", "default": True},
        "json_generic": {
            "required": False, "type": "dict", "default": None,
            "options": {
                "dictbody": {"required": False, "type": "dict"},
                "jsonbody": {"required": False, "type": "str"},
                "method": {"required": True, "type": "str",
                           "choices": ["GET", "PUT", "POST",
                                       "DELETE"]},
                "path": {"required": True, "type": "str"},
                "specialparams": {"required": False, "type": "str"}

            }
        }
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    # legacy_mode refers to using fortiosapi instead of HTTPAPI
    legacy_mode = 'host' in module.params and module.params['host'] is not None and \
                  'username' in module.params and module.params['username'] is not None and \
                  'password' in module.params and module.params['password'] is not None

    if not legacy_mode:
        if module._socket_path:
            connection = Connection(module._socket_path)
            fos = FortiOSHandler(connection)

            is_error, has_changed, result = fortios_json(module.params, fos)
        else:
            module.fail_json(**FAIL_SOCKET_MSG)
    else:
        module.fail_json(msg="Doesn't support FortiOSAPI, the feature is only supported only in HTTPAPI.")

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
