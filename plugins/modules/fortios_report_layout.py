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
module: fortios_report_layout
short_description: Report layout configuration in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify report feature and layout category.
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
    report_layout:
        description:
            - Report layout configuration.
        default: null
        type: dict
        suboptions:
            body_item:
                description:
                    - Configure report body item.
                type: list
                suboptions:
                    chart:
                        description:
                            - Report item chart name.
                        type: str
                    chart_options:
                        description:
                            - Report chart options.
                        type: str
                        choices:
                            - include-no-data
                            - hide-title
                            - show-caption
                    column:
                        description:
                            - Report section column number.
                        type: int
                    content:
                        description:
                            - Report item text content.
                        type: str
                    description:
                        description:
                            - Description.
                        type: str
                    drill_down_items:
                        description:
                            - Control how drill down charts are shown.
                        type: str
                    drill_down_types:
                        description:
                            - Control whether keys from the parent being combined or not.
                        type: str
                    hide:
                        description:
                            - Enable/disable hide item in report.
                        type: str
                        choices:
                            - enable
                            - disable
                    id:
                        description:
                            - Report item ID.
                        required: true
                        type: int
                    img_src:
                        description:
                            - Report item image file name.
                        type: str
                    list:
                        description:
                            - Configure report list item.
                        type: list
                        suboptions:
                            content:
                                description:
                                    - List entry content.
                                type: str
                            id:
                                description:
                                    - List entry ID.
                                required: true
                                type: int
                    list_component:
                        description:
                            - Report item list component.
                        type: str
                        choices:
                            - bullet
                            - numbered
                    misc_component:
                        description:
                            - Report item miscellaneous component.
                        type: str
                        choices:
                            - hline
                            - page-break
                            - column-break
                            - section-start
                    parameters:
                        description:
                            - Parameters.
                        type: list
                        suboptions:
                            id:
                                description:
                                    - ID.
                                required: true
                                type: int
                            name:
                                description:
                                    - Field name that match field of parameters defined in dataset.
                                type: str
                            value:
                                description:
                                    - Value to replace corresponding field of parameters defined in dataset.
                                type: str
                    style:
                        description:
                            - Report item style.
                        type: str
                    table_caption_style:
                        description:
                            - Table chart caption style.
                        type: str
                    table_column_widths:
                        description:
                            - Report item table column widths.
                        type: str
                    table_even_row_style:
                        description:
                            - Table chart even row style.
                        type: str
                    table_head_style:
                        description:
                            - Table chart head style.
                        type: str
                    table_odd_row_style:
                        description:
                            - Table chart odd row style.
                        type: str
                    text_component:
                        description:
                            - Report item text component.
                        type: str
                        choices:
                            - text
                            - heading1
                            - heading2
                            - heading3
                    title:
                        description:
                            - Report section title.
                        type: str
                    top_n:
                        description:
                            - Value of top.
                        type: int
                    type:
                        description:
                            - Report item type.
                        type: str
                        choices:
                            - text
                            - image
                            - chart
                            - misc
            cutoff_option:
                description:
                    - Cutoff-option is either run-time or custom.
                type: str
                choices:
                    - run-time
                    - custom
            cutoff_time:
                description:
                    - 'Custom cutoff time to generate report [hh:mm].'
                type: str
            day:
                description:
                    - Schedule days of week to generate report.
                type: str
                choices:
                    - sunday
                    - monday
                    - tuesday
                    - wednesday
                    - thursday
                    - friday
                    - saturday
            description:
                description:
                    - Description.
                type: str
            email_recipients:
                description:
                    - Email recipients for generated reports.
                type: str
            email_send:
                description:
                    - Enable/disable sending emails after reports are generated.
                type: str
                choices:
                    - enable
                    - disable
            format:
                description:
                    - Report format.
                type: list
                choices:
                    - pdf
            max_pdf_report:
                description:
                    - Maximum number of PDF reports to keep at one time (oldest report is overwritten).
                type: int
            name:
                description:
                    - Report layout name.
                required: true
                type: str
            options:
                description:
                    - Report layout options.
                type: list
                choices:
                    - include-table-of-content
                    - auto-numbering-heading
                    - view-chart-as-heading
                    - show-html-navbar-before-heading
                    - dummy-option
            page:
                description:
                    - Configure report page.
                type: dict
                suboptions:
                    column_break_before:
                        description:
                            - Report page auto column break before heading.
                        type: list
                        choices:
                            - heading1
                            - heading2
                            - heading3
                    footer:
                        description:
                            - Configure report page footer.
                        type: dict
                        suboptions:
                            footer_item:
                                description:
                                    - Configure report footer item.
                                type: list
                                suboptions:
                                    content:
                                        description:
                                            - Report item text content.
                                        type: str
                                    description:
                                        description:
                                            - Description.
                                        type: str
                                    id:
                                        description:
                                            - Report item ID.
                                        required: true
                                        type: int
                                    img_src:
                                        description:
                                            - Report item image file name.
                                        type: str
                                    style:
                                        description:
                                            - Report item style.
                                        type: str
                                    type:
                                        description:
                                            - Report item type.
                                        type: str
                                        choices:
                                            - text
                                            - image
                            style:
                                description:
                                    - Report footer style.
                                type: str
                    header:
                        description:
                            - Configure report page header.
                        type: dict
                        suboptions:
                            header_item:
                                description:
                                    - Configure report header item.
                                type: list
                                suboptions:
                                    content:
                                        description:
                                            - Report item text content.
                                        type: str
                                    description:
                                        description:
                                            - Description.
                                        type: str
                                    id:
                                        description:
                                            - Report item ID.
                                        required: true
                                        type: int
                                    img_src:
                                        description:
                                            - Report item image file name.
                                        type: str
                                    style:
                                        description:
                                            - Report item style.
                                        type: str
                                    type:
                                        description:
                                            - Report item type.
                                        type: str
                                        choices:
                                            - text
                                            - image
                            style:
                                description:
                                    - Report header style.
                                type: str
                    options:
                        description:
                            - Report page options.
                        type: list
                        choices:
                            - header-on-first-page
                            - footer-on-first-page
                    page_break_before:
                        description:
                            - Report page auto page break before heading.
                        type: list
                        choices:
                            - heading1
                            - heading2
                            - heading3
                    paper:
                        description:
                            - Report page paper.
                        type: str
                        choices:
                            - a4
                            - letter
            schedule_type:
                description:
                    - Report schedule type.
                type: str
                choices:
                    - demand
                    - daily
                    - weekly
            style_theme:
                description:
                    - Report style theme.
                type: str
            subtitle:
                description:
                    - Report subtitle.
                type: str
            time:
                description:
                    - 'Schedule time to generate report [hh:mm].'
                type: str
            title:
                description:
                    - Report title.
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
  - name: Report layout configuration.
    fortios_report_layout:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      report_layout:
        body_item:
         -
            chart: "<your_own_value>"
            chart_options: "include-no-data"
            column: "6"
            content: "<your_own_value>"
            description: "<your_own_value>"
            drill_down_items: "<your_own_value>"
            drill_down_types: "<your_own_value>"
            hide: "enable"
            id:  "12"
            img_src: "<your_own_value>"
            list:
             -
                content: "<your_own_value>"
                id:  "16"
            list_component: "bullet"
            misc_component: "hline"
            parameters:
             -
                id:  "20"
                name: "default_name_21"
                value: "<your_own_value>"
            style: "<your_own_value>"
            table_caption_style: "<your_own_value>"
            table_column_widths: "<your_own_value>"
            table_even_row_style: "<your_own_value>"
            table_head_style: "<your_own_value>"
            table_odd_row_style: "<your_own_value>"
            text_component: "text"
            title: "<your_own_value>"
            top_n: "31"
            type: "text"
        cutoff_option: "run-time"
        cutoff_time: "<your_own_value>"
        day: "sunday"
        description: "<your_own_value>"
        email_recipients: "<your_own_value>"
        email_send: "enable"
        format: "pdf"
        max_pdf_report: "40"
        name: "default_name_41"
        options: "include-table-of-content"
        page:
            column_break_before: "heading1"
            footer:
                footer_item:
                 -
                    content: "<your_own_value>"
                    description: "<your_own_value>"
                    id:  "49"
                    img_src: "<your_own_value>"
                    style: "<your_own_value>"
                    type: "text"
                style: "<your_own_value>"
            header:
                header_item:
                 -
                    content: "<your_own_value>"
                    description: "<your_own_value>"
                    id:  "58"
                    img_src: "<your_own_value>"
                    style: "<your_own_value>"
                    type: "text"
                style: "<your_own_value>"
            options: "header-on-first-page"
            page_break_before: "heading1"
            paper: "a4"
        schedule_type: "demand"
        style_theme: "<your_own_value>"
        subtitle: "<your_own_value>"
        time: "<your_own_value>"
        title: "<your_own_value>"

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


def filter_report_layout_data(json):
    option_list = ['body_item', 'cutoff_option', 'cutoff_time',
                   'day', 'description', 'email_recipients',
                   'email_send', 'format', 'max_pdf_report',
                   'name', 'options', 'page',
                   'schedule_type', 'style_theme', 'subtitle',
                   'time', 'title']
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
    multilist_attrs = [[u'format'], [u'page', u'column_break_before'], [u'page', u'page_break_before'], [u'page', u'options'], [u'options'], [u'body_item',
                                                                                                                                              u'chart_options']]

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


def report_layout(data, fos, check_mode=False):

    vdom = data['vdom']

    state = data['state']

    report_layout_data = data['report_layout']
    report_layout_data = flatten_multilists_attributes(report_layout_data)
    filtered_data = underscore_to_hyphen(filter_report_layout_data(report_layout_data))

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
        return fos.set('report',
                       'layout',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('report',
                          'layout',
                          mkey=filtered_data['name'],
                          vdom=vdom)
    else:
        fos._module.fail_json(msg='state must be present or absent!')


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_report(data, fos, check_mode):

    if data['report_layout']:
        resp = report_layout(data, fos, check_mode)
    else:
        fos._module.fail_json(msg='missing task body: %s' % ('report_layout'))
    if check_mode:
        return resp
    return not is_successful_status(resp), \
        resp['status'] == "success" and \
        (resp['revision_changed'] if 'revision_changed' in resp else True), \
        resp


versioned_schema = {
    "type": "list",
    "children": {
        "email_recipients": {
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
        "subtitle": {
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
        "style_theme": {
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
        "title": {
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
        "email_send": {
            "type": "string",
            "options": [
                {
                    "value": "enable",
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
                {
                    "value": "disable",
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
            ],
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
        "format": {
            "multiple_values": True,
            "type": "list",
            "options": [
                {
                    "value": "pdf",
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
            ],
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
        "max_pdf_report": {
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
        "page": {
            "type": "dict",
            "children": {
                "footer": {
                    "type": "dict",
                    "children": {
                        "footer_item": {
                            "type": "list",
                            "children": {
                                "style": {
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
                                "content": {
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
                                "img_src": {
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
                                "type": {
                                    "type": "string",
                                    "options": [
                                        {
                                            "value": "text",
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
                                        {
                                            "value": "image",
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
                                    ],
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
                                "id": {
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
                        },
                        "style": {
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
                },
                "column_break_before": {
                    "multiple_values": True,
                    "type": "list",
                    "options": [
                        {
                            "value": "heading1",
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
                        {
                            "value": "heading2",
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
                        {
                            "value": "heading3",
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
                    ],
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
                "header": {
                    "type": "dict",
                    "children": {
                        "style": {
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
                        "header_item": {
                            "type": "list",
                            "children": {
                                "style": {
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
                                "content": {
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
                                "img_src": {
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
                                "type": {
                                    "type": "string",
                                    "options": [
                                        {
                                            "value": "text",
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
                                        {
                                            "value": "image",
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
                                    ],
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
                                "id": {
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
                },
                "paper": {
                    "type": "string",
                    "options": [
                        {
                            "value": "a4",
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
                        {
                            "value": "letter",
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
                    ],
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
                "page_break_before": {
                    "multiple_values": True,
                    "type": "list",
                    "options": [
                        {
                            "value": "heading1",
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
                        {
                            "value": "heading2",
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
                        {
                            "value": "heading3",
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
                    ],
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
                "options": {
                    "multiple_values": True,
                    "type": "list",
                    "options": [
                        {
                            "value": "header-on-first-page",
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
                        {
                            "value": "footer-on-first-page",
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
                    ],
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
        },
        "options": {
            "multiple_values": True,
            "type": "list",
            "options": [
                {
                    "value": "include-table-of-content",
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
                {
                    "value": "auto-numbering-heading",
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
                {
                    "value": "view-chart-as-heading",
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
                {
                    "value": "show-html-navbar-before-heading",
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
                {
                    "value": "dummy-option",
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
            ],
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
        "body_item": {
            "type": "list",
            "children": {
                "list_component": {
                    "type": "string",
                    "options": [
                        {
                            "value": "bullet",
                            "revisions": {
                                "v6.0.0": True,
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
                        {
                            "value": "numbered",
                            "revisions": {
                                "v6.0.0": True,
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
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
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
                "text_component": {
                    "type": "string",
                    "options": [
                        {
                            "value": "text",
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
                        {
                            "value": "heading1",
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
                        {
                            "value": "heading2",
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
                        {
                            "value": "heading3",
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
                    ],
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
                "id": {
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
                "style": {
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
                "hide": {
                    "type": "string",
                    "options": [
                        {
                            "value": "enable",
                            "revisions": {
                                "v6.0.0": True,
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
                        {
                            "value": "disable",
                            "revisions": {
                                "v6.0.0": True,
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
                    ],
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
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
                "parameters": {
                    "type": "list",
                    "children": {
                        "id": {
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
                        "value": {
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
                        "name": {
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
                },
                "title": {
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
                "content": {
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
                "drill_down_types": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
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
                "img_src": {
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
                "table_head_style": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
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
                "drill_down_items": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
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
                "type": {
                    "type": "string",
                    "options": [
                        {
                            "value": "text",
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
                        {
                            "value": "image",
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
                        {
                            "value": "chart",
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
                        {
                            "value": "misc",
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
                    ],
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
                "chart_options": {
                    "multiple_values": True,
                    "type": "list",
                    "options": [
                        {
                            "value": "include-no-data",
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
                        {
                            "value": "hide-title",
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
                        {
                            "value": "show-caption",
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
                    ],
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
                "table_even_row_style": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
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
                "top_n": {
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
                "table_odd_row_style": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
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
                "chart": {
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
                "table_caption_style": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
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
                "table_column_widths": {
                    "type": "string",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
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
                "column": {
                    "type": "integer",
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
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
                "list": {
                    "type": "list",
                    "children": {
                        "content": {
                            "type": "string",
                            "revisions": {
                                "v6.0.0": True,
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
                        "id": {
                            "type": "integer",
                            "revisions": {
                                "v6.0.0": True,
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
                    },
                    "revisions": {
                        "v6.0.0": True,
                        "v7.0.0": False,
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
                "misc_component": {
                    "type": "string",
                    "options": [
                        {
                            "value": "hline",
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
                        {
                            "value": "page-break",
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
                        {
                            "value": "column-break",
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
                        {
                            "value": "section-start",
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
                    ],
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
        },
        "cutoff_time": {
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
        "time": {
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
        "schedule_type": {
            "type": "string",
            "options": [
                {
                    "value": "demand",
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
                {
                    "value": "daily",
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
                {
                    "value": "weekly",
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
            ],
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
        "cutoff_option": {
            "type": "string",
            "options": [
                {
                    "value": "run-time",
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
                {
                    "value": "custom",
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
            ],
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
        "day": {
            "type": "string",
            "options": [
                {
                    "value": "sunday",
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
                {
                    "value": "monday",
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
                {
                    "value": "tuesday",
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
                {
                    "value": "wednesday",
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
                {
                    "value": "thursday",
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
                {
                    "value": "friday",
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
                {
                    "value": "saturday",
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
            ],
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
        "name": {
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
    mkeyname = 'name'
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "enable_log": {"required": False, "type": bool},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "state": {"required": True, "type": "str",
                  "choices": ["present", "absent"]},
        "report_layout": {
            "required": False, "type": "dict", "default": None,
            "options": {
            }
        }
    }
    for attribute_name in module_spec['options']:
        fields["report_layout"]['options'][attribute_name] = module_spec['options'][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["report_layout"]['options'][attribute_name]['required'] = True

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
        versions_check_result = check_schema_versioning(fos, versioned_schema, "report_layout")

        is_error, has_changed, result = fortios_report(module.params, fos, module.check_mode)

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
