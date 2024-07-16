#!/usr/bin/python
from __future__ import absolute_import, division, print_function

# Copyright: (c) 2022 Fortinet
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

__metaclass__ = type

ANSIBLE_METADATA = {
    "status": ["preview"],
    "supported_by": "community",
    "metadata_version": "1.1",
}

DOCUMENTATION = """
---
module: fortios_dlp_sensor
short_description: Configure sensors used by DLP blocking in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify dlp feature and sensor category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.0
version_added: "2.0.0"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@frankshen01)
    - Miguel Angel Munoz (@mamunozgonzalez)
    - Nicolas Thomas (@thomnico)
notes:
    - Legacy fortiosapi has been deprecated, httpapi is the preferred way to run playbooks

    - The module supports check_mode.

requirements:
    - ansible>=2.15
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
    member_path:
        type: str
        description:
            - Member attribute path to operate on.
            - Delimited by a slash character if there are more than one attribute.
            - Parameter marked with member_path is legitimate for doing member operation.
    member_state:
        type: str
        description:
            - Add or delete a member under specified attribute path.
            - When member_state is specified, the state option is ignored.
        choices:
            - 'present'
            - 'absent'

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - 'present'
            - 'absent'
    dlp_sensor:
        description:
            - Configure sensors used by DLP blocking.
        default: null
        type: dict
        suboptions:
            comment:
                description:
                    - Optional comments.
                type: str
            dlp_log:
                description:
                    - Enable/disable DLP logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            entries:
                description:
                    - DLP sensor entries.
                type: list
                elements: dict
                suboptions:
                    count:
                        description:
                            - Count of dictionary matches to trigger sensor entry match (Dictionary might not be able to trigger more than once based on its
                               "repeat" option, 1 - 255).
                        type: int
                    dictionary:
                        description:
                            - Select a DLP dictionary or exact-data-match. Source dlp.dictionary.name dlp.exact-data-match.name.
                        type: str
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    status:
                        description:
                            - Enable/disable this entry.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            eval:
                description:
                    - Expression to evaluate.
                type: str
            extended_log:
                description:
                    - Enable/disable extended logging for data leak prevention.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            feature_set:
                description:
                    - Flow/proxy feature set.
                type: str
                choices:
                    - 'flow'
                    - 'proxy'
            filter:
                description:
                    - Set up DLP filters for this sensor.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Action to take with content that this DLP sensor matches.
                        type: str
                        choices:
                            - 'allow'
                            - 'log-only'
                            - 'block'
                            - 'quarantine-ip'
                    archive:
                        description:
                            - Enable/disable DLP archiving.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    company_identifier:
                        description:
                            - Enter a company identifier watermark to match. Only watermarks that your company has placed on the files are matched.
                        type: str
                    expiry:
                        description:
                            - Quarantine duration in days, hours, minutes (format = dddhhmm).
                        type: str
                    file_size:
                        description:
                            - Match files this size or larger (0 - 4294967295 kbytes).
                        type: int
                    file_type:
                        description:
                            - Select the number of a DLP file pattern table to match. Source dlp.filepattern.id.
                        type: int
                    filter_by:
                        description:
                            - Select the type of content to match.
                        type: str
                        choices:
                            - 'credit-card'
                            - 'ssn'
                            - 'regexp'
                            - 'file-type'
                            - 'file-size'
                            - 'fingerprint'
                            - 'watermark'
                            - 'encrypted'
                    fp_sensitivity:
                        description:
                            - Select a DLP file pattern sensitivity to match.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Select a DLP sensitivity. Source dlp.fp-sensitivity.name.
                                required: true
                                type: str
                    id:
                        description:
                            - ID. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    match_percentage:
                        description:
                            - Percentage of fingerprints in the fingerprint databases designated with the selected sensitivity to match.
                        type: int
                    name:
                        description:
                            - Filter name.
                        type: str
                    proto:
                        description:
                            - Check messages or files over one or more of these protocols.
                        type: list
                        elements: str
                        choices:
                            - 'smtp'
                            - 'pop3'
                            - 'imap'
                            - 'http-get'
                            - 'http-post'
                            - 'ftp'
                            - 'nntp'
                            - 'mapi'
                            - 'ssh'
                            - 'cifs'
                            - 'mm1'
                            - 'mm3'
                            - 'mm4'
                            - 'mm7'
                    regexp:
                        description:
                            - Enter a regular expression to match (max. 255 characters).
                        type: str
                    sensitivity:
                        description:
                            - Select a DLP file pattern sensitivity to match.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Select a DLP sensitivity. Source dlp.sensitivity.name.
                                required: true
                                type: str
                    severity:
                        description:
                            - Select the severity or threat level that matches this filter.
                        type: str
                        choices:
                            - 'info'
                            - 'low'
                            - 'medium'
                            - 'high'
                            - 'critical'
                    type:
                        description:
                            - Select whether to check the content of messages (an email message) or files (downloaded files or email attachments).
                        type: str
                        choices:
                            - 'file'
                            - 'fos_message'
            flow_based:
                description:
                    - Enable/disable flow-based DLP.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            full_archive_proto:
                description:
                    - Protocols to always content archive.
                type: list
                elements: str
                choices:
                    - 'smtp'
                    - 'pop3'
                    - 'imap'
                    - 'http-get'
                    - 'http-post'
                    - 'ftp'
                    - 'nntp'
                    - 'mapi'
                    - 'ssh'
                    - 'cifs'
                    - 'mm1'
                    - 'mm3'
                    - 'mm4'
                    - 'mm7'
            match_type:
                description:
                    - Logical relation between entries .
                type: str
                choices:
                    - 'match-all'
                    - 'match-any'
                    - 'match-eval'
            nac_quar_log:
                description:
                    - Enable/disable NAC quarantine logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            name:
                description:
                    - Name of table containing the sensor.
                required: true
                type: str
            options:
                description:
                    - Configure DLP options.
                type: str
            replacemsg_group:
                description:
                    - Replacement message group used by this DLP sensor. Source system.replacemsg-group.name.
                type: str
            summary_proto:
                description:
                    - Protocols to always log summary.
                type: list
                elements: str
                choices:
                    - 'smtp'
                    - 'pop3'
                    - 'imap'
                    - 'http-get'
                    - 'http-post'
                    - 'ftp'
                    - 'nntp'
                    - 'mapi'
                    - 'ssh'
                    - 'cifs'
                    - 'mm1'
                    - 'mm3'
                    - 'mm4'
                    - 'mm7'
"""

EXAMPLES = """
- name: Configure sensors used by DLP blocking.
  fortinet.fortios.fortios_dlp_sensor:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      dlp_sensor:
          comment: "Optional comments."
          dlp_log: "enable"
          entries:
              -
                  count: "1"
                  dictionary: "<your_own_value> (source dlp.dictionary.name dlp.exact-data-match.name)"
                  id: "8"
                  status: "enable"
          eval: "<your_own_value>"
          extended_log: "enable"
          feature_set: "flow"
          filter:
              -
                  action: "allow"
                  archive: "disable"
                  company_identifier: "myId_16"
                  expiry: "<your_own_value>"
                  file_size: "10"
                  file_type: "0"
                  filter_by: "credit-card"
                  fp_sensitivity:
                      -
                          name: "default_name_22 (source dlp.fp-sensitivity.name)"
                  id: "23"
                  match_percentage: "10"
                  name: "default_name_25"
                  proto: "smtp"
                  regexp: "<your_own_value>"
                  sensitivity:
                      -
                          name: "default_name_29 (source dlp.sensitivity.name)"
                  severity: "info"
                  type: "file"
          flow_based: "enable"
          full_archive_proto: "smtp"
          match_type: "match-all"
          nac_quar_log: "enable"
          name: "default_name_36"
          options: "<your_own_value>"
          replacemsg_group: "<your_own_value> (source system.replacemsg-group.name)"
          summary_proto: "smtp"
"""

RETURN = """
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
"""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    FortiOSHandler,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_legacy_fortiosapi,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    schema_to_module_spec,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_schema_versioning,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import (
    FAIL_SOCKET_MSG,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.data_post_processor import (
    remove_invalid_fields,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    is_same_comparison,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    serialize,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    find_current_values,
)


def filter_dlp_sensor_data(json):
    option_list = [
        "comment",
        "dlp_log",
        "entries",
        "eval",
        "extended_log",
        "feature_set",
        "filter",
        "flow_based",
        "full_archive_proto",
        "match_type",
        "nac_quar_log",
        "name",
        "options",
        "replacemsg_group",
        "summary_proto",
    ]

    json = remove_invalid_fields(json)
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def flatten_single_path(data, path, index):
    if (
        not data
        or index == len(path)
        or path[index] not in data
        or not data[path[index]]
    ):
        return

    if index == len(path) - 1:
        data[path[index]] = " ".join(str(elem) for elem in data[path[index]])
    elif isinstance(data[path[index]], list):
        for value in data[path[index]]:
            flatten_single_path(value, path, index + 1)
    else:
        flatten_single_path(data[path[index]], path, index + 1)


def flatten_multilists_attributes(data):
    multilist_attrs = [
        ["filter", "proto"],
        ["full_archive_proto"],
        ["summary_proto"],
    ]

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
            new_data[k.replace("_", "-")] = underscore_to_hyphen(v)
        data = new_data

    return data


def valid_attr_to_invalid_attr(data):
    speciallist = {"message": "fos_message"}

    for k, v in speciallist.items():
        if v == data:
            return k

    return data


def valid_attr_to_invalid_attrs(data):
    if isinstance(data, list):
        new_data = []
        for elem in data:
            elem = valid_attr_to_invalid_attrs(elem)
            new_data.append(elem)
        data = new_data
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[valid_attr_to_invalid_attr(k)] = valid_attr_to_invalid_attrs(v)
        data = new_data

    return valid_attr_to_invalid_attr(data)


def dlp_sensor(data, fos, check_mode=False):
    state = None
    vdom = data["vdom"]

    state = data["state"]

    dlp_sensor_data = data["dlp_sensor"]
    dlp_sensor_data = flatten_multilists_attributes(dlp_sensor_data)
    filtered_data = filter_dlp_sensor_data(dlp_sensor_data)
    converted_data = underscore_to_hyphen(valid_attr_to_invalid_attrs(filtered_data))

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("dlp", "sensor", filtered_data, vdom=vdom)
        current_data = fos.get("dlp", "sensor", vdom=vdom, mkey=mkey)
        is_existed = (
            current_data
            and current_data.get("http_status") == 200
            and isinstance(current_data.get("results"), list)
            and len(current_data["results"]) > 0
        )

        # 2. if it exists and the state is 'present' then compare current settings with desired
        if state == "present" or state is True:
            if mkey is None:
                return False, True, filtered_data, diff

            # if mkey exists then compare each other
            # record exits and they're matched or not
            if is_existed:
                is_same = is_same_comparison(
                    serialize(current_data["results"][0]), serialize(filtered_data)
                )

                current_values = find_current_values(
                    current_data["results"][0], filtered_data
                )

                return (
                    False,
                    not is_same,
                    filtered_data,
                    {"before": current_values, "after": filtered_data},
                )

            # record does not exist
            return False, True, filtered_data, diff

        if state == "absent":
            if mkey is None:
                return (
                    False,
                    False,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )

            if is_existed:
                return (
                    False,
                    True,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )
            return False, False, filtered_data, {}

        return True, False, {"reason: ": "Must provide state parameter"}, {}

    if state == "present" or state is True:
        return fos.set("dlp", "sensor", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("dlp", "sensor", mkey=converted_data["name"], vdom=vdom)
    else:
        fos._module.fail_json(msg="state must be present or absent!")


def is_successful_status(resp):
    return (
        "status" in resp
        and resp["status"] == "success"
        or "http_status" in resp
        and resp["http_status"] == 200
        or "http_method" in resp
        and resp["http_method"] == "DELETE"
        and resp["http_status"] == 404
    )


def fortios_dlp(data, fos, check_mode):
    fos.do_member_operation("dlp", "sensor")
    if data["dlp_sensor"]:
        resp = dlp_sensor(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("dlp_sensor"))
    if isinstance(resp, tuple) and len(resp) == 4:
        return resp
    return (
        not is_successful_status(resp),
        is_successful_status(resp)
        and (resp["revision_changed"] if "revision_changed" in resp else True),
        resp,
        {},
    )


versioned_schema = {
    "type": "list",
    "elements": "dict",
    "children": {
        "name": {"v_range": [["v6.0.0", ""]], "type": "string", "required": True},
        "match_type": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [
                {"value": "match-all"},
                {"value": "match-any"},
                {"value": "match-eval"},
            ],
        },
        "eval": {"v_range": [["v7.2.0", ""]], "type": "string"},
        "comment": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "entries": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "integer",
                    "required": True,
                },
                "dictionary": {"v_range": [["v7.2.0", ""]], "type": "string"},
                "count": {"v_range": [["v7.2.0", ""]], "type": "integer"},
                "status": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
            "v_range": [["v7.2.0", ""]],
        },
        "feature_set": {
            "v_range": [["v6.4.0", "v7.0.12"]],
            "type": "string",
            "options": [{"value": "flow"}, {"value": "proxy"}],
        },
        "replacemsg_group": {"v_range": [["v6.0.0", "v7.0.12"]], "type": "string"},
        "filter": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "v_range": [["v6.0.0", "v7.0.12"]],
                    "type": "integer",
                    "required": True,
                },
                "name": {"v_range": [["v6.0.0", "v7.0.12"]], "type": "string"},
                "severity": {
                    "v_range": [["v6.0.0", "v7.0.12"]],
                    "type": "string",
                    "options": [
                        {"value": "info"},
                        {"value": "low"},
                        {"value": "medium"},
                        {"value": "high"},
                        {"value": "critical"},
                    ],
                },
                "type": {
                    "v_range": [["v6.0.0", "v7.0.12"]],
                    "type": "string",
                    "options": [{"value": "file"}, {"value": "fos_message"}],
                },
                "proto": {
                    "v_range": [["v6.0.0", "v7.0.12"]],
                    "type": "list",
                    "options": [
                        {"value": "smtp"},
                        {"value": "pop3"},
                        {"value": "imap"},
                        {"value": "http-get"},
                        {"value": "http-post"},
                        {"value": "ftp"},
                        {"value": "nntp"},
                        {"value": "mapi"},
                        {"value": "ssh", "v_range": [["v6.2.0", "v7.0.12"]]},
                        {"value": "cifs", "v_range": [["v6.4.0", "v7.0.12"]]},
                        {"value": "mm1", "v_range": [["v6.0.0", "v6.2.7"]]},
                        {"value": "mm3", "v_range": [["v6.0.0", "v6.2.7"]]},
                        {"value": "mm4", "v_range": [["v6.0.0", "v6.2.7"]]},
                        {"value": "mm7", "v_range": [["v6.0.0", "v6.2.7"]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "filter_by": {
                    "v_range": [["v6.0.0", "v7.0.12"]],
                    "type": "string",
                    "options": [
                        {"value": "credit-card"},
                        {"value": "ssn"},
                        {"value": "regexp"},
                        {"value": "file-type"},
                        {"value": "file-size"},
                        {"value": "fingerprint"},
                        {"value": "watermark"},
                        {"value": "encrypted"},
                    ],
                },
                "file_size": {"v_range": [["v6.0.0", "v7.0.12"]], "type": "integer"},
                "company_identifier": {
                    "v_range": [["v6.0.0", "v7.0.12"]],
                    "type": "string",
                },
                "sensitivity": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.2.0", "v7.0.12"]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.2.0", "v7.0.12"]],
                },
                "match_percentage": {
                    "v_range": [["v6.0.0", "v7.0.12"]],
                    "type": "integer",
                },
                "file_type": {"v_range": [["v6.0.0", "v7.0.12"]], "type": "integer"},
                "regexp": {"v_range": [["v6.0.0", "v7.0.12"]], "type": "string"},
                "archive": {
                    "v_range": [["v6.0.0", "v7.0.12"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "action": {
                    "v_range": [["v6.0.0", "v7.0.12"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "log-only"},
                        {"value": "block"},
                        {"value": "quarantine-ip"},
                    ],
                },
                "expiry": {"v_range": [["v6.0.0", "v7.0.12"]], "type": "string"},
                "fp_sensitivity": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v6.0.0", "v6.0.11"]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v6.0.0", "v6.0.11"]],
                },
            },
            "v_range": [["v6.0.0", "v7.0.12"]],
        },
        "dlp_log": {
            "v_range": [["v6.0.0", "v7.0.12"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "extended_log": {
            "v_range": [["v6.0.0", "v7.0.12"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "nac_quar_log": {
            "v_range": [["v6.0.0", "v7.0.12"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "full_archive_proto": {
            "v_range": [["v6.0.0", "v7.0.12"]],
            "type": "list",
            "options": [
                {"value": "smtp"},
                {"value": "pop3"},
                {"value": "imap"},
                {"value": "http-get"},
                {"value": "http-post"},
                {"value": "ftp"},
                {"value": "nntp"},
                {"value": "mapi"},
                {"value": "ssh", "v_range": [["v6.2.0", "v7.0.12"]]},
                {"value": "cifs", "v_range": [["v6.4.0", "v7.0.12"]]},
                {"value": "mm1", "v_range": [["v6.0.0", "v6.2.7"]]},
                {"value": "mm3", "v_range": [["v6.0.0", "v6.2.7"]]},
                {"value": "mm4", "v_range": [["v6.0.0", "v6.2.7"]]},
                {"value": "mm7", "v_range": [["v6.0.0", "v6.2.7"]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "summary_proto": {
            "v_range": [["v6.0.0", "v7.0.12"]],
            "type": "list",
            "options": [
                {"value": "smtp"},
                {"value": "pop3"},
                {"value": "imap"},
                {"value": "http-get"},
                {"value": "http-post"},
                {"value": "ftp"},
                {"value": "nntp"},
                {"value": "mapi"},
                {"value": "ssh", "v_range": [["v6.2.0", "v7.0.12"]]},
                {"value": "cifs", "v_range": [["v6.4.0", "v7.0.12"]]},
                {"value": "mm1", "v_range": [["v6.0.0", "v6.2.7"]]},
                {"value": "mm3", "v_range": [["v6.0.0", "v6.2.7"]]},
                {"value": "mm4", "v_range": [["v6.0.0", "v6.2.7"]]},
                {"value": "mm7", "v_range": [["v6.0.0", "v6.2.7"]]},
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "options": {"v_range": [["v6.0.0", "v6.2.7"]], "type": "string"},
        "flow_based": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
    },
    "v_range": [["v6.0.0", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "name"
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "enable_log": {"required": False, "type": "bool", "default": False},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"],
        },
        "state": {"required": True, "type": "str", "choices": ["present", "absent"]},
        "dlp_sensor": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["dlp_sensor"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["dlp_sensor"]["options"][attribute_name]["required"] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)
    check_legacy_fortiosapi(module)

    is_error = False
    has_changed = False
    result = None
    diff = None

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if "access_token" in module.params:
            connection.set_custom_option("access_token", module.params["access_token"])

        if "enable_log" in module.params:
            connection.set_custom_option("enable_log", module.params["enable_log"])
        else:
            connection.set_custom_option("enable_log", False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(
            fos, versioned_schema, "dlp_sensor"
        )

        is_error, has_changed, result, diff = fortios_dlp(
            module.params, fos, module.check_mode
        )

    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result["matched"] is False:
        module.warn(
            "Ansible has detected version mismatch between FortOS system and your playbook, see more details by specifying option -vvv"
        )

    if not is_error:
        if versions_check_result and versions_check_result["matched"] is False:
            module.exit_json(
                changed=has_changed,
                version_check_warning=versions_check_result,
                meta=result,
                diff=diff,
            )
        else:
            module.exit_json(changed=has_changed, meta=result, diff=diff)
    else:
        if versions_check_result and versions_check_result["matched"] is False:
            module.fail_json(
                msg="Error in repo",
                version_check_warning=versions_check_result,
                meta=result,
            )
        else:
            module.fail_json(msg="Error in repo", meta=result)


if __name__ == "__main__":
    main()
