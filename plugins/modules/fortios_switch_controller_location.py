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
module: fortios_switch_controller_location
short_description: Configure FortiSwitch location services in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify switch_controller feature and location category.
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
    switch_controller_location:
        description:
            - Configure FortiSwitch location services.
        default: null
        type: dict
        suboptions:
            address_civic:
                description:
                    - Configure location civic address.
                type: dict
                suboptions:
                    additional:
                        description:
                            - Location additional details.
                        type: str
                    additional_code:
                        description:
                            - Location additional code details.
                        type: str
                    block:
                        description:
                            - Location block details.
                        type: str
                    branch_road:
                        description:
                            - Location branch road details.
                        type: str
                    building:
                        description:
                            - Location building details.
                        type: str
                    city:
                        description:
                            - Location city details.
                        type: str
                    city_division:
                        description:
                            - Location city division details.
                        type: str
                    country:
                        description:
                            - The two-letter ISO 3166 country code in capital ASCII letters eg. US, CA, DK, DE.
                        type: str
                    country_subdivision:
                        description:
                            - National subdivisions (state, canton, region, province, or prefecture).
                        type: str
                    county:
                        description:
                            - County, parish, gun (JP), or district (IN).
                        type: str
                    direction:
                        description:
                            - Leading street direction.
                        type: str
                    floor:
                        description:
                            - Floor.
                        type: str
                    landmark:
                        description:
                            - Landmark or vanity address.
                        type: str
                    language:
                        description:
                            - Language.
                        type: str
                    name:
                        description:
                            - Name (residence and office occupant).
                        type: str
                    number:
                        description:
                            - House number.
                        type: str
                    number_suffix:
                        description:
                            - House number suffix.
                        type: str
                    parent_key:
                        description:
                            - Parent key name.
                        type: str
                    place_type:
                        description:
                            - Place type.
                        type: str
                    post_office_box:
                        description:
                            - Post office box.
                        type: str
                    postal_community:
                        description:
                            - Postal community name.
                        type: str
                    primary_road:
                        description:
                            - Primary road name.
                        type: str
                    road_section:
                        description:
                            - Road section.
                        type: str
                    room:
                        description:
                            - Room number.
                        type: str
                    script:
                        description:
                            - Script used to present the address information.
                        type: str
                    seat:
                        description:
                            - Seat number.
                        type: str
                    street:
                        description:
                            - Street.
                        type: str
                    street_name_post_mod:
                        description:
                            - Street name post modifier.
                        type: str
                    street_name_pre_mod:
                        description:
                            - Street name pre modifier.
                        type: str
                    street_suffix:
                        description:
                            - Street suffix.
                        type: str
                    sub_branch_road:
                        description:
                            - Sub branch road name.
                        type: str
                    trailing_str_suffix:
                        description:
                            - Trailing street suffix.
                        type: str
                    unit:
                        description:
                            - Unit (apartment, suite).
                        type: str
                    zip:
                        description:
                            - Postal/zip code.
                        type: str
            coordinates:
                description:
                    - Configure location GPS coordinates.
                type: dict
                suboptions:
                    altitude:
                        description:
                            - Plus or minus floating point number. For example, 117.47.
                        type: str
                    altitude_unit:
                        description:
                            - Configure the unit for which the altitude is to (m = meters, f = floors of a building).
                        type: str
                        choices:
                            - 'm'
                            - 'f'
                    datum:
                        description:
                            - WGS84, NAD83, NAD83/MLLW.
                        type: str
                        choices:
                            - 'WGS84'
                            - 'NAD83'
                            - 'NAD83/MLLW'
                    latitude:
                        description:
                            - Floating point starting with +/- or ending with (N or S). For example, +/-16.67 or 16.67N.
                        type: str
                    longitude:
                        description:
                            - Floating point starting with +/- or ending with (N or S). For example, +/-26.789 or 26.789E.
                        type: str
                    parent_key:
                        description:
                            - Parent key name.
                        type: str
            elin_number:
                description:
                    - Configure location ELIN number.
                type: dict
                suboptions:
                    elin_num:
                        description:
                            - Configure ELIN callback number.
                        type: str
                    parent_key:
                        description:
                            - Parent key name.
                        type: str
            name:
                description:
                    - Unique location item name.
                required: true
                type: str
"""

EXAMPLES = """
- name: Configure FortiSwitch location services.
  fortinet.fortios.fortios_switch_controller_location:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      switch_controller_location:
          address_civic:
              additional: "<your_own_value>"
              additional_code: "<your_own_value>"
              block: "<your_own_value>"
              branch_road: "<your_own_value>"
              building: "<your_own_value>"
              city: "<your_own_value>"
              city_division: "<your_own_value>"
              country: "<your_own_value>"
              country_subdivision: "<your_own_value>"
              county: "<your_own_value>"
              direction: "<your_own_value>"
              floor: "<your_own_value>"
              landmark: "<your_own_value>"
              language: "<your_own_value>"
              name: "default_name_18"
              number: "<your_own_value>"
              number_suffix: "<your_own_value>"
              parent_key: "<your_own_value>"
              place_type: "<your_own_value>"
              post_office_box: "<your_own_value>"
              postal_community: "<your_own_value>"
              primary_road: "<your_own_value>"
              road_section: "<your_own_value>"
              room: "<your_own_value>"
              script: "<your_own_value>"
              seat: "<your_own_value>"
              street: "<your_own_value>"
              street_name_post_mod: "<your_own_value>"
              street_name_pre_mod: "<your_own_value>"
              street_suffix: "<your_own_value>"
              sub_branch_road: "<your_own_value>"
              trailing_str_suffix: "<your_own_value>"
              unit: "<your_own_value>"
              zip: "<your_own_value>"
          coordinates:
              altitude: "<your_own_value>"
              altitude_unit: "m"
              datum: "WGS84"
              latitude: "<your_own_value>"
              longitude: "<your_own_value>"
              parent_key: "<your_own_value>"
          elin_number:
              elin_num: "<your_own_value>"
              parent_key: "<your_own_value>"
          name: "default_name_48"
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


def filter_switch_controller_location_data(json):
    option_list = ["address_civic", "coordinates", "elin_number", "name"]

    json = remove_invalid_fields(json)
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
            new_data[k.replace("_", "-")] = underscore_to_hyphen(v)
        data = new_data

    return data


def switch_controller_location(data, fos, check_mode=False):
    state = None
    vdom = data["vdom"]

    state = data["state"]

    switch_controller_location_data = data["switch_controller_location"]

    filtered_data = filter_switch_controller_location_data(
        switch_controller_location_data
    )
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("switch-controller", "location", filtered_data, vdom=vdom)
        current_data = fos.get("switch-controller", "location", vdom=vdom, mkey=mkey)
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
            copied_filtered_data = filtered_data.copy()
            copied_filtered_data.pop(fos.get_mkeyname(None, None), None)

            if is_existed:
                is_same = is_same_comparison(
                    serialize(current_data["results"][0]),
                    serialize(copied_filtered_data),
                )

                current_values = find_current_values(
                    copied_filtered_data, current_data["results"][0]
                )

                return (
                    False,
                    not is_same,
                    filtered_data,
                    {"before": current_values, "after": copied_filtered_data},
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
    # pass post processed data to member operations
    data_copy = data.copy()
    data_copy["switch_controller_location"] = converted_data
    fos.do_member_operation(
        "switch-controller",
        "location",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("switch-controller", "location", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "switch-controller", "location", mkey=converted_data["name"], vdom=vdom
        )
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


def fortios_switch_controller(data, fos, check_mode):
    if data["switch_controller_location"]:
        resp = switch_controller_location(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("switch_controller_location")
        )
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
        "name": {"v_range": [["v6.2.0", ""]], "type": "string", "required": True},
        "address_civic": {
            "v_range": [["v6.2.0", ""]],
            "type": "dict",
            "children": {
                "additional": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "additional_code": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "block": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "branch_road": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "building": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "city": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "city_division": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "country": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "country_subdivision": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "county": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "direction": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "floor": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "landmark": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "language": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "name": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "number": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "number_suffix": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "place_type": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "post_office_box": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "postal_community": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "primary_road": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "road_section": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "room": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "script": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "seat": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "street": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "street_name_post_mod": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "street_name_pre_mod": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "street_suffix": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "sub_branch_road": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "trailing_str_suffix": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "unit": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "zip": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "parent_key": {
                    "v_range": [
                        ["v6.2.7", "v6.2.7"],
                        ["v6.4.4", "v7.0.5"],
                        ["v7.2.0", "v7.2.0"],
                    ],
                    "type": "string",
                },
            },
        },
        "coordinates": {
            "v_range": [["v6.2.0", ""]],
            "type": "dict",
            "children": {
                "altitude": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "altitude_unit": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "m"}, {"value": "f"}],
                },
                "datum": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "WGS84"},
                        {"value": "NAD83"},
                        {"value": "NAD83/MLLW"},
                    ],
                },
                "latitude": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "longitude": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "parent_key": {
                    "v_range": [
                        ["v6.2.7", "v6.2.7"],
                        ["v6.4.4", "v7.0.5"],
                        ["v7.2.0", "v7.2.0"],
                    ],
                    "type": "string",
                },
            },
        },
        "elin_number": {
            "v_range": [["v6.2.0", ""]],
            "type": "dict",
            "children": {
                "elin_num": {"v_range": [["v6.2.0", ""]], "type": "string"},
                "parent_key": {
                    "v_range": [
                        ["v6.2.7", "v6.2.7"],
                        ["v6.4.4", "v7.0.5"],
                        ["v7.2.0", "v7.2.0"],
                    ],
                    "type": "string",
                },
            },
        },
    },
    "v_range": [["v6.2.0", ""]],
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
        "switch_controller_location": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["switch_controller_location"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["switch_controller_location"]["options"][attribute_name][
                "required"
            ] = True

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
            fos, versioned_schema, "switch_controller_location"
        )

        is_error, has_changed, result, diff = fortios_switch_controller(
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
