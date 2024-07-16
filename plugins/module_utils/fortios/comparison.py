from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
import re


IP_PREFIX = re.compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")


def bits(netmask):
    count = 0
    while (netmask):
        count += netmask & 1
        netmask >>= 1
    return count


def is_same_ip_address(current_ip, applied_ip):
    '''
    current_ip can be either an ip of type str or ip and subnet of tye list
    ip like "10.10.10.0"
    ip with subnet mask: ["10.10.10.0", "255.255.255.0"]

    applied_ip can be in 3 formats:
    2 same as above and
    "10.10.10.0/24"
    '''
    if isinstance(current_ip, list):
        current_ip = ' '.join(current_ip)
    if len(current_ip) == 0 and len(applied_ip) == 0:
        return True
    if len(current_ip) == 0 or len(applied_ip) == 0:
        return False
    if ' ' not in applied_ip and '/' not in applied_ip:
        return current_ip == applied_ip

    splitted_current_ip = [current_ip]
    splitted_applied_ip = [applied_ip]
    total_bits_current_ip = 0
    total_bits_applied_ip = 0

    if ' ' in current_ip:
        splitted_current_ip = current_ip.split(' ')
    elif '/' in current_ip:
        splitted_current_ip = current_ip.split('/')
    if ' ' in applied_ip:
        splitted_applied_ip = applied_ip.split(' ')
    elif '/' in applied_ip:
        splitted_applied_ip = applied_ip.split('/')

    if splitted_current_ip[0] != splitted_applied_ip[0]:
        return False
    else:
        if '.' in splitted_current_ip[1]:
            total_bits_current_ip = sum([bits(int(s)) for s in splitted_current_ip[1].split('.')])
        else:
            total_bits_current_ip = int(splitted_current_ip[1])
        if '.' in splitted_applied_ip[1]:
            total_bits_applied_ip = sum([bits(int(s)) for s in splitted_applied_ip[1].split('.')])
        else:
            total_bits_applied_ip = int(splitted_applied_ip[1])

        return total_bits_current_ip == total_bits_applied_ip


def is_same_comparison(reorder_current, reorder_filtered):
    for key, value in reorder_filtered.items():
        if key.replace("_", "-") not in reorder_current:
            return False

        if isinstance(value, dict):
            if not is_same_comparison(reorder_current[key.replace("_", "-")], value):
                return False
        elif isinstance(value, list):
            if len(value) != len(reorder_current[key.replace("_", "-")]):
                return False
            if len(value) and isinstance(value[0], dict):
                for current_dict in reorder_current[key.replace("_", "-")]:
                    if not is_same_comparison(current_dict, value[0]):
                        return False
            elif reorder_current[key.replace("_", "-")] != value:
                return False
        elif isinstance(value, str) and IP_PREFIX.match(value):
            return is_same_ip_address(reorder_current[key.replace("_", "-")], value)
        elif reorder_current[key.replace("_", "-")] != value:
            return False

    return True


def find_current_values(reorder_current, reorder_filtered):
    '''Find keyvalues in current according to keys from filtered'''
    result = {}
    for key, value in reorder_filtered.items():
        if key.replace("_", "-") not in reorder_current:
            result[key] = None  # Handle missing key
            continue

        if isinstance(value, dict):
            result[key] = find_current_values(reorder_current[key.replace("_", "-")], value)
        elif isinstance(value, list):
            result[key] = []
            for i in range(len(value)):
                if isinstance(value[i], dict):
                    result[key].append(find_current_values(reorder_current[key.replace("_", "-")][i], value[i]))
                else:
                    result[key].append(reorder_current[key.replace("_", "-")])
        elif isinstance(value, str):
            result[key] = reorder_current[key.replace("_", "-")]

    return result


def serialize(data):
    if isinstance(data, str) and ' ' in data:
        return serialize(data.split(' '))
    if isinstance(data, list) and len(data) > 0:
        if isinstance(data[0], dict):
            list_to_order = []
            for dt in data:
                ret = {}
                for key, value in dt.items():
                    ret[key] = serialize(value)
                list_to_order.append(ret)

            return sorted(list_to_order, key=lambda dt: str(dt.items()))
        else:
            return sorted(data)

    if isinstance(data, dict):
        result = {}
        for key, value in data.items():
            result[key] = serialize(value)

        return result

    return data


def validate_result(result, desc):
    if not result:
        raise AssertionError("failed on test " + desc)
