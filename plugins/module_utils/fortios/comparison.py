from __future__ import absolute_import, division, print_function

__metaclass__ = type
import re


IP_PREFIX = re.compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")


def bits(netmask):
    count = 0
    while netmask:
        count += netmask & 1
        netmask >>= 1
    return count


def is_same_ip_address(current_ip, applied_ip):
    """
    current_ip can be either an ip of type str or ip and subnet of tye list
    ip like "10.10.10.0"
    ip with subnet mask: ["10.10.10.0", "255.255.255.0"]

    applied_ip can be in 3 formats:
    2 same as above and
    "10.10.10.0/24"
    """
    if isinstance(current_ip, list):
        current_ip = " ".join(current_ip)
    if len(current_ip) == 0 and len(applied_ip) == 0:
        return True
    if len(current_ip) == 0 or len(applied_ip) == 0:
        return False
    if " " not in applied_ip and "/" not in applied_ip:
        return current_ip == applied_ip

    splitted_current_ip = [current_ip]
    splitted_applied_ip = [applied_ip]
    total_bits_current_ip = 0
    total_bits_applied_ip = 0

    if " " in current_ip:
        splitted_current_ip = current_ip.split(" ")
    elif "/" in current_ip:
        splitted_current_ip = current_ip.split("/")
    if " " in applied_ip:
        splitted_applied_ip = applied_ip.split(" ")
    elif "/" in applied_ip:
        splitted_applied_ip = applied_ip.split("/")

    if splitted_current_ip[0] != splitted_applied_ip[0]:
        return False
    else:
        if "." in splitted_current_ip[1]:
            total_bits_current_ip = sum(
                [bits(int(s)) for s in splitted_current_ip[1].split(".")]
            )
        else:
            total_bits_current_ip = int(splitted_current_ip[1])
        if "." in splitted_applied_ip[1]:
            total_bits_applied_ip = sum(
                [bits(int(s)) for s in splitted_applied_ip[1].split(".")]
            )
        else:
            total_bits_applied_ip = int(splitted_applied_ip[1])

        return total_bits_current_ip == total_bits_applied_ip


def is_same_comparison(reorder_current, reorder_filtered):
    for key, value in reorder_filtered.items():
        if key not in reorder_current:
            return False

        if isinstance(value, dict):
            if not is_same_comparison(reorder_current[key], value):
                return False
        elif isinstance(value, list):
            if len(value) and isinstance(value[0], dict):
                dedup_value = set(str(item) for item in value)
                dedup_current = set(str(item) for item in reorder_current[key])

                if len(dedup_value) != len(dedup_current):
                    return False
                for item in value:
                    if not any(
                        is_same_comparison(current_dict, item)
                        for current_dict in reorder_current[key]
                    ):
                        return False
            elif reorder_current[key] != value:
                return False
        elif isinstance(value, str) and IP_PREFIX.match(value):
            return is_same_ip_address(reorder_current[key], value)
        elif reorder_current[key] != value:
            return False

    return True


def is_subset(small, big):
    """check if small is a subset of big object:
    1. If small is a dict and big is a dict, then check if all keys in small are present in big.
    2. If small is a list and big is a list, then check if all element keys in small are present in big.
    3. If small is a primitive type, then check if it is equal to big.
    """
    if isinstance(small, dict) and isinstance(big, dict):
        for key, value in small.items():
            hyphen_key = key.replace("_", "-")
            if hyphen_key not in big or not is_subset(value, big[hyphen_key]):
                return False
        return True
    elif isinstance(small, list) and isinstance(big, list) and len(big) > 0:
        for item in small:
            if any(is_subset(item, x) for x in big):
                continue
            return False
        return True

    return str(small) == str(big)


def omit_hidden_keys(input, omit_keys=("q_origin_key")):
    if isinstance(input, dict):
        result = {}
        for key, value in input.items():
            if key in omit_keys:
                continue
            result[key.replace("-", "_")] = omit_hidden_keys(value, omit_keys)
        return result
    elif isinstance(input, list):
        result = []
        for item in input:
            result.append(omit_hidden_keys(item, omit_keys))
        return result

    return input


def find_current_values(small, big):
    """Extract all key-value pairs from big that also exist in small.
    For values that are lists, extract the values in small first following the same order as in small
    and append additional values from big to the end of the list.
    """
    if isinstance(small, dict) and isinstance(big, dict):
        result = {}
        for key, value in small.items():
            hyphen_key = key.replace("_", "-")
            if hyphen_key in big:
                result[key] = omit_hidden_keys(
                    find_current_values(value, big[hyphen_key])
                )
        return result
    elif isinstance(small, list) and isinstance(big, list):
        result = []
        for small_item in small:
            for big_item in big:
                if is_subset(small_item, big_item):
                    result.append(
                        omit_hidden_keys(find_current_values(small_item, big_item)),
                    )
                    break
        for big_item in big:
            if not any(is_subset(x, big_item) for x in result):
                result.append(
                    omit_hidden_keys(big_item),
                )
        return result
    else:
        return omit_hidden_keys(
            small if is_same_comparison({"dummy": big}, {"dummy": small}) else big
        )


def serialize(data):
    if isinstance(data, str) and " " in data:
        return serialize(data.split(" "))
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
