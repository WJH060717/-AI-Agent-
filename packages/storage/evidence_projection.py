"""Bounded lifecycle fields, never raw commands, accounts or arbitrary extensions."""


def process_projection(value) -> dict:
    if not isinstance(value, dict):
        return {}
    integers = {"pid", "ppid", "start_ticks", "parent_start_ticks"}
    strings = {"action", "start_time", "parent_start_time", "identity_basis", "executable"}
    result = {}
    for key in integers:
        item = value.get(key)
        if type(item) is int and 0 <= item <= 2**63 - 1:
            result[key] = item
    for key in strings:
        item = value.get(key)
        if isinstance(item, str):
            result[key] = item[:200]
            if len(item) > 200:
                result["fields_truncated"] = True
    return result
