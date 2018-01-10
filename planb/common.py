import base64
import yaml
import json
import copy
import time
import io
import os
import functools

from datetime import datetime


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""

    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, bytes):
        return str(obj, 'UTF-8')

    raise TypeError("Type not serializable")


# TODO: can be actually a list of dicts...
# use better name
def dump_dict_as_file(data: dict, filename: str):
    with open(filename, 'w') as f:
        json.dump(data, f, default=json_serial)


def load_dict_from_file(filename: str) -> dict:
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            return json.load(f)


def decode_user_data(b64data: str) -> dict:
    raw_bytes = base64.b64decode(b64data)
    data = str(raw_bytes, 'UTF-8')
    stream = io.StringIO(data)
    return yaml.safe_load(stream)


def dump_user_data_for_taupage(user_data: dict) -> str:
    return '#taupage-ami-config\n{}'.format(yaml.safe_dump(user_data))


def rectify_block_device_mapping(mapping: dict) -> dict:
    if 'Ebs' in mapping:
        #
        # If the Encrypted flag is present, we have to delete
        # it even if it matches the actual snapshot setting,
        # otherwise amazon will complain rather loudly.
        #
        # Take a deep copy before deleting the key:
        #
        m = copy.deepcopy(mapping)

        ebs = m['Ebs']
        if 'Encrypted' in ebs:
            del(ebs['Encrypted'])

        return m

    else:
        #
        # Override any ephemeral volumes with NoDevice mapping,
        # otherwise auto-recovery alarm cannot be actually enabled.
        #
        return {
            'DeviceName': mapping['DeviceName'],
            'NoDevice': ''
        }


def prepare_block_device_mappings(mappings: list) -> list:
    return [rectify_block_device_mapping(m) for m in mappings]


def environment_as_dict(environment: list) -> dict:
    return dict(map(lambda x: x.split("=", 1), environment))


def thread_val(i, funcs):
    return functools.reduce(lambda x, f: f(x), funcs, i)
