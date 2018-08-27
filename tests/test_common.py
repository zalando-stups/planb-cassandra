import pytest

from planb.common import environment_as_dict, tags_as_dict, select_keys


def test_environment_as_dict():
    raw_list = ["key=value", "base64=dGVzdA=="]
    expected = {'key': 'value', 'base64': 'dGVzdA=='}
    assert environment_as_dict(raw_list) == expected


def test_tags_as_dict():
    taglist = [{'Key': 'key1', 'Value': 'val1'},
               {'Key': 'key2', 'Value': 'val2'}]
    tagdict = {'key1': 'val1',
               'key2': 'val2'}
    assert tags_as_dict(taglist) == tagdict


def test_select_keys():
    assert select_keys({'a': 1, 'b': 2, 'c': 3}, ['a', 'c']) == {'a': 1, 'c': 3}
