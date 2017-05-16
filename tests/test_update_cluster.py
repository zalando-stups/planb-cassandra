from unittest.mock import MagicMock
from planb.update_cluster import *


def test_select_keys():
    assert select_keys({'a': 1, 'b': 2, 'c': 3}, ['a', 'c']) == {'a': 1, 'c': 3}


def test_tags_as_dict():
    taglist = [{'Key': 'key1', 'Value': 'val1'},
               {'Key': 'key2', 'Value': 'val2'}]
    tagdict = {'key1': 'val1',
               'key2': 'val2'}
    assert tags_as_dict(taglist) == tagdict


def test_get_user_data():
    ec2 = MagicMock()
    ec2.describe_instance_attribute.return_value = {
        'UserData': {'Value': "dGVzdDogSGVsbG8hCg=="}
    }
    user_data = {'test': 'Hello!'}
    assert get_user_data(ec2, 'i-123') == user_data


def test_build_run_instances_params():
    ec2 = MagicMock()
    ec2.describe_images.return_value = {
        'Images': [{'BlockDeviceMappings': []}]
    }

    volume = {}
    saved_instance = {
        'ImageId': 'ami-12345678',
        'SecurityGroups': [{'GroupId': 'sg-abcdef'}, {'GroupId': 'sg-654321'}],
        'InstanceType': 't2.micro',
        'SubnetId': 'sn-123',
        'PrivateIpAddress': '172.31.128.11',
        'IamInstanceProfile': {'Arn': 'arn:barn', 'Id': '123'},
        'Tags': [{'Key': 'Name', 'Value': 'my-cluster-name'}],
        'UserData': {
            'source': 'docker.registry/cassandra:101',
            'mounts': {
                '/var/lib/cassandra': {
                    'partition': '/dev/xvdf'
                }
            }
        }
    }
    options = {
        'cluster_name': 'my-cluster-name',
        'docker_image': 'docker.registry/cassandra:123',
        'taupage_ami_id': 'ami-654321'
    }
    result = {
        'MinCount': 1,
        'MaxCount': 1,
        'ImageId': 'ami-654321',
        'SecurityGroupIds': ['sg-abcdef', 'sg-654321'],
        'InstanceType': 't2.micro',
        'SubnetId': 'sn-123',
        'PrivateIpAddress': '172.31.128.11',
        'BlockDeviceMappings': [],
        'IamInstanceProfile': {'Arn': 'arn:barn'},
        'UserData': {
            'source': 'docker.registry/cassandra:123',
            'volumes': {
                'ebs': {
                    '/dev/xvdf': 'my-cluster-name-172.31.128.11'
                }
            },
            'mounts': {
                '/var/lib/cassandra': {
                    'partition': '/dev/xvdf'
                }
            }
        }
    }
    assert build_run_instances_params(ec2, volume, saved_instance, options) == result
