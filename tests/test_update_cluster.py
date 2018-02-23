from unittest.mock import MagicMock
from planb.update_cluster import get_volume_name_tag, get_user_data, \
    build_run_instances_params


def test_volume_name_tag():
    instance = {
        'PrivateIpAddress': '12.34',
        'Tags': {'Name': 'my-cluster'}
    }
    assert get_volume_name_tag(instance) == 'my-cluster-12.34'


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

    saved_instance = {
        'ImageId': 'ami-12345678',
        'SecurityGroups': [{'GroupId': 'sg-abcdef'}, {'GroupId': 'sg-654321'}],
        'InstanceType': 't2.micro',
        'SubnetId': 'sn-123',
        'PrivateIpAddress': '172.31.128.11',
        'IamInstanceProfile': {'Arn': 'arn:barn', 'Id': '123'},
        'Tags': {'Name': 'my-cluster-name'},
        'UserData': {
            'source': 'docker.registry/cassandra:101',
            'mounts': {
                '/var/lib/cassandra': {
                    'partition': '/dev/xvdf'
                }
            },
            'environment': {
                'key0': 'keepval0',
                'key1': 'oldval1'
            }
        }
    }
    options = {
        'cluster_name': 'my-cluster-name*',
        'docker_image': 'docker.registry/cassandra:123',
        'taupage_ami_id': 'ami-654321',
        'instance_type': 'm4.xlarge',
        'environment': {
            'key1': 'value1',
            'key2': 'value2'
        },
        'scalyr_region': 'eu',
        'scalyr_key': 'new-shiny-scalyr-key'
    }
    expected = {
        'MinCount': 1,
        'MaxCount': 1,
        'ImageId': 'ami-654321',
        'SecurityGroupIds': ['sg-abcdef', 'sg-654321'],
        'InstanceType': 'm4.xlarge',
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
            },
            'environment': {
                'key0': 'keepval0',
                'key1': 'value1',
                'key2': 'value2'
            },
            'scalyr_region': 'eu',
            'scalyr_account_key': 'new-shiny-scalyr-key'
        }
    }
    actual = build_run_instances_params(ec2, saved_instance, options)
    assert actual == expected


def test_preserve_original_scalyr_key():
    ec2 = MagicMock()
    ec2.describe_images.return_value = {
        'Images': [{'BlockDeviceMappings': []}]
    }

    saved_instance = {
        'ImageId': 'ami-12345678',
        'SecurityGroups': [{'GroupId': 'sg-abcdef'}, {'GroupId': 'sg-654321'}],
        'InstanceType': 't2.micro',
        'SubnetId': 'sn-123',
        'PrivateIpAddress': '172.31.128.11',
        'IamInstanceProfile': {'Arn': 'arn:barn', 'Id': '123'},
        'Tags': {'Name': 'my-cluster-name'},
        'UserData': {
            'source': 'docker.registry/cassandra:101',
            'mounts': {
                '/var/lib/cassandra': {
                    'partition': '/dev/xvdf'
                }
            },
            'scalyr_account_key': 'original-scalyr-key'
        }
    }
    options = {
        'cluster_name': 'my-cluster-name',
        'taupage_ami_id': None,
        'instance_type': None
    }
    expected = {
        'MinCount': 1,
        'MaxCount': 1,
        'ImageId': 'ami-12345678',
        'SecurityGroupIds': ['sg-abcdef', 'sg-654321'],
        'InstanceType': 't2.micro',
        'SubnetId': 'sn-123',
        'PrivateIpAddress': '172.31.128.11',
        'BlockDeviceMappings': [],
        'IamInstanceProfile': {'Arn': 'arn:barn'},
        'UserData': {
            'source': 'docker.registry/cassandra:101',
            'volumes': {
                'ebs': {
                    '/dev/xvdf': 'my-cluster-name-172.31.128.11'
                }
            },
            'mounts': {
                '/var/lib/cassandra': {
                    'partition': '/dev/xvdf'
                }
            },
            'scalyr_account_key': 'original-scalyr-key'
        }
    }
    actual = build_run_instances_params(ec2, saved_instance, options)
    assert actual == expected
