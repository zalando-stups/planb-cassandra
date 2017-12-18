import pytest
from unittest.mock import MagicMock

from planb.create_cluster import generate_private_ip_addresses, \
    IpAddressPoolDepletedException, \
    create_user_data_for_ring


def test_generate_private_ip_addresses():
    region_subnets = {
        'eu-central-1': [
            {'CidrBlock': '172.31.0.0/24'},
            {'CidrBlock': '172.31.8.0/24'}
        ],
        'eu-west-1': [
            {'CidrBlock': '172.31.100.0/24'},
            {'CidrBlock': '172.31.108.0/24'},
            {'CidrBlock': '172.31.116.0/24'}
        ]
    }
    region_taken_ips = {
        'eu-central-1': ['172.31.8.11'],
        'eu-west-1':    ['172.31.100.12', '172.31.116.11']
    }
    #
    # The ip ranges for the above networks start with .1 and we skip
    # the first 10 of them in every subnet, hence the available ones
    # start with .11
    #
    region_expected_ips = {
        'eu-central-1': [
            '172.31.0.11', '172.31.8.12', '172.31.0.12',
            '172.31.8.13', '172.31.0.13'
        ],
        'eu-west-1': [
            '172.31.100.11', '172.31.108.11', '172.31.116.12',
            '172.31.100.13', '172.31.108.12'
        ]
    }

    for region, subnets in region_subnets.items():
        iplist = list(generate_private_ip_addresses(
            subnets, cluster_size=5, taken_ips=region_taken_ips[region]
        ))
        assert iplist == region_expected_ips[region]

    with pytest.raises(IpAddressPoolDepletedException):
        list(generate_private_ip_addresses(
               [{'CidrBlock': '192.168.1.0/29'}], cluster_size=10, taken_ips=[]
        ))

    # should not raise exceptions
    list(generate_private_ip_addresses(
           [{'CidrBlock': '192.168.1.0/27'}], cluster_size=20, taken_ips=[]
    ))

    with pytest.raises(IpAddressPoolDepletedException):
        ips = generate_private_ip_addresses(
            [{'CidrBlock': '192.168.1.0/27'}], cluster_size=21, taken_ips=[]
        )
        list(ips)


def test_create_user_data_template():
    cluster = {
        'name': 'hello-world',
        'keystore': b'123',
        'truststore': b'321',
        'seed_nodes': {
            'eu-central-1': [
                {'_defaultIp': '12.34.56.78'},
                {'_defaultIp': '34.56.78.90'}
            ]
        },
        'docker_image': 'repo/team/artifact:v123',
        'admin_password': 'qwerty',
        'scalyr_key': 'scalyr-key==',
        'scalyr_region': 'eu'
    }
    ring = {
        'dmz': False,
        'num_tokens': 1,
        'environment': {
            'EXTRA1': 'value1'
        }
    }
    expected = {
        'runtime': 'Docker',
        'source': 'repo/team/artifact:v123',
        'application_id': cluster['name'],
        'application_version': 'v123',
        'networking': 'host',
        'ports': {
            '7001': '7001',
            '9042': '9042'
        },
        'environment': {
            'CLUSTER_NAME': cluster['name'],
            'NUM_TOKENS': ring['num_tokens'],
            'SUBNET_TYPE': 'internal',
            'SEEDS': '12.34.56.78,34.56.78.90',
            'KEYSTORE': 'MTIz',
            'TRUSTSTORE': 'MzIx',
            'ADMIN_PASSWORD': 'qwerty',
            'EXTRA1': 'value1'
        },
        'volumes': {
            'ebs': {
                '/dev/xvdf': None
            }
        },
        'mounts': {
            '/var/lib/cassandra': {
                'partition': '/dev/xvdf',
                'options': 'noatime,nodiratime'
            }
        },
        'scalyr_account_key': 'scalyr-key==',
        'scalyr_region': 'eu'
    }
    assert create_user_data_for_ring(cluster, ring) == expected
