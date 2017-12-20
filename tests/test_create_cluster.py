import pytest
import copy

from planb.create_cluster import \
    IpAddressPoolDepletedException, \
    take_private_ips_for_seeds, \
    create_user_data_template, \
    create_user_data_for_ring


# def test_calc_seed_nodes_count():
#     seed_count_per_ring = calc_seed_nodes_count(
#         region_rings={
#             'eu-central-1': [
#                 {'size': 7},
#                 {'size': 2}
#             ]
#         }
#     )
#     expected = {
#         'eu-central-1': [
#             {'size': 7, 'seed_count': 3},
#             {'size': 2, 'seed_count': 2}
#         ]
#     }
#     assert seed_count_per_ring == expected


def test_take_private_ips_for_seeds():
    region_rings = {
        'eu-central-1': {
            'subnets': [
                {
                    'name': 'internal-eu-central-1a',
                    'cidr_block': '172.31.0.0/24'
                },
                {
                    'name': 'internal-eu-central-1b',
                    'cidr_block': '172.31.8.0/24'
                }
            ],
            'rings': [
                {'size': 5},
                {'size': 2}
            ]
        },
        'eu-west-1': {
            'subnets': [
                {
                    'name': 'internal-eu-west-1a',
                    'cidr_block': '172.31.100.0/24'
                },
                {
                    'name': 'internal-eu-west-1b',
                    'cidr_block': '172.31.108.0/24',
                },
                {
                    'name': 'internal-eu-west-1c',
                    'cidr_block': '172.31.116.0/24'
                }
            ],
            'rings': [
                {'size': 5}
            ]
        }
    }
    region_taken_ips = {
        'eu-central-1': set(['172.31.8.11']),
        'eu-west-1':    set(['172.31.100.11', '172.31.116.11'])
    }
    #
    # The ip ranges for the above networks start with .1 and we skip
    # the first 10 of them in every subnet, hence the available ones
    # start with .11
    #
    expected = copy.deepcopy(region_rings)
    expected['eu-central-1']['rings'][0]['seeds'] = {
        'internal-eu-central-1a': ['172.31.0.11', '172.31.0.12'],
        'internal-eu-central-1b': ['172.31.8.12']
    }
    expected['eu-central-1']['rings'][1]['seeds'] = {
        'internal-eu-central-1a': ['172.31.0.13'],
        'internal-eu-central-1b': ['172.31.8.13']
    }
    expected['eu-west-1']['rings'][0]['seeds'] = {
        'internal-eu-west-1a': ['172.31.100.12'],
        'internal-eu-west-1b': ['172.31.108.11'],
        'internal-eu-west-1c': ['172.31.116.12']
    }

    assert take_private_ips_for_seeds(region_rings, region_taken_ips) == expected

    with pytest.raises(IpAddressPoolDepletedException):
        take_private_ips_for_seeds(
            region_rings={
                'localdc': {
                    'subnets': [
                        {
                            'name': '192-168-1',
                            'cidr_block': '192.168.1.0/30'
                        }
                    ] ,
                    'rings': [
                        {'size': 10}
                    ]
                }
            },
            region_taken_ips={}
        )

    # should not raise exceptions
    take_private_ips_for_seeds(
        region_rings={
            'localdc': {
                'subnets': [
                    {
                        'name': '10-0-0',
                        'cidr_block': '10.0.0.0/27'
                    }
                ] ,
                'rings': [
                    {'size': 10}
                ]
            }
        },
        region_taken_ips={}
    )


def test_create_user_data_template():
    cluster = {
        'name': 'hello-world',
        'keystore': b'123',
        'truststore': b'321',
        'admin_password': 'qwerty',
        'seed_nodes': {
            'eu-central-1': [
                {'_defaultIp': '12.34.56.78'},
                {'_defaultIp': '34.56.78.90'}
            ]
        },
        'docker_image': 'repo/team/artifact:v123',
        'scalyr_key': 'scalyr-key==',
        'scalyr_region': 'eu'
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
            'SEEDS': '12.34.56.78,34.56.78.90',
            'KEYSTORE': 'MTIz',
            'TRUSTSTORE': 'MzIx',
            'ADMIN_PASSWORD': 'qwerty',
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
    assert create_user_data_template(cluster) == expected


def test_create_user_data_for_ring():
    template = {
        'key': 'unchanged',
        'environment': {
            'OTHER': 'stuff',
        }
    }
    ring = {
        'dmz': False,
        'num_tokens': 1,
        'environment': {
            'EXTRA1': 'value1'
        }
    }
    expected = {
        'key': 'unchanged',
        'environment': {
            'OTHER': 'stuff',
            'NUM_TOKENS': 1,
            'SUBNET_TYPE': 'internal',
            'EXTRA1': 'value1'
        }
    }
    assert create_user_data_for_ring(template, ring) == expected
