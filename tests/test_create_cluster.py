import itertools
import pytest
import copy

from unittest.mock import MagicMock

from planb.create_cluster import \
    IpAddressPoolDepletedException, \
    add_elastic_ips, \
    add_elastic_ips_to_region, \
    add_nodes_to_regions, \
    add_security_groups, \
    add_subnets, \
    add_taken_private_ips, \
    add_taupage_amis, \
    collect_seed_nodes, \
    configure_launched_instance, \
    create_data_volume_for_node, \
    create_user_data_for_ring, \
    create_user_data_template, \
    get_region_ip_iterator, \
    get_subnet_name, \
    launch_node, \
    make_ingress_rules, \
    make_nodes, \
    prepare_rings, \
    seed_iterator

from test_aws import install_boto_client_mock

from test_common import dict_contains, list_just_contains_dicts


BOTO_CENTRAL_EIPS = [
    {'PublicIp': '12.34', 'AllocationId': 'a1'},
    {'PublicIp': '56.78', 'AllocationId': 'a2'}
]


BOTO_CENTRAL_SUBNETS = [
    {
        'SubnetId': 'subnet-central-1a-dmz',
        'AvailabilityZone': 'eu-central-1a',
        'CidrBlock': '10.0.0.0/24',
        'Tags': [{'Key': 'Name', 'Value': 'dmz-eu-central-1a'}]
    },
    {
        'SubnetId': 'subnet-central-1b-dmz',
        'AvailabilityZone': 'eu-central-1b',
        'CidrBlock': '10.10.0.0/24',
        'Tags': [{'Key': 'Name', 'Value': 'dmz-eu-central-1b'}]
    },
    {
        'SubnetId': 'subnet-central-1a',
        'AvailabilityZone': 'eu-central-1a',
        'CidrBlock': '172.31.0.0/24',
        'Tags': [{'Key': 'Name', 'Value': 'internal-eu-central-1a'}]
    },
    {
        'SubnetId': 'subnet-central-1b',
        'AvailabilityZone': 'eu-central-1b',
        'CidrBlock': '172.31.8.0/24',
        'Tags': [{'Key': 'Name', 'Value': 'internal-eu-central-1b'}]
    }
]


BOTO_WEST_EIPS = [
    {'PublicIp': '34.12', 'AllocationId': 'b1'},
    {'PublicIp': '78.56', 'AllocationId': 'b2'},
    {'PublicIp': '90.12', 'AllocationId': 'b3'}
]


BOTO_WEST_SUBNETS = [
    {
        'SubnetId': 'subnet-west-1a',
        'AvailabilityZone': 'eu-west-1a',
        'CidrBlock': '172.31.100.0/24',
        'Tags': [{'Key': 'Name', 'Value': 'internal-eu-west-1a'}]
    },
    {
        'SubnetId': 'subnet-west-1b',
        'AvailabilityZone': 'eu-west-1b',
        'CidrBlock': '172.31.108.0/24',
        'Tags': [{'Key': 'Name', 'Value': 'internal-eu-west-1b'}]
    },
    {
        'SubnetId': 'subnet-west-1c',
        'AvailabilityZone': 'eu-west-1c',
        'CidrBlock': '172.31.116.0/24',
        'Tags': [{'Key': 'Name', 'Value': 'internal-eu-west-1c'}]
    }
]


@pytest.fixture
def ec2_fixture(monkeypatch):
    ec2_central = MagicMock()
    ec2_central.describe_instances.return_value = {
        'Reservations': [
            {
                'Instances': [
                    {'PrivateIpAddress': '172.31.8.11'}
                ]
            }
        ]
    }
    ec2_central.allocate_address.side_effect = BOTO_CENTRAL_EIPS
    ec2_central.describe_subnets.return_value = {
        'Subnets': BOTO_CENTRAL_SUBNETS
    }
    ec2_west = MagicMock()
    ec2_west.describe_instances.return_value = {
        'Reservations': [
            {
                'Instances': [
                    {'PrivateIpAddress': '172.31.100.11'},
                    {'PrivateIpAddress': '172.31.116.11'}
                ]
            }
        ]
    }
    ec2_west.allocate_address.side_effect = BOTO_WEST_EIPS
    ec2_west.describe_subnets.return_value = {
        'Subnets': BOTO_WEST_SUBNETS
    }
    ec2 = {
        'eu-central-1': ec2_central,
        'eu-west-1': ec2_west
    }
    install_boto_client_mock(monkeypatch, ec2)
    return ec2
    

@pytest.fixture
def ec2_taupage_fixture(monkeypatch):
    ec2_central = MagicMock()
    ec2_central_ami1 = MagicMock()
    ec2_central_ami1.id = 'ami-central-1'
    ec2_central_ami1.name = 'taupage-central-1'
    ec2_central_ami1.block_device_mappings = []
    ec2_central.images.filter.return_value = [ec2_central_ami1]

    ec2_west = MagicMock()
    ec2_west_ami1 = MagicMock()
    ec2_west_ami1.id = 'ami-west-1'
    ec2_west_ami1.name = 'taupage-west-1'
    ec2_west_ami1.block_device_mappings = []
    ec2_west.images.filter.return_value = [ec2_west_ami1]

    ec2 = {
        'eu-central-1': ec2_central,
        'eu-west-1': ec2_west
    }

    resource = MagicMock()
    resource.side_effect = lambda _, region_name: ec2[region_name]
    monkeypatch.setattr('boto3.resource', resource)

    return ec2


@pytest.fixture
def ec2_sg_fixture(ec2_fixture):
    ec2 = ec2_fixture

    ec2['eu-central-1'].describe_vpcs.return_value = {
        'Vpcs': [
            {'VpcId': 'vpc-central-1'}
        ]
    }
    ec2['eu-west-1'].describe_vpcs.return_value = {
        'Vpcs': [
            {'VpcId': 'vpc-west-1'}
        ]
    }
    ec2['eu-central-1'].describe_security_groups.return_value = {
        'SecurityGroups': [
            {
                'GroupId': 'sg-central-1',
                'IpPermissions': [
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 7001,
                        'ToPort': 7001,
                        'IpRanges': [
                            {'CidrIp': '12.34/32'},
                            {'CidrIp': '56.78/32'}
                        ]
                    }
                ]
            }
        ]
    }
    ec2['eu-west-1'].describe_security_groups.return_value = {
        'SecurityGroups': []
    }
    ec2['eu-central-1'].create_security_group.return_value = {
        'GroupId': 'sg-central-1'
    }
    ec2['eu-west-1'].create_security_group.return_value = {
        'GroupId': 'sg-west-1'
    }
    ec2['eu-central-1'].create_tags.return_value = None
    ec2['eu-west-1'].create_tags.return_value = None

    return ec2


@pytest.fixture
def ec2_launch_fixture(monkeypatch):
    ec2 = {
        'eu-central-1': MagicMock()
    }
    install_boto_client_mock(monkeypatch, ec2)
    return ec2


EU_CENTRAL_TAUPAGE_AMI = {
    'id': 'ami-central-1',
    'name': 'taupage-central-1',
    'block_device_mappings': []
}


EU_WEST_TAUPAGE_AMI = {
    'id': 'ami-west-1',
    'name': 'taupage-west-1',
    'block_device_mappings': []
}


EU_CENTRAL_SUBNETS = [
    {
        'id': 'subnet-central-1a-dmz',
        'zone': 'eu-central-1a',
        'name': 'dmz-eu-central-1a',
        'cidr_block': '10.0.0.0/24'
    },
    {
        'id': 'subnet-central-1a',
        'zone': 'eu-central-1a',
        'name': 'internal-eu-central-1a',
        'cidr_block': '172.31.0.0/24'
    },
    {
        'id': 'subnet-central-1b-dmz',
        'zone': 'eu-central-1b',
        'name': 'dmz-eu-central-1b',
        'cidr_block': '10.10.0.0/24'
    },
    {
        'id': 'subnet-central-1b',
        'zone': 'eu-central-1b',
        'name': 'internal-eu-central-1b',
        'cidr_block': '172.31.8.0/24'
    }
]

EU_CENTRAL = {
    'dmz': False,
    'rings': [
        {
            'size': 5,
            'volume': 'vol-a'
        },
        {
            'size': 2,
            'volume': 'vol-b'
        }
    ]
}


EU_WEST_SUBNETS = [
    # TODO
    # {
    #     'name': 'dmz-eu-west-1a',
    #     'cidr_block': '10.0.0.0/24'
    # },
    {
        'id': 'subnet-west-1a',
        'zone': 'eu-west-1a',
        'name': 'internal-eu-west-1a',
        'cidr_block': '172.31.100.0/24'
    },
    {
        'id': 'subnet-west-1b',
        'zone': 'eu-west-1b',
        'name': 'internal-eu-west-1b',
        'cidr_block': '172.31.108.0/24',
    },
    {
        'id': 'subnet-west-1c',
        'zone': 'eu-west-1c',
        'name': 'internal-eu-west-1c',
        'cidr_block': '172.31.116.0/24'
    }
]


EU_WEST = {
    'dmz': False,
    'rings': [
        {
            'size': 5,
            'volume': 'vol-c'
        }
    ]
}


REGION_RINGS = {
    'eu-central-1': EU_CENTRAL,
    'eu-west-1': EU_WEST
}


PRIVATE_CENTRAL_NODES = [
    # TODO: WTF do these key names look so differently?
    # 1st ring
    {'_defaultIp': '172.31.0.11',
     'PrivateIp': '172.31.0.11',
     'subnet': {'id': 'subnet-central-1a', 'zone': 'eu-central-1a'},
     'seed?': True},
    {'_defaultIp': '172.31.8.12',
     'PrivateIp': '172.31.8.12',
     'subnet': {'id': 'subnet-central-1b', 'zone': 'eu-central-1b'},
     'seed?': True},
    {'_defaultIp': '172.31.0.12',
     'PrivateIp': '172.31.0.12',
     'subnet': {'id': 'subnet-central-1a', 'zone': 'eu-central-1a'},
     'seed?': True},
    {'_defaultIp': '172.31.8.13',
     'PrivateIp': '172.31.8.13',
     'subnet': {'id': 'subnet-central-1b', 'zone': 'eu-central-1b'},
     'seed?': False},
    {'_defaultIp': '172.31.0.13',
     'PrivateIp': '172.31.0.13',
     'subnet': {'id': 'subnet-central-1a', 'zone': 'eu-central-1a'},
     'seed?': False},

    # 2nd ring starts where the 1st left
    {'_defaultIp': '172.31.8.14',
     'PrivateIp': '172.31.8.14',
     'subnet': {'id': 'subnet-central-1b', 'zone': 'eu-central-1b'},
     'seed?': True},
    {'_defaultIp': '172.31.0.14',
     'PrivateIp': '172.31.0.14',
     'subnet': {'id': 'subnet-central-1a', 'zone': 'eu-central-1a'},
     'seed?': True}
]


PUBLIC_CENTRAL_NODES = [
    {'_defaultIp': '12.34',
     'PrivateIp': '172.31.8.14',
     'PublicIp': '12.34',
     'AllocationId': 'a1',
     'subnet': {'id': 'subnet-central-1b-dmz', 'zone': 'eu-central-1b'},
     'seed?': True},
    {'_defaultIp': '56.78',
     'PrivateIp': '172.31.0.14',
     'PublicIp': '56.78',
     'AllocationId': 'a2',
     'subnet': {'id': 'subnet-central-1a-dmz', 'zone': 'eu-central-1a'},
     'seed?': True}
]


PRIVATE_WEST_NODES = [
    {'_defaultIp': '172.31.100.12',
     'PrivateIp': '172.31.100.12',
     'subnet': {'id': 'subnet-west-1a', 'zone': 'eu-west-1a'},
     'seed?': True},
    {'_defaultIp': '172.31.108.11',
     'PrivateIp': '172.31.108.11',
     'subnet': {'id': 'subnet-west-1b', 'zone': 'eu-west-1b'},
     'seed?': True},
    {'_defaultIp': '172.31.116.12',
     'PrivateIp': '172.31.116.12',
     'subnet': {'id': 'subnet-west-1c', 'zone': 'eu-west-1c'},
     'seed?': True},
    {'_defaultIp': '172.31.100.13',
     'PrivateIp': '172.31.100.13',
     'subnet': {'id': 'subnet-west-1a', 'zone': 'eu-west-1a'},
     'seed?': False},
    {'_defaultIp': '172.31.108.12',
     'PrivateIp': '172.31.108.12',
     'subnet': {'id': 'subnet-west-1b', 'zone': 'eu-west-1b'},
     'seed?': False}
]


PUBLIC_WEST_NODES = [
    {'_defaultIp': '24.12',
     'PrivateIp': '172.31.100.12',
     'PublicIp': '34.12',
     'AllocationId': 'b1',
     'subnet': {'id': 'subnet-west-1a-dmz', 'zone': 'eu-west-1a'},
     'seed?': True},
    {'_defaultIp': '78.56',
     'PrivateIp': '172.31.108.11',
     'PublicIp': '78.56',
     'AllocationId': 'b2',
     'subnet': {'id': 'subnet-west-1b-dmz', 'zone': 'eu-west-1b'},
     'seed?': True},
    {'_defaultIp': '90.12',
     'PrivateIp': '172.31.116.12',
     'PublicIp': '90.12',
     'AllocationId': 'b3',
     'subnet': {'id': 'subnet-west-1c-dmz', 'zone': 'eu-west-1c'},
     'seed?': True},
]


TAKEN_CENTRAL_IPS = set(['172.31.8.11'])
TAKEN_WEST_IPS = set(['172.31.100.11', '172.31.116.11'])


def test_address_pool_depletion():
    with pytest.raises(IpAddressPoolDepletedException):
        it = get_region_ip_iterator(
            subnets=[
                {
                    'id': 'sn-1',
                    'zone': 'local',
                    'name': 'internal-192-168-1',
                    'cidr_block': '192.168.1.0/30'
                }
            ],
            taken_ips=set(),
            elastic_ips=[],
            dmz=False
        )
        for _ in range(10):
            next(it)

    # should not raise exceptions
    it = get_region_ip_iterator(
        subnets=[
            {
                'id': 'sn-2',
                'zone': 'local',
                'name': 'internal-10-0-0',
                'cidr_block': '10.0.0.0/27'
            }
        ],
        taken_ips=set(),
        elastic_ips=[],
        dmz=False
    )
    for _ in range(10):
        next(it)


def test_region_elastic_ip_allocation():
    ec2 = MagicMock()
    elastic_ips = [
        {'PublicIp': '123.45', 'AllocationId': 'a1'},
        {'PublicIp': '123.12', 'AllocationId': 'a2'},
        {'PublicIp': '123.34', 'AllocationId': 'a3'}
    ]
    ec2.allocate_address.side_effect = elastic_ips
    region = {
        'dmz': True,
        'rings': [
            {'size': 1},
            {'size': 2},
        ]
    }
    expected = copy.deepcopy(region)
    expected['elastic_ips'] = elastic_ips

    actual = add_elastic_ips_to_region(ec2, region)
    assert actual == expected


def test_add_elastic_ips(ec2_fixture):
    region_rings = {
        'eu-central-1': {
            'dmz': True,
            'rings': [
                {'size': 2}
            ]
        },
        'eu-west-1': {
            'dmz': True,
            'rings': [
                {'size': 3}
            ]
        }
    }
    expected = copy.deepcopy(region_rings)
    expected['eu-central-1']['elastic_ips'] = BOTO_CENTRAL_EIPS
    expected['eu-west-1']['elastic_ips'] = BOTO_WEST_EIPS
    actual = add_elastic_ips(region_rings)
    assert actual == expected


def test_make_nodes_one_ring():
    region_rings = copy.deepcopy(REGION_RINGS)
    eu_west = region_rings['eu-west-1']
    eu_west['subnets'] = EU_WEST_SUBNETS
    eu_west['taken_ips'] = TAKEN_WEST_IPS
    node_template = {}
    actual = make_nodes(node_template, eu_west)
    assert list_just_contains_dicts(actual, PRIVATE_WEST_NODES)


def test_make_nodes_two_rings():
    region_rings = copy.deepcopy(REGION_RINGS)
    eu_central = region_rings['eu-central-1']
    eu_central['subnets'] = EU_CENTRAL_SUBNETS
    eu_central['taken_ips'] = TAKEN_CENTRAL_IPS
    node_template = {}
    actual = make_nodes(node_template, eu_central)
    assert list_just_contains_dicts(actual, PRIVATE_CENTRAL_NODES)


def test_make_nodes_with_template():
    eu_central = {
        'dmz': False,
        'rings': [
            {
                'size': 2
            }
        ],
        'subnets': EU_CENTRAL_SUBNETS,
        'taken_ips': TAKEN_CENTRAL_IPS
    }
    node_template = {
        'instance_type': 't2.atto',
        'volume': {
            'type': 'gp2'
        }
    }
    expected = [node_template, node_template]
    actual = make_nodes(node_template, eu_central)
    assert list_just_contains_dicts(actual, expected)


def test_seed_iterator():
    actual = list(seed_iterator(REGION_RINGS['eu-central-1']['rings']))
    expected = [True, True, True, False, False, True, True]
    assert actual == expected


def test_get_region_ip_iterator_elastic_ips():
    elastic_ips = [
         {'PublicIp': '51.1', 'AllocationId': 'a2'},
         {'PublicIp': '51.3', 'AllocationId': 'a4'},
         {'PublicIp': '51.5', 'AllocationId': 'a6'},
         {'PublicIp': '51.7', 'AllocationId': 'a8'}]
    subnets = EU_CENTRAL_SUBNETS
    taken_ips = TAKEN_CENTRAL_IPS
    ipiter = get_region_ip_iterator(subnets, taken_ips, elastic_ips, True)
    actual = [next(ipiter) for i in range(4)]

    # we want to compare certain keys only
    ignore_keys = set(['PrivateIp', 'PublicIp'])
    for i in actual:
        for ignore in ignore_keys:
            del i[ignore]
    expected = [
        {'_defaultIp': '51.1',
         'AllocationId': 'a2',
         'subnet': {'id': 'subnet-central-1a-dmz', 'zone': 'eu-central-1a'}},
        {'_defaultIp': '51.3',
         'AllocationId': 'a4',
         'subnet': {'id': 'subnet-central-1b-dmz', 'zone': 'eu-central-1b'}},
        {'_defaultIp': '51.5',
         'AllocationId': 'a6',
         'subnet': {'id': 'subnet-central-1a-dmz', 'zone': 'eu-central-1a'}},
        {'_defaultIp': '51.7',
         'AllocationId': 'a8',
         'subnet': {'id': 'subnet-central-1b-dmz', 'zone': 'eu-central-1b'}}
    ]
    assert actual == expected


def test_get_region_ip_iterator_remove_taken_ip():
    subnets = EU_CENTRAL_SUBNETS
    taken_ips = TAKEN_CENTRAL_IPS
    ipiter = get_region_ip_iterator(subnets, taken_ips, [], False)
    actual = [next(ipiter) for i in range(4)]

    # we want to compare certain keys only
    ignore_keys = set(['PrivateIp'])
    for i in actual:
        for ignore in ignore_keys:
            del i[ignore]
    expected = [
        {'_defaultIp': '172.31.0.11',
         'subnet': {'id': 'subnet-central-1a', 'zone': 'eu-central-1a'}},
        {'_defaultIp': '172.31.8.12',
         'subnet': {'id': 'subnet-central-1b', 'zone': 'eu-central-1b'}},
        {'_defaultIp': '172.31.0.12',
         'subnet': {'id': 'subnet-central-1a', 'zone': 'eu-central-1a'}},
        {'_defaultIp': '172.31.8.13',
         'subnet': {'id': 'subnet-central-1b', 'zone': 'eu-central-1b'}}
    ]
    assert actual == expected


def test_add_nodes_to_regions():
    region_rings = copy.deepcopy(REGION_RINGS)
    eu_central = region_rings['eu-central-1']
    eu_central['subnets'] = EU_CENTRAL_SUBNETS
    eu_central['taken_ips'] = TAKEN_CENTRAL_IPS
    eu_central['elastic_ips'] = []
    eu_west = region_rings['eu-west-1']
    eu_west['subnets'] = EU_WEST_SUBNETS
    eu_west['taken_ips'] = TAKEN_WEST_IPS
    eu_west['elastic_ips'] = []
    node_template = {}
    expected = copy.deepcopy(region_rings)

    actual = add_nodes_to_regions(node_template, region_rings)
    assert set(actual.keys()) == set(expected.keys())
    for k in expected.keys():
        assert dict_contains(actual[k], expected[k])

    assert list_just_contains_dicts(
        actual['eu-central-1']['nodes'], PRIVATE_CENTRAL_NODES
    )
    assert list_just_contains_dicts(
        actual['eu-west-1']['nodes'], PRIVATE_WEST_NODES
    )


def test_collect_seed_nodes():
    eu_central = copy.deepcopy(EU_CENTRAL)
    eu_central['nodes'] = PRIVATE_CENTRAL_NODES
    expected = [
        '172.31.0.11', '172.31.8.12', '172.31.0.12',
        '172.31.8.14', '172.31.0.14'
    ]
    assert set(collect_seed_nodes({'eu-central-1': eu_central})) == set(expected)


def test_get_subnet_name():
    subnet = {
        'Tags': [{
            'Key': 'Name',
            'Value': 'test-subnet'
        }]
    }
    assert get_subnet_name(subnet) == 'test-subnet'


def test_create_user_data_template():
    cluster = {
        'name': 'hello-world',
        'keystore': b'123',
        'truststore': b'321',
        'admin_password': 'qwerty',
        'docker_image': 'repo/team/artifact:v123',
        'scalyr_key': 'scalyr-key==',
        'scalyr_region': 'eu'
    }
    region_rings = {
        'eu-central-1': {
            'nodes': [
                {'_defaultIp': '12.34.56.78', 'seed?': True},
                {'_defaultIp': '8.8.8.8', 'seed?': False},
                {'_defaultIp': '34.56.78.90', 'seed?': True}
            ]
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
    assert create_user_data_template(cluster, region_rings) == expected


def test_create_user_data_for_ring():
    template = {
        'key': 'unchanged',
        'environment': {
            'OTHER': 'stuff',
        }
    }
    ring = {
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
    assert create_user_data_for_ring(template, ring, dmz=False) == expected


def test_add_taken_private_ips(ec2_fixture):
    region_rings = copy.deepcopy(REGION_RINGS)
    expected = copy.deepcopy(REGION_RINGS)
    expected['eu-central-1']['taken_ips'] = TAKEN_CENTRAL_IPS
    expected['eu-west-1']['taken_ips'] = TAKEN_WEST_IPS
    actual = add_taken_private_ips(region_rings)
    assert actual == expected


def test_add_subnets(ec2_fixture):
    region_rings = copy.deepcopy(REGION_RINGS)
    expected = copy.deepcopy(REGION_RINGS)
    expected['eu-central-1']['subnets'] = EU_CENTRAL_SUBNETS
    expected['eu-west-1']['subnets'] = EU_WEST_SUBNETS
    actual = add_subnets(region_rings)
    assert actual == expected
    

def test_prepare_rings(ec2_fixture, ec2_taupage_fixture):
    region_rings = copy.deepcopy(REGION_RINGS)
    node_template = {}
    expected = copy.deepcopy(REGION_RINGS)
    expected['eu-central-1'].update(
        taupage_ami=EU_CENTRAL_TAUPAGE_AMI,
        subnets=EU_CENTRAL_SUBNETS,
        taken_ips=TAKEN_CENTRAL_IPS)
    expected['eu-west-1'].update(
        taupage_ami=EU_WEST_TAUPAGE_AMI,
        subnets=EU_WEST_SUBNETS,
        taken_ips=TAKEN_WEST_IPS)
    actual = prepare_rings(node_template, region_rings)
    assert set(actual.keys()) == set(expected.keys())
    for k in expected.keys():
        assert dict_contains(actual[k], expected[k])

    assert list_just_contains_dicts(
        actual['eu-central-1']['nodes'], PRIVATE_CENTRAL_NODES
    )
    assert list_just_contains_dicts(
        actual['eu-west-1']['nodes'], PRIVATE_WEST_NODES
    )


def test_create_security_groups(ec2_sg_fixture):
    cluster = {'name': 'test-cluster'}

    region_rings = copy.deepcopy(REGION_RINGS)
    region_rings['eu-central-1']['nodes'] = PRIVATE_CENTRAL_NODES
    region_rings['eu-west-1']['nodes'] = PRIVATE_WEST_NODES

    expected = copy.deepcopy(region_rings)
    expected['eu-central-1']['security_group_id'] = 'sg-central-1'
    expected['eu-west-1']['security_group_id'] = 'sg-west-1'

    ec2_sg_fixture['eu-central-1'].authorize_security_group_ingress.return_value = None
    ec2_sg_fixture['eu-west-1'].authorize_security_group_ingress.return_value = None

    actual = add_security_groups(cluster, None, region_rings)
    assert actual == expected

    ec2_sg_fixture['eu-central-1'].authorize_security_group_ingress\
        .assert_called_once_with(
            GroupId='sg-central-1',
            IpPermissions=[
                {
                    'IpProtocol': '-1',
                    'UserIdGroupPairs': [{'GroupId': 'sg-central-1'}]
                }
            ]
        )
    ec2_sg_fixture['eu-west-1'].authorize_security_group_ingress\
        .assert_called_once_with(
            GroupId='sg-west-1',
            IpPermissions=[
                {
                    'IpProtocol': '-1',
                    'UserIdGroupPairs': [{'GroupId': 'sg-west-1'}]
                }
            ]
        )


def test_create_security_groups_dmz(ec2_sg_fixture):
    cluster = {'name': 'test-cluster'}

    region_rings = {
        'eu-central-1': {
            'dmz': True,
            'nodes': PUBLIC_CENTRAL_NODES
        },
        'eu-west-1': {
            'dmz': True,
            'nodes': PUBLIC_WEST_NODES
        }
    }

    expected = copy.deepcopy(region_rings)
    expected['eu-central-1']['security_group_id'] = 'sg-central-1'
    expected['eu-west-1']['security_group_id'] = 'sg-west-1'

    ec2_sg_fixture['eu-central-1'].authorize_security_group_ingress\
        .return_value = None
    ec2_sg_fixture['eu-west-1'].authorize_security_group_ingress\
        .return_value = None

    # TODO: order is not defined
    all_rules = make_ingress_rules(PUBLIC_CENTRAL_NODES + PUBLIC_WEST_NODES)

    actual = add_security_groups(cluster, None, region_rings)
    assert actual == expected

    ec2_sg_fixture['eu-central-1'].authorize_security_group_ingress\
        .assert_called_once_with(
            GroupId='sg-central-1',
            IpPermissions=(all_rules + [
                {
                    'IpProtocol': '-1',
                    'UserIdGroupPairs': [{'GroupId': 'sg-central-1'}]
                }
            ])
        )
    ec2_sg_fixture['eu-west-1'].authorize_security_group_ingress\
        .assert_called_once_with(
            GroupId='sg-west-1',
            IpPermissions=(all_rules + [
                {
                    'IpProtocol': '-1',
                    'UserIdGroupPairs': [{'GroupId': 'sg-west-1'}]
                }
            ])
        )


def test_extend_security_groups(ec2_sg_fixture):
    cluster = {'name': 'test-cluster'}
    from_region = 'eu-central-1'
    region_rings = {
        'eu-west-1': {
            'dmz': True,
            'nodes': PUBLIC_WEST_NODES
        }
    }

    expected = copy.deepcopy(region_rings)
    expected['eu-west-1']['security_group_id'] = 'sg-west-1'

    observed_west_rules = []
    def west_ingress_watcher(GroupId: str, IpPermissions: list, **kwargs):
        assert GroupId == 'sg-west-1'
        observed_west_rules.extend(IpPermissions)

    ec2_sg_fixture['eu-central-1'].authorize_security_group_ingress\
        .return_value = None
    ec2_sg_fixture['eu-west-1'].authorize_security_group_ingress\
        .side_effect = west_ingress_watcher

    central_rules = make_ingress_rules(PUBLIC_CENTRAL_NODES)
    west_rules = make_ingress_rules(PUBLIC_WEST_NODES)

    actual = add_security_groups(cluster, from_region, region_rings)
    assert actual == expected

    ec2_sg_fixture['eu-central-1'].authorize_security_group_ingress\
        .assert_called_once_with(
            GroupId='sg-central-1',
            IpPermissions=west_rules
        )
    all_rules = central_rules + west_rules
    extract_ips = lambda rules: [r['CidrIp']
                                 for rule in rules
                                 for r in rule.get('IpRanges', [])]
    assert sorted(extract_ips(observed_west_rules)) == sorted(extract_ips(all_rules))


def test_extend_security_groups_same_region(ec2_sg_fixture):
    cluster = {'name': 'test-cluster'}
    from_region = 'eu-central-1'
    region_rings = {
        'eu-central-1': {
            'dmz': False,
            'nodes': PRIVATE_CENTRAL_NODES
        }
    }

    expected = copy.deepcopy(region_rings)
    expected['eu-central-1']['security_group_id'] = 'sg-central-1'

    observed_central_rules = []
    def central_ingress_watcher(GroupId: str, IpPermissions: list, **kwargs):
        observed_central_rules.extend(IpPermissions)

    ec2_sg_fixture['eu-central-1'].authorize_security_group_ingress\
        .return_value = central_ingress_watcher

    actual = add_security_groups(cluster, from_region, region_rings)
    assert actual == expected
    assert observed_central_rules == []


def test_add_taupage_amis(ec2_taupage_fixture):
    region_rings = copy.deepcopy(REGION_RINGS)
    expected = copy.deepcopy(REGION_RINGS)
    expected['eu-central-1']['taupage_ami'] = EU_CENTRAL_TAUPAGE_AMI
    expected['eu-west-1']['taupage_ami'] = EU_WEST_TAUPAGE_AMI
    actual = add_taupage_amis(region_rings)
    assert actual == expected


def test_create_data_volume(ec2_launch_fixture):
    ec2 = ec2_launch_fixture

    node = {
        'volume': {
            'type': 'gp2',
            'size': '10',
            'name': 'test-cluster-vol111'
        },
        'subnet': {
            'zone': 'eu-central-1x'
        }
    }

    expected = 'vol-123'
    def check_create_volume(**kwargs):
        assert kwargs == {
            'AvailabilityZone': 'eu-central-1x',
            'VolumeType': 'gp2',
            'Size': '10',
            'Encrypted': False
        }
        return {
            'VolumeId': expected
        }
    ec2['eu-central-1'].create_volume.side_effect = check_create_volume

    actual = create_data_volume_for_node('eu-central-1', node)
    assert actual == expected

    ec2['eu-central-1'].create_tags.assert_called_once_with(
        Resources=[expected],
        Tags=[
            {'Key': 'Name', 'Value': 'test-cluster-vol111'},
            {'Key': 'Taupage:erase-on-boot', 'Value': 'True'}
        ]
    )


def test_launch_node(ec2_launch_fixture):
    ec2 = ec2_launch_fixture

    cluster = {
        'name': 'test-cluster',
        'instance_profile': {
            'Arn': 'arn:test-instance-profile'
        },
        'user_data_template': {
            'volumes': {
                'ebs': {
                }
            }
        }
    }
    region = {
        'taupage_ami': EU_CENTRAL_TAUPAGE_AMI,
        'security_group_id': 'sg-central-1'
    }
    node = {
        'PrivateIp': '172.31.0.0',
        'subnet': {'id': 'subnet-123', 'zone': 'eu-123'},
        'instance_type': 't2.nano',
        'volume': {
            'name': 'test-cluster-172.31.0.0'
        },
        'protect_from_termination': False
    }
    expected = 'i-central-123'
    def check_run_instances(**kwargs):
        del(kwargs['UserData']) # TODO: ignoring user data for now
        assert kwargs == {
            'ImageId': 'ami-central-1',
            'MinCount': 1,
            'MaxCount': 1,
            'SecurityGroupIds': ['sg-central-1'],
            'InstanceType': 't2.nano',
            'SubnetId': 'subnet-123',
            'PrivateIpAddress': '172.31.0.0',
            'BlockDeviceMappings': [],
            'IamInstanceProfile': {'Arn': 'arn:test-instance-profile'},
            'DisableApiTermination': False
        }
        return {
            'Instances': [
                {
                    'InstanceId': expected
                }
            ]
        }
    ec2['eu-central-1'].run_instances.side_effect = check_run_instances

    actual = launch_node(cluster, 'eu-central-1', region, node)
    assert actual == expected


def test_configure_launched_instance(ec2_launch_fixture):
    ec2 = ec2_launch_fixture

    cluster = {
        'name': 'test-cluster'
    }
    region = {
        'alarm_sns_topic_arn': 'xxx'
    }
    node = {
        'instance_id': 'i-12345',
        'PublicIp': '12.34',
        'AllocationId': 'a1'
    }

    ec2['eu-central-1'].describe_instances.return_value = {
        'Reservations': [
            {
                'Instances': [
                    {
                        'State': {
                            'Name': 'running'
                        }
                    }
                ]
            }
        ]
    }

    configure_launched_instance(cluster, 'eu-central-1', region, node)

    ec2['eu-central-1'].create_tags.assert_called_once_with(
        Resources=['i-12345'],
        Tags=[{'Key': 'Name', 'Value': 'test-cluster'}]
    )
    ec2['eu-central-1'].associate_address.assert_called_once_with(
        InstanceId='i-12345',
        AllocationId='a1'
    )
    ec2['eu-central-1'].put_metric_alarm.assert_called_once()
