import pytest
from unittest.mock import MagicMock

from create_cluster import *

def test_generate_private_ip_addresses():
    ec2 = MagicMock()
    # for a test, assume no private IP is taken
    ec2.describe_instances.return_value = {'Reservations': []}

    region_subnets = {
        'eu-central-1': [
            {'CidrBlock': '171.31.0.0/21'},
            {'CidrBlock': '171.31.8.0/21'}
        ],
        'eu-west-1': [
            {'CidrBlock': '171.31.0.0/21'},
            {'CidrBlock': '171.31.8.0/21'},
            {'CidrBlock': '171.31.16.0/21'}
        ]
    }
    #
    # The ip ranges for the above networks start with .1 and we skip
    # the first 10 of them in every subnet, hence the available ones
    # start with .11
    #
    expected_ips = {
        'eu-central-1': [
            '171.31.0.11', '171.31.8.11', '171.31.0.12', '171.31.8.12', '171.31.0.13'
        ],
        'eu-west-1': [
            '171.31.0.11', '171.31.8.11', '171.31.16.11', '171.31.0.12', '171.31.8.12'
        ]
    }

    cluster_size = 5

    for region, subnets in region_subnets.items():
        assert list(generate_private_ip_addresses(ec2, subnets, cluster_size)) == expected_ips[region]

    with pytest.raises(IpAddressPoolDepletedException):
        print(list(generate_private_ip_addresses(ec2, [{'CidrBlock': '192.168.1.0/29'}], 10)))

    list(generate_private_ip_addresses(ec2, [{'CidrBlock': '192.168.1.0/27'}], 20))

    with pytest.raises(IpAddressPoolDepletedException):
        list(generate_private_ip_addresses(ec2, [{'CidrBlock': '192.168.1.0/27'}], 21))
