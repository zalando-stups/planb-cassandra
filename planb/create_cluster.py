#!/usr/bin/env python3

import collections
import itertools
import tempfile
import requests
import netaddr
import random
import string
import base64
import copy
import time
import sys
import re
import os
from subprocess import check_call, call

import boto3
import click
from botocore.exceptions import ClientError
from clickclick import Action, info

from .aws import boto_client, list_instances, fetch_user_data, \
    setup_sns_topics_for_alarm, create_auto_recovery_alarm, \
    ensure_instance_profile

from .common import override_ephemeral_block_devices, \
    dump_user_data_for_taupage, environment_as_dict

MAX_SEEDS_PER_RING = 3


def find_security_group_by_name(ec2: object, sg_name: str) -> dict:
    resp = ec2.describe_security_groups(GroupNames=[sg_name])
    return resp['SecurityGroups'][0]


def create_security_group(region: str, ips: list, use_dmz: bool,
                          cluster_name: str, node_ips: dict) -> dict:
    description = 'Allow Cassandra nodes to talk to each other on port 7001'
    with Action('Creating Security Group in {}..'.format(region)):
        ec2 = boto_client('ec2', region)
        resp = ec2.describe_vpcs()
        # TODO: support more than one VPC..
        vpc = resp['Vpcs'][0]
        sg_name = cluster_name
        sg = ec2.create_security_group(
            GroupName=sg_name,
            VpcId=vpc['VpcId'],
            Description=description
        )

        ec2.create_tags(
            Resources=[sg['GroupId']],
            Tags=[{'Key': 'Name', 'Value': sg_name}]
        )
        ip_permissions = []
        if use_dmz:
            # NOTE: we need to allow ALL public IPs (from all regions)
            for ip in itertools.chain(*node_ips.values()):
                ingress_rule = {
                    'IpProtocol': 'tcp',
                    'FromPort': 7001,  # port range: From-To
                    'ToPort':   7001,
                    'IpRanges': [
                        {
                            'CidrIp': '{}/32'.format(ip['PublicIp'])
                        }
                    ]
                }
                ip_permissions.append(ingress_rule)
        # if internal subnets are used we just allow access from
        # within the SG, which we also need in multi-region setup
        # (for the nodetool?)
        self_ingress_rule = {
            'IpProtocol': '-1',
            'UserIdGroupPairs': [{'GroupId': sg['GroupId']}]
        }
        ip_permissions.append(self_ingress_rule)

        # if we can find the Odd security group, authorize SSH access from it
        try:
            odd_sg = find_security_group_by_name(ec2, 'Odd (SSH Bastion Host)')
            odd_ingress_rule = {
                'IpProtocol': 'tcp',
                'FromPort': 22,  # port range: From-To
                'ToPort': 22,
                'UserIdGroupPairs': [{
                    'GroupId': odd_sg['GroupId']
                }]
            }
            ip_permissions.append(odd_ingress_rule)
        except ClientError:
            msg = "No Odd host in region {}, skipping Security Group rule."
            info(msg.format(region))
            pass

        ec2.authorize_security_group_ingress(
            GroupId=sg['GroupId'],
            IpPermissions=ip_permissions
        )

        return sg


def extend_security_group(region: str, sg: dict, other_region_ips: list):
    with Action('Updating Security Group in {}..'.format(region)):
        ip_permissions = [
            {
                'IpProtocol': 'tcp',
                'FromPort': 7001,  # port range: From-To
                'ToPort':   7001,
                'IpRanges': [
                    {
                        'CidrIp': '{}/32'.format(ip['PublicIp'])
                    }
                ]
            }
            for ip in other_region_ips
        ]

        ec2 = boto_client('ec2', region)
        ec2.authorize_security_group_ingress(
            GroupId=sg['GroupId'],
            IpPermissions=ip_permissions
        )


def setup_security_groups(use_dmz: bool, cluster_name: str, node_ips: dict,
                          result: dict) -> dict:
    '''
    Allow traffic between regions (or within a VPC, if `use_dmz' is False)
    '''
    for region, ips in node_ips.items():
        result[region] = create_security_group(
            region, ips, use_dmz, cluster_name, node_ips
        )


def get_public_ips_from_sg(sg: dict) -> list:
    result = []
    for ip in sg['IpPermissions']:
        if ip['IpProtocol'] == 'tcp' and \
           ip['FromPort'] == 7001 and ip['ToPort'] == 7001:
            for ip_range in ip['IpRanges']:
                cidr_ip = ip_range.get('CidrIp')
                if cidr_ip and cidr_ip.endswith('/32'):
                    result.append({
                        'PublicIp': cidr_ip.replace('/32', '')
                    })
    return result


def find_taupage_amis(regions: list) -> dict:
    '''
    Find latest Taupage AMI for each region
    '''
    result = {}
    for region in regions:
        with Action('Finding latest Taupage AMI in {}..'.format(region)):
            # TODO: can we use our wrapped boto client here as well?
            ec2 = boto3.resource('ec2', region)
            filters = [
                {'Name': 'name', 'Values': ['*Taupage-AMI-*']},
                {'Name': 'is-public', 'Values': ['false']},
                {'Name': 'state', 'Values': ['available']},
                {'Name': 'root-device-type', 'Values': ['ebs']}
            ]
            images = list(ec2.images.filter(Filters=filters))
            if not images:
                raise Exception('No Taupage AMI found')
            most_recent_image = sorted(images, key=lambda i: i.name)[-1]
            result[region] = most_recent_image
        info(most_recent_image.name)
    return result


def get_latest_docker_image_version(artifact_name):
    url = 'https://registry.opensource.zalan.do/teams/stups/artifacts/{}/tags' \
          .format(artifact_name)
    return requests.get(url).json()[-1]['name']


password_chars = "{}{}{}".format(
    string.ascii_letters, string.digits,
    re.sub("[\\\\'\"]", "", string.punctuation)
)


def generate_password(length: int = 32) -> str:
    return "".join(random.choice(password_chars) for x in range(length))


def generate_certificate(cluster_name: str):
    check = call(["which", "keytool"])
    if check:
        print("Keytool is not in searchpath")
        return

    d = tempfile.mkdtemp()
    try:
        keystore = os.path.join(d, 'keystore')
        cmd = [
            "keytool", "-genkeypair",
            "-alias", "planb",
            "-keyalg", "RSA",
            "-validity", "36000",
            "-keystore", keystore,
            "-dname", "c=DE, st=Berlin, l=Berlin, o=Zalando SE, cn=zalando.net",
            "-storepass", cluster_name,
            "-keypass", cluster_name
        ]
        check_call(cmd)
        cert = os.path.join(d, 'cert')
        export = [
            "keytool", "-export",
            "-alias", "planb",
            "-keystore", keystore,
            "-rfc",
            "-file", cert,
            "-storepass", cluster_name
        ]
        check_call(export)
        truststore = os.path.join(d, 'truststore')
        importcmd = [
            "keytool", "-import",
            "-noprompt",
            "-alias", "planb",
            "-file", cert,
            "-keystore", truststore,
            "-storepass", cluster_name
        ]
        check_call(importcmd)

        with open(keystore, 'rb') as fd:
            keystore_data = fd.read()
        with open(truststore, 'rb') as fd:
            truststore_data = fd.read()
    finally:
        pass
    return keystore_data, truststore_data


def init_cluster_secuirty_features(cluster: dict):
    "Enriches the cluster dict with admin password and key/trust-store data."

    cluster['admin_password'] = generate_password()
    cluster['keystore'], cluster['truststore'] = generate_certificate(
        cluster['name']
    )


# def calc_seed_nodes_count(region_rings: dict) -> dict:
#     return {
#         region: [dict(r, seed_count=min(r['size'], MAX_SEEDS_PER_RING))
#                  for r in rings]
#         for region, rings in region_rings.items()
#     }


def seed_iterator(rings: list) -> object:
    """For a list of rings it returns an iterator over `seed?` predicates."""
    for ring in rings:
        for i in range(ring['size']):
            if i < min(ring['size'], MAX_SEEDS_PER_RING):
                b = True
            else:
                b = False
            yield b


class IpAddressPoolDepletedException(Exception):

    def __init__(self, cidr_block: str):
        msg = "Pool of unused IP addresses depleted in subnet: {}".format(cidr_block)
        super(IpAddressPoolDepletedException, self).__init__(msg)


def try_next_address(address_iterator: object, cidr_block: str) -> str:
    try:
        return str(next(address_iterator))
    except StopIteration:
        raise IpAddressPoolDepletedException(cidr_block)


def get_network_iterator(cidr_block: str) -> object:
    iterator = netaddr.IPNetwork(cidr_block).iter_hosts()
    #
    # Some of the first addresses in each subnet are taken by AWS system
    # instances that we can't see, so we try to skip them.
    #
    for _ in range(10):
        try_next_address(iterator, cidr_block)
    return iterator


def get_region_ip_iterator(
        subnets: list, taken_ips: set, elastic_ips: list, dmz: bool) -> object:
    """Returns an iterator over IPs from the cycle of subnets.
       May raise an IpAddressPoolDepletedException."""
    # We can do this because of the stups naming convention
    subnet_prefix = 'dmz-' if dmz else 'internal-'
    nets = [s for s in subnets
              if s['name'].startswith(subnet_prefix)]

    iterators = {s['name'] : get_network_iterator(s['cidr_block'])
                 for s in nets}
    eips = iter(elastic_ips)

    for s in itertools.cycle(nets):
        while True:
            ip = try_next_address(iterators[s['name']], s['cidr_block'])
            if ip not in taken_ips:
                break
        address = {'PrivateIp': ip}
        if dmz:
            resp = next(eips)
            address['_defaultIp'] = resp['PublicIp']
            address['PublicIp'] = resp['PublicIp']
            address['AllocationId'] = resp['AllocationId']
        else:
            address['_defaultIp'] = ip
        address['subnet'] = s['name']
        yield address


def make_nodes(region: dict) -> list:
    ipiter = get_region_ip_iterator(
        region['subnets'], region['taken_ips'],
        region['elastic_ips'], region['dmz'])
    nodes = []
    seeds = seed_iterator(region['rings'])
    for s, ip in zip(seeds, ipiter):
        ip.update({'seed?': s})
        nodes.append(ip)

    return nodes


def add_nodes_to_regions(region_rings: dict) -> dict:
    # iterate over regions and call make_nodes
    # TODO
    pass


def list_taken_private_ips(ec2: object) -> set:
    #paginator = ec2.get_paginator('describe_instances')
    #resp = paginator.paginate().build_full_result()
    #
    # TODO: paginators don't enjoy our retry/refresh wrappers unfortunately.
    # Using MaxResults=1000 sounds like a good enough approximation for now.
    #
    instances = list_instances(ec2, MaxResults=1000)
    return set([i['PrivateIpAddress'] for i in instances])


def xxx(subnets: list, ips_count: int, taken_ips: list) -> list:
    addresses = []
    for ip in generate_private_ip_addresses(subnets, ips_count, taken_ips):
        address = {'PrivateIp': ip}

        if take_elastic_ips:
            resp = ec2.allocate_address(Domain='vpc')
            address['_defaultIp'] = resp['PublicIp']
            address['PublicIp'] = resp['PublicIp']
            address['AllocationId'] = resp['AllocationId']
        else:
            address['_defaultIp'] = ip
        addresses.append(address)

    return addresses


def allocate_ip_addresses(
        region_subnets: dict, cluster_size: int,
        node_ips: dict, take_elastic_ips: bool):
    '''
    Allocate unused private IP addresses by checking the current
    reservations, and optionally allocate Elastic IPs.
    '''
    for region, subnets in region_subnets.items():
        with Action('Allocating IP addresses in {}..'.format(region)) as act:
            ec2 = boto_client('ec2', region)

            taken_ips = list_taken_private_ips(ec2)
            node_ips[region] = xxx(subnets, cluster_size, taken_ips)


def pick_seed_node_ips(node_ips: dict, seed_count: int) -> dict:
    '''
    Take first {seed_count} IPs in every region for the seed nodes.
    '''
    seed_nodes = {}
    for region, ips in node_ips.items():
        seed_nodes[region] = ips[0:seed_count]

        list_ips = ', '.join([ip['_defaultIp'] for ip in seed_nodes[region]])
        info('Our seed nodes in {} will be: {}'.format(region, list_ips))
    return seed_nodes


def get_subnet_name(subnet: dict) -> str:
    for tag in subnet['Tags']:
        if tag['Key'] == 'Name':
            return tag['Value']


def get_region_subnets(region_name: str) -> list:
    ec2 = boto_client('ec2', region_name)
    resp = ec2.describe_subnets()
    sorted_subnets = sorted(
        resp['Subnets'],
        key=lambda subnet: subnet['AvailabilityZone']
    )
    return [{'name': get_subnet_name(subnet),
             'cidr_block': subnet['CidrBlock']}
            for subnet in sorted_subnets]


def get_subnets(regions: dict) -> dict:
    return {region_name: dict(region, subnets=get_region_subnets(region_name))
            for region_name, region in regions.items()}


def hostname_from_private_ip(region: str, ip: str) -> str:
    return 'ip-{}.{}.compute.internal.'.format('-'.join(ip.split('.')), region)


def make_dns_records(region: str, ips: list) -> list:
    hosts = [hostname_from_private_ip(region, ip['PrivateIp']) for ip in ips]
    return [{'Value': '1 1 9042 {}'.format(host)} for host in hosts]


def setup_dns_records(
        cluster_name: str, hosted_zone: str, node_ips: dict, dc_suffix: str=""):

    r53 = boto_client('route53')

    zone = None
    zones = r53.list_hosted_zones_by_name(DNSName=hosted_zone)
    for z in zones['HostedZones']:
        if z['Name'] == hosted_zone:
            zone = z
    if not zone:
        raise Exception('Failed to find Hosted Zone {}'.format(hosted_zone))

    for region, ips in node_ips.items():
        with Action('Setting up Route53 SRV records in {}..'.format(region)):
            name = '_{}{}-{}._tcp.{}'.format(
                cluster_name, dc_suffix, region, hosted_zone
            )
            #
            # NB: We always want the clients to connect using private
            # IP addresses.
            #
            # But we must record the host names, otherwise the client
            # will get the addresses ending with the dot from the DSN
            # lookup and won't recognize them as such.
            #
            records = make_dns_records(region, ips)

            r53.change_resource_record_sets(
                HostedZoneId=zone['Id'],
                ChangeBatch={
                    'Changes': [{
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': name,
                            'Type': 'SRV',
                            'TTL': 60,
                            'ResourceRecords': records
                        }
                    }]
                }
            )


def list_all_seed_node_ips(seed_nodes: dict) -> list:
    return [
        ip['_defaultIp']
        for region, ips in seed_nodes.items()
        for ip in ips
    ]


def collect_seed_nodes(region_rings: dict) -> list:
    return sum([seeds
                for _, region in region_rings.items()
                for ring in region['rings']
                for _, seeds in ring['seeds'].items()],
               [])


def create_user_data_template(cluster: dict, region_rings: dict) -> dict:
    '''
    Generate Taupage user data to start a Cassandra node
    http://docs.stups.io/en/latest/components/taupage.html
    '''
    keystore_base64 = base64.b64encode(cluster['keystore'])
    truststore_base64 = base64.b64encode(cluster['truststore'])

    data = {
        'runtime': 'Docker',
        'source': cluster['docker_image'],
        'application_id': cluster['name'],
        'application_version': cluster['docker_image'].split(':')[-1], # TODO: WTF?
        'networking': 'host',
        'ports': {
            '7001': '7001',
            '9042': '9042'
        },
        'environment': {
            'CLUSTER_NAME': cluster['name'],
            'SEEDS': ','.join(collect_seed_nodes(region_rings)),
            'KEYSTORE': str(keystore_base64, 'UTF-8'),
            'TRUSTSTORE': str(truststore_base64, 'UTF-8'),
            'ADMIN_PASSWORD': cluster['admin_password']
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
        'scalyr_account_key': cluster['scalyr_key']
    }
    if cluster.get('scalyr_region'):
        data['scalyr_region'] = cluster['scalyr_region']

    return data


def create_user_data_for_ring(template: dict, ring: dict) -> dict:
    data = copy.deepcopy(template)

    env = data['environment']
    env['NUM_TOKENS'] = ring['num_tokens']
    env['SUBNET_TYPE'] = 'dmz' if ring['dmz'] else 'internal'

    if ring.get('environment'):
        data['environment'].update(ring['environment'])

    return data


def create_tagged_volume(ec2: object, options: dict, zone: str, name: str):
    ebs_data = {
        "AvailabilityZone": zone,
        "VolumeType": options['volume_type'],
        "Size": options['volume_size'],
        "Encrypted": False,
    }
    if options['volume_type'] == 'io1':
        ebs_data['Iops'] = options['volume_iops']
    vol = ec2.create_volume(**ebs_data)

    tags = [
        {'Key': 'Name', 'Value': name},
        {'Key': 'Taupage:erase-on-boot', 'Value': 'True'}
    ]
    ec2.create_tags(Resources=[vol['VolumeId']], Tags=tags)


def launch_instance(region: str, ip: dict, ami: object, subnet: dict,
                    security_group_id: str, is_seed: bool, options: dict):

    node_type = 'SEED' if is_seed else 'NORMAL'
    msg = 'Launching {} node {} in {}..'.format(
        node_type,
        ip['_defaultIp'],
        region
    )
    with Action(msg) as act:
        ec2 = boto_client('ec2', region)

        mappings = ami.block_device_mappings
        block_devices = override_ephemeral_block_devices(mappings)

        volume_name = '{}-{}'.format(options['cluster_name'], ip['PrivateIp'])
        create_tagged_volume(
            ec2,
            options,
            subnet['AvailabilityZone'],
            volume_name
        )

        user_data = options['user_data']
        user_data['volumes']['ebs']['/dev/xvdf'] = volume_name
        taupage_user_data = dump_user_data_for_taupage(user_data)

        resp = ec2.run_instances(
            ImageId=ami.id,
            MinCount=1,
            MaxCount=1,
            SecurityGroupIds=[security_group_id],
            UserData=taupage_user_data,
            InstanceType=options['instance_type'],
            SubnetId=subnet['SubnetId'],
            PrivateIpAddress=ip['PrivateIp'],
            BlockDeviceMappings=block_devices,
            IamInstanceProfile={'Arn': options['instance_profile']['Arn']},
            DisableApiTermination=not(options['no_termination_protection'])
        )
        instance = resp['Instances'][0]
        instance_id = instance['InstanceId']

        ec2.create_tags(
            Resources=[instance_id],
            Tags=[{'Key': 'Name', 'Value': options['cluster_name']}]
        )
        # wait for instance to initialize before we can assign a
        # public IP address to it or tag the attached volume
        while True:
            resp = ec2.describe_instances(InstanceIds=[instance_id])
            instance = resp['Reservations'][0]['Instances'][0]
            if instance['State']['Name'] != 'pending':
                break
            time.sleep(5)
            act.progress()

        if options['use_dmz']:
            ec2.associate_address(
                InstanceId=instance_id,
                AllocationId=ip['AllocationId']
            )

        alarm_sns_topic_arn = None
        if options['alarm_topics']:
            alarm_sns_topic_arn = options['alarm_topics'][region]

        create_auto_recovery_alarm(
            region, options['cluster_name'],
            instance_id, alarm_sns_topic_arn
        )


def launch_seed_nodes(options: dict):
    total_seed_count = options['seed_count'] * len(options['regions'])
    seeds_launched = 0
    for region, ips in options['seed_nodes'].items():
        security_group_id = options['security_groups'][region]['GroupId']
        subnets = options['subnets'][region]
        for i, ip in enumerate(ips):
            launch_instance(
                region, ip,
                ami=options['taupage_amis'][region],
                subnet=subnets[i % len(subnets)],
                security_group_id=security_group_id,
                is_seed=True,
                options=options
            )
            seeds_launched += 1
            if seeds_launched < total_seed_count:
                info("Sleeping for a minute before launching next SEED node..")
                time.sleep(60)


def launch_normal_nodes(options: dict):
    # TODO: parallelize by region?
    for region, ips in options['node_ips'].items():
        subnets = options['subnets'][region]
        security_group_id = options['security_groups'][region]['GroupId']
        for i, ip in enumerate(ips):
            if i >= options['seed_count']:
                # avoid stating all nodes at the same time
                info("Sleeping for one minute before launching next node..")
                time.sleep(60)
                launch_instance(
                    region, ip,
                    ami=options['taupage_amis'][region],
                    subnet=subnets[i % len(subnets)],
                    security_group_id=security_group_id,
                    is_seed=False,
                    options=options
                )


def print_success_message(options: dict):
    info('Cluster initialization completed successfully!')

    regions_list = ' '.join(options['regions'])

    # prepare alter keyspace params in the format: 'eu-central': N [, ...]
    dc_list = ', '.join([
        "'{}': {}".format(re.sub('-[0-9]+$', '', r), options['cluster_size'])
        for r in options['regions']
    ])

    sys.stdout.write('''
The Cassandra cluster {cluster_name} was created with {cluster_size} nodes
in each of the following AWS regions: {regions_list}

You might need to update the Security Group named {cluster_name}
(in all regions!) to allow access to Cassandra from the Odd host (port 22),
from your application (port 9042) and optionally to allow access to Jolokia
(port 8778) and/or Prometheus Node Exporter (port 9100) from your monitoring
tool.

You should now login to any of the cluster nodes to change the replication
settings of system_auth keyspace and to create the admin superuser, using the
following commands:

$ docker exec -ti taupageapp bash

(docker)$ cqlsh -u cassandra -p cassandra \\
  -e "ALTER KEYSPACE system_auth WITH replication = {{
        'class': 'NetworkTopologyStrategy', {dc_list}
      }};
      CREATE USER admin WITH PASSWORD '$ADMIN_PASSWORD' SUPERUSER;"

Then login with the newly created admin account and disable the default
superuser account:

(docker)$ cqlsh -u admin -p $ADMIN_PASSWORD

cqlsh> ALTER USER cassandra WITH PASSWORD '{random_pw}' NOSUPERUSER;

You can then also create non-superuser application roles and data keyspace(s).

In general, follow the documentation on setting up authentication, depending
on your Cassandra version:

  http://docs.datastax.com/en/cassandra/3.0/cassandra/configuration/secureConfigNativeAuth.html
  http://docs.datastax.com/en/cassandra/2.1/cassandra/security/security_config_native_authenticate_t.html
'''.format(**options, regions_list=regions_list, dc_list=dc_list,
           random_pw=generate_password()))


def print_failure_message():
    sys.stderr.write('''
You were trying to deploy Plan B Cassandra, but the process has failed :-(

One of the reasons might be that some of Private IP addresses we were
going to use to launch the EC2 instances were taken by some other
instances in the middle of the process.  If that is the case, simply
retrying the operation might resolve the problem (you still might need
to clean up after this attempt before retrying).

Please review the error message to see if that is the case, then
either correct the error or retry.

''')


def validate_artifact_version(options: dict) -> dict:
    conflict_options_msg = """Conflicting options: --artifact-name and
--docker-image cannot be specified at the same time"""
    if not options['docker_image']:
        if not options['artifact_name']:
            options['artifact_name'] = 'planb-cassandra-3.0'
        image_version = get_latest_docker_image_version(options['artifact_name'])
        docker_image = 'registry.opensource.zalan.do/stups/{}:{}' \
                       .format(options['artifact_name'], image_version)
        info('Using docker image: {}'.format(docker_image))
    else:
        if options['artifact_name']:
            raise click.UsageError(conflict_options_msg)
        image_version = options['docker_image'].split(':')[-1]
        docker_image = options['docker_image']
    return dict(options, docker_image=docker_image, image_version=image_version)


def fetch_user_data_template(from_region: str, cluster: dict) -> dict:
    ec2 = boto_client('ec2', from_region)
    running_instances = [
        i
        for i in list_instances(ec2, cluster['name'])
        if i['State']['Name'] == 'running'
    ]
    if not running_instances:
        msg = "Could not find any running EC2 instances for {} in {}".format(
            cluster['name'],
            from_region
        )
        raise click.UsageError(msg)

    # TODO: should user be able to specify the clone-from instance?
    instance_id = running_instances[0]['InstanceId']
    return decode_user_data(fetch_user_data(ec2, instance_id))


def create_rings(cluster: dict, from_region: str, region_rings: dict):
    # 1. Go to Orodruin TODO?

    # prepare
    region_rings = get_subnets(region_rings) ## TODO: name sounds odd in this context
    # TODO: put the taken IPs into the region
    region_taken_ips = {r: list_taken_private_ips(boto_client('ec2', region_name=r))
                        for r in region_rings.keys()}
    # TODO: allocate elastic IPs and put it into region
    region_rings = get_ips_for_seeds(region_rings, region_taken_ips)

    if from_region:
        user_data_template = fetch_user_data_template(from_region, cluster)
    else:
        init_cluster_secuirty_features(cluster)
        user_data_template = create_user_data_template(cluster, region_rings)

    # dostuff
    # * per region
    # ** setup or extend SGs
    # ** per ring
    # TODO: consider starting all seed nodes from all rings first, then normal ones
    for region, rings in region_to_rings.items():
        for ring in rings:
            user_data = create_user_data_for_ring(user_data_template, ring)
    # *** launch seed nodes
    # *** launch normal nodes

    # cleanup


def create_cluster(options: dict):
    cluster = {
        'name': options['cluster_name'],
        'protect_from_termination': not(options['no_termination_protection']),
        'hosted_zone': options['hosted_zone'],
        'scalyr_region': options['scalyr_region'],
        'scalyr_key': options['scalyr_key'],
        'docker_image': options['docker_image'], # TODO: resolve using artifact name
        'environment': options['environment'],
        'sns_topic': options['sns_topic'],
        'sns_email': options['sns_email']
    }
    region_rings = {
        region: {
            'rings': [{
                'size': options['cluster_size'],
                'dmz': options['use_dmz'],
                'dc_suffix': options['dc_suffix'],
                'num_tokens': options['num_tokens'],
                'instance_type': options['instance_type'],
                'volume_type': options['volume_type'],
                'volume_size': options['volume_size'],
                'volume_iops': options['volume_iops'],
                'taupage_ami': None # TODO: let to override
            }]
        }
        for region in options['regions']
    }
    create_rings(cluster, from_region=None, region_rings=region_rings)

################################################################################
# old implementation
#
    options = validate_artifact_version(options)
    options['environment'] = environment_as_dict(options.get('environment', []))

    keystore, truststore = generate_certificate(options['cluster_name'])

    # List of IP addresses by region
    node_ips = collections.defaultdict(list)

    # Mapping of region name to the Security Group
    security_groups = {}

    try:
        taupage_amis = find_taupage_amis(options['regions'])

        subnets = get_subnets(
            'dmz-' if options['use_dmz'] else 'internal-',
            options['regions']
        )
        allocate_ip_addresses(
            subnets, options['cluster_size'], node_ips,
            take_elastic_ips=options['use_dmz']
        )

        if options['sns_topic'] or options['sns_email']:
            alarm_topics = setup_sns_topics_for_alarm(
                options['regions'],
                options['sns_topic'],
                options['sns_email']
            )
        else:
            alarm_topics = {}

        if options['hosted_zone']:
            setup_dns_records(
                options['cluster_name'],
                options['hosted_zone'],
                node_ips
            )
        setup_security_groups(
            options['use_dmz'],
            options['cluster_name'],
            node_ips,
            security_groups
        )
        # We should have up to 3 seeds nodes per DC
        seed_count = min(options['cluster_size'], 3)
        seed_nodes = pick_seed_node_ips(node_ips, seed_count)

        options = dict(
            options,
            keystore=keystore,
            truststore=truststore,
            seed_count=seed_count,
            seed_nodes=seed_nodes
        )
        user_data = generate_taupage_user_data(options)

        instance_profile = ensure_instance_profile(options['cluster_name'])

        options = dict(
            options,
            node_ips=node_ips,
            security_groups=security_groups,
            taupage_amis=taupage_amis,
            subnets=subnets,
            alarm_topics=alarm_topics,
            user_data=user_data,
            instance_profile=instance_profile
        )
        launch_seed_nodes(options)

        # TODO: make sure all seed nodes are up
        launch_normal_nodes(options)

        print_success_message(options)

    except:
        print_failure_message()

        #
        # TODO: in order to break dependencies, delete entities in the
        # order opposite to the creation.  For that pushing things on
        # Undo stack sounds like a natural choice.
        #
        for region, sg in security_groups.items():
            ec2 = boto_client('ec2', region)
            info('Cleaning up security group: {}'.format(sg['GroupId']))
            ec2.delete_security_group(GroupId=sg['GroupId'])

        if options['use_dmz']:
            for region, ips in node_ips.items():
                ec2 = boto_client('ec2', region)
                for ip in ips:
                    info('Releasing IP address: {}'.format(ip['PublicIp']))
                    ec2.release_address(AllocationId=ip['AllocationId'])

        raise


def extend_cluster(options: dict):
    cluster = {
        'name': options['cluster_name'],
        'protect_from_termination': not(options['no_termination_protection']),
        'hosted_zone': options['hosted_zone'],
        'scalyr_region': options['scalyr_region'],
        'scalyr_key': options['scalyr_key'],
        'docker_image': options['docker_image'], # TODO: resolve using artifact name
        'environment': options['environment'],
        'sns_topic': options['sns_topic'],
        'sns_email': options['sns_email']
    }
    region_rings = {
        options['to_region']: {
            'rings': [{
                'size': options['ring_size'],
                'dmz': options['use_dmz'],  # TODO: currently it seems not supported by our network to have it as attr of ring
                'dc_suffix': options['dc_suffix'],
                'num_tokens': options['num_tokens'],
                'instance_type': options['instance_type'],
                'volume_type': options['volume_type'],
                'volume_size': options['volume_size'],
                'volume_iops': options['volume_iops'],
                'taupage_ami': None
            }]
        }
    }
    create_rings(
        cluster, from_region=options['from_region'], region_rings=region_rings
    )

################################################################################
# old implementation
#

    # TODO: don't override docker image?
    options = validate_artifact_version(options)
    options['environment'] = environment_as_dict(options.get('environment', []))

    # List of IP addresses by region
    node_ips = collections.defaultdict(list)

    # Mapping of region name to the Security Group
    security_groups = {}

    try:
        # TODO: get it from a running instance details?
        taupage_amis = find_taupage_amis([options['to_region']])

        subnets = get_subnets(
            'dmz-' if options['use_dmz'] else 'internal-',
            [options['to_region']]
        )
        allocate_ip_addresses(
            subnets, options['ring_size'], node_ips,
            take_elastic_ips=options['use_dmz']
        )

        if options['sns_topic'] or options['sns_email']:
            alarm_topics = setup_sns_topics_for_alarm(
                [options['to_region']],
                options['sns_topic'],
                options['sns_email']
            )
        else:
            alarm_topics = {}

        if options['hosted_zone']:
            setup_dns_records(
                options['cluster_name'],
                options['hosted_zone'],
                node_ips,
                options['dc_suffix']
            )

        cluster_sg = find_security_group_by_name(ec2, options['cluster_name'])
        security_groups = {
            options['from_region']: cluster_sg
        }
        if options['to_region'] != options['from_region']:
            all_ips = node_ips.copy()
            all_ips[options['from_region']] = get_public_ips_from_sg(cluster_sg)

            security_groups[options['to_region']] = create_security_group(
                options['to_region'],
                node_ips[options['to_region']],
                options['use_dmz'],
                options['cluster_name'],
                all_ips
            )
            # TODO: no rollback for now
            extend_security_group(
                options['from_region'],
                cluster_sg,
                node_ips[options['to_region']]
            )

        # We should have up to 3 seeds nodes per DC
        seed_count = min(options['ring_size'], 3)
        seed_nodes = pick_seed_node_ips(node_ips, seed_count)

        options = dict(
            options,
            seed_count=seed_count,
            seed_nodes=seed_nodes
        )


        env = user_data['environment']
        env['AUTO_BOOTSTRAP'] = 'false'
        env['DC_SUFFIX'] = options['dc_suffix']

        new_seeds = list_all_seed_node_ips(seed_nodes)
        env['SEEDS'] = "{},{}".format(','.join(new_seeds), env['SEEDS'])

        instance_profile = ensure_instance_profile(options['cluster_name'])

        # we only launch instances in the target region:
        options['regions'] = [options['to_region']]

        options = dict(
            options,
            node_ips=node_ips,
            security_groups=security_groups,
            taupage_amis=taupage_amis,
            subnets=subnets,
            alarm_topics=alarm_topics,
            user_data=user_data,
            instance_profile=instance_profile
        )
        launch_seed_nodes(options)

        # TODO: make sure all seed nodes are up
        launch_normal_nodes(options)

    except:
        print_failure_message()

        if options['to_region'] != options['from_region']:
            region = options['to_region']
            sg = security_groups.get(region)
            if sg:
                info('Cleaning up security group: {}'.format(sg['GroupId']))
                ec2 = boto_client('ec2', region)
                ec2.delete_security_group(GroupId=sg['GroupId'])

        if options['use_dmz']:
            for region, ips in node_ips.items():
                ec2 = boto_client('ec2', region)
                for ip in ips:
                    if 'AllocationId' in ip:
                        info('Releasing IP address: {}'.format(ip['PublicIp']))
                        ec2.release_address(AllocationId=ip['AllocationId'])

        raise
