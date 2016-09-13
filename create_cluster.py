#!/usr/bin/env python3

import itertools
import time
import base64
import boto3
from botocore.exceptions import ClientError
import click
import collections
import yaml
import requests
import string
import re
import random
from clickclick import Action, info, action
from subprocess import check_call, call
import tempfile
import os
import sys
import copy
import netaddr


def setup_security_groups(internal: bool, cluster_name: str, node_ips: dict,
                          result: dict) -> dict:
    '''
    Allow traffic between regions (or within a VPC, if `internal' is True)
    '''
    for region, ips in node_ips.items():
        with Action('Configuring Security Group in {}..'.format(region)):
            ec2 = boto3.client('ec2', region)
            resp = ec2.describe_vpcs()
            # TODO: support more than one VPC..
            vpc = resp['Vpcs'][0]
            sg_name = cluster_name
            sg = ec2.create_security_group(GroupName=sg_name,
                                           VpcId=vpc['VpcId'],
                                           Description='Allow Cassandra nodes to talk to each other on Secure Transport port 7001')
            result[region] = sg

            ec2.create_tags(Resources=[sg['GroupId']],
                            Tags=[{'Key': 'Name', 'Value': sg_name}])

            ip_permissions = []
            if not internal:
                # NOTE: we need to allow ALL public IPs (from all regions)
                for ip in itertools.chain(*node_ips.values()):
                    ip_permissions.append({
                        'IpProtocol': 'tcp',
                        'FromPort': 7001,  # port range: From-To
                        'ToPort':   7001,
                        'IpRanges': [{
                            'CidrIp': '{}/32'.format(ip['PublicIp'])
                        }]
                    })
            # if internal subnets are used we just allow access from
            # within the SG, which we also need in multi-region setup
            # (for the nodetool?)
            ip_permissions.append({'IpProtocol': '-1',
                                   'UserIdGroupPairs': [{'GroupId': sg['GroupId']}]})

            # if we can find the Odd security group, authorize SSH access from it
            try:
                resp = ec2.describe_security_groups(GroupNames=['Odd (SSH Bastion Host)'])
                odd_sg = resp['SecurityGroups'][0]

                ip_permissions.append({
                    'IpProtocol': 'tcp',
                    'FromPort': 22,  # port range: From-To
                    'ToPort': 22,
                    'UserIdGroupPairs': [{
                        'GroupId': odd_sg['GroupId']
                    }]
                })
            except ClientError:
                info("Could not find Odd bastion host in region {}, skipping Security Group rule.".format(region))
                pass

            ec2.authorize_security_group_ingress(GroupId=sg['GroupId'],
                                                 IpPermissions=ip_permissions)


def find_taupage_amis(regions: list) -> dict:
    '''
    Find latest Taupage AMI for each region
    '''
    result = {}
    for region in regions:
        with Action('Finding latest Taupage AMI in {}..'.format(region)):
            ec2 = boto3.resource('ec2', region)
            filters = [{'Name': 'name', 'Values': ['*Taupage-AMI-*']},
                       {'Name': 'is-public', 'Values': ['false']},
                       {'Name': 'state', 'Values': ['available']},
                       {'Name': 'root-device-type', 'Values': ['ebs']}]
            images = list(ec2.images.filter(Filters=filters))
            if not images:
                raise Exception('No Taupage AMI found')
            most_recent_image = sorted(images, key=lambda i: i.name)[-1]
            result[region] = most_recent_image
        info(most_recent_image.name)
    return result


def get_latest_docker_image_version():
    url = 'https://registry.opensource.zalan.do/teams/stups/artifacts/planb-cassandra/tags'
    return requests.get(url).json()[-1]['name']


password_chars = "{}{}{}".format(string.ascii_letters, string.digits,
                                 re.sub("[\\\\'\"]", "", string.punctuation))


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
        cmd = ["keytool", "-genkeypair",
               "-alias", "planb",
               "-keyalg", "RSA",
               "-validity", "36000",
               "-keystore", keystore,
               "-dname", "c=DE, st=Berlin, l=Berlin, o=Zalando SE, cn=zalando.net",
               "-storepass", cluster_name,
               "-keypass", cluster_name]
        check_call(cmd)
        cert = os.path.join(d, 'cert')
        export = ["keytool", "-export",
                  "-alias", "planb",
                  "-keystore", keystore,
                  "-rfc",
                  "-file", cert,
                  "-storepass", cluster_name]
        check_call(export)
        truststore = os.path.join(d, 'truststore')
        importcmd = ["keytool", "-import",
                     "-noprompt",
                     "-alias", "planb",
                     "-file", cert,
                     "-keystore", truststore,
                     "-storepass", cluster_name]
        check_call(importcmd)

        with open(keystore, 'rb') as fd:
            keystore_data = fd.read()
        with open(truststore, 'rb') as fd:
            truststore_data = fd.read()
    finally:
        pass
    return keystore_data, truststore_data


class IpAddressPoolDepletedException(Exception):

    def __init__(self, cidr_block: str):
        msg = "Pool of unused IP addresses depleted in subnet: {}".format(cidr_block)
        super(IpAddressPoolDepletedException, self).__init__(msg)


def generate_private_ip_addresses(ec2: object, subnets: list, cluster_size: int):

    def try_next_address(ips, subnet):
        try:
            return str(next(ips))
        except StopIteration:
            raise IpAddressPoolDepletedException(subnet['CidrBlock'])

    #
    # Here we have to account for the behavior of launch_*_nodes
    # which iterate through subnets to put the instances into
    # different Availability Zones.
    #
    network_ips = [netaddr.IPNetwork(s['CidrBlock']).iter_hosts() for s in subnets]

    for idx, ips in enumerate(network_ips):
        #
        # Some of the first addresses in each subnet are
        # taken by AWS system instances that we can't see,
        # so we try to skip them.
        #
        for _ in range(10):
            try_next_address(ips, subnets[idx])

    i = 0
    while i < cluster_size:
        idx = i % len(subnets)

        ip = try_next_address(network_ips[idx], subnets[idx])

        resp = ec2.describe_instances(Filters=[{
            'Name': 'private-ip-address',
            'Values': [ip]
        }])
        if not resp['Reservations']:
            i += 1
            yield ip


def allocate_ip_addresses(region_subnets: dict, cluster_size: int, node_ips: dict,
                          take_elastic_ips: bool):
    '''
    Allocate unused private IP addresses by checking the current
    reservations, and optionally allocate Elastic IPs.
    '''
    for region, subnets in region_subnets.items():
        with Action('Allocating IP addresses in {}..'.format(region)) as act:
            ec2 = boto3.client('ec2', region_name=region)

            for ip in generate_private_ip_addresses(ec2, subnets, cluster_size):
                address = {'PrivateIp': ip}

                if take_elastic_ips:
                    resp = ec2.allocate_address(Domain='vpc')
                    address['_defaultIp'] = resp['PublicIp']
                    address['PublicIp'] = resp['PublicIp']
                    address['AllocationId'] = resp['AllocationId']
                else:
                    address['_defaultIp'] = ip

                node_ips[region].append(address)
                act.progress()


def pick_seed_node_ips(node_ips: dict, seed_count: int) -> dict:
    '''
    Take first {seed_count} IPs in every region for the seed nodes.
    '''
    seed_nodes = {}
    for region, ips in node_ips.items():
        seed_nodes[region] = ips[0:seed_count]

        list_ips = [ip['_defaultIp'] for ip in seed_nodes[region]]
        info('Our seed nodes in {} will be: {}'.format(region, ', '.join(list_ips)))
    return seed_nodes


def get_subnets(prefix_filter: str, regions: list) -> dict:
    '''
    Returns a dict of per-region lists of subnets, which names start
    with the specified prefix (it should be either 'dmz-' or
    'internal-'), sorted by the Availability Zone.
    '''
    subnets = collections.defaultdict(list)
    for region in regions:
        ec2 = boto3.client('ec2', region)
        resp = ec2.describe_subnets()

        for subnet in sorted(resp['Subnets'], key=lambda subnet: subnet['AvailabilityZone']):
            for tag in subnet['Tags']:
                if tag['Key'] == 'Name':
                    if tag['Value'].startswith(prefix_filter):
                        subnets[region].append(subnet)
    return subnets


def hostname_from_private_ip(region: str, ip: str) -> str:
    return 'ip-{}.{}.compute.internal.'.format('-'.join(ip.split('.')), region)


def setup_dns_records(cluster_name: str, hosted_zone: str, node_ips: dict):
    r53 = boto3.client('route53')

    zone = None
    zones = r53.list_hosted_zones_by_name(DNSName=hosted_zone)
    for z in zones['HostedZones']:
        if z['Name'] == hosted_zone:
            zone = z
    if not zone:
        raise Exception('Failed to find Hosted Zone {}'.format(hosted_zone))

    for region, ips in node_ips.items():
        with Action('Setting up Route53 SRV records in {}..'.format(region)):
            name = '_{}-{}._tcp.{}'.format(cluster_name, region, hosted_zone)
            #
            # NB: We always want the clients to connect using private
            # IP addresses.
            #
            # But we must record the host names, otherwise the client
            # will get the addresses ending with the dot from the DSN
            # lookup and won't recognize them as such.
            #
            records = [{'Value': '1 1 9042 {}'.format(hostname_from_private_ip(region, ip['PrivateIp']))} for ip in ips]

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
                })


def setup_sns_topics_for_alarm(regions: list, topic_name: str, email: str) -> list:
    if not(topic_name):
        topic_name = 'planb-cassandra-system-event'

    result = {}
    for region in regions:
        sns = boto3.client('sns', region_name=region)
        resp = sns.create_topic(Name=topic_name)
        topic_arn = resp['TopicArn']
        if email:
            sns.subscribe(TopicArn=topic_arn, Protocol='email', Endpoint=email)
        result[region] = topic_arn
    return result


def generate_taupage_user_data(options: dict) -> str:
    '''
    Generate Taupage user data to start a Cassandra node
    http://docs.stups.io/en/latest/components/taupage.html
    '''
    keystore_base64 = base64.b64encode(options['keystore'])
    truststore_base64 = base64.b64encode(options['truststore'])

    docker_image = options.get('docker_image')
    if not docker_image:
        version = get_latest_docker_image_version()
        docker_image = 'registry.opensource.zalan.do/stups/planb-cassandra:{}'.format(version)


    # seed nodes across all regions
    all_seeds = [ip['_defaultIp'] for region, ips in options['seed_nodes'].items() for ip in ips]

    data = {'runtime': 'Docker',
            'source': docker_image,
            'application_id': options['cluster_name'],
            'application_version': "1.0",
            'networking': 'host',
            'ports': {'7001': '7001',
                      '9042': '9042'},
            'environment': {
                'CLUSTER_NAME': options['cluster_name'],
                'CLUSTER_SIZE': options['cluster_size'],
                'REGIONS': ' '.join(options['regions']),
                'SUBNET_TYPE': 'internal' if options['internal'] else 'dmz',
                'SEEDS': ','.join(all_seeds),
                'KEYSTORE': keystore_base64,
                'TRUSTSTORE': truststore_base64,
                'ADMIN_PASSWORD': generate_password()
            },
            'mounts': {
                '/var/lib/cassandra': {
                    'partition': '/dev/xvdf',
                    'options': 'noatime,nodiratime'
                }
            },
            'scalyr_account_key': options['scalyr_key']
    }

    if options['environment']:
        data['environment'].update(options['environment'])

    return data


def launch_instance(region: str, ip: dict, ami: object, subnet_id: str,
                    security_group_id: str, is_seed: bool, options: dict):

    node_type = 'SEED' if is_seed else 'NORMAL'
    with Action('Launching {} node {} in {}..'.format(node_type, ip['_defaultIp'], region)) as act:
        ec2 = boto3.client('ec2', region_name=region)

        #
        # Override any ephemeral volumes with NoDevice mapping,
        # otherwise auto-recovery alarm cannot be actually enabled.
        #
        block_devices = []
        for bd in ami.block_device_mappings:
            if 'Ebs' in bd:
                #
                # This has to be our root EBS.
                #
                # If the Encrypted flag is present, we have to delete
                # it even if it matches the actual snapshot setting,
                # otherwise amazon will complain rather loudly.
                #
                # Take a deep copy before deleting the key:
                #
                bd = copy.deepcopy(bd)

                root_ebs = bd['Ebs']
                if 'Encrypted' in root_ebs:
                    del(root_ebs['Encrypted'])

                block_devices.append(bd)
            else:
                # ignore any ephemeral volumes (aka. instance storage)
                block_devices.append({'DeviceName': bd['DeviceName'],
                                      'NoDevice': ''})

        #
        # Make sure our data EBS volume is persisted, but NOT
        # encrypted: the latter will prevent auto-recovery.
        #
        data_ebs = {'VolumeType': options['volume_type'],
                    'VolumeSize': options['volume_size'],
                    'DeleteOnTermination': False,
                    'Encrypted': False}
        if options['volume_type'] == 'io1':
            data_ebs['Iops'] = options['volume_iops']

        #
        # Now add the data EBS with pre-defined device name (it is
        # referred to in Taupage user data).
        #
        block_devices.append({'DeviceName': '/dev/xvdf', 'Ebs': data_ebs})

        resp = ec2.run_instances(
            ImageId=ami.id,
            MinCount=1,
            MaxCount=1,
            SecurityGroupIds=[security_group_id],
            UserData=options['taupage_user_data'],
            InstanceType=options['instance_type'],
            SubnetId=subnet_id,
            PrivateIpAddress=ip['PrivateIp'],
            BlockDeviceMappings=block_devices,
            DisableApiTermination=not(options['no_termination_protection']))

        instance = resp['Instances'][0]
        instance_id = instance['InstanceId']

        ec2.create_tags(Resources=[instance_id],
                        Tags=[{'Key': 'Name', 'Value': options['cluster_name']}])

        # wait for instance to initialize before we can assign a
        # public IP address to it or tag the attached volume
        while True:
            resp = ec2.describe_instances(InstanceIds=[instance_id])
            instance = resp['Reservations'][0]['Instances'][0]
            if instance['State']['Name'] != 'pending':
                break
            time.sleep(5)
            act.progress()

        if not options['internal']:
            ec2.associate_address(InstanceId=instance_id,
                                  AllocationId=ip['AllocationId'])

        # tag the attached data EBS volume for easier cleanup when testing
        for bd in instance['BlockDeviceMappings']:
            if bd['DeviceName'] == '/dev/xvdf':
                ec2.create_tags(Resources=[bd['Ebs']['VolumeId']],
                                Tags=[{'Key': 'Name', 'Value': options['cluster_name']}])

        # add an auto-recovery alarm for this instance
        cw = boto3.client('cloudwatch', region_name=region)
        alarm_actions = ['arn:aws:automate:{}:ec2:recover'.format(region)]
        if options['alarm_topics']:
            alarm_actions.append(options['alarm_topics'][region])

        cw.put_metric_alarm(AlarmName='{}-{}-auto-recover'.format(options['cluster_name'], instance_id),
                            AlarmActions=alarm_actions,
                            MetricName='StatusCheckFailed_System',
                            Namespace='AWS/EC2',
                            Statistic='Minimum',
                            Dimensions=[{
                                'Name': 'InstanceId',
                                'Value': instance_id
                            }],
                            Period=60,  # 1 minute
                            EvaluationPeriods=2,
                            Threshold=0,
                            ComparisonOperator='GreaterThanThreshold')


def launch_seed_nodes(options: dict):
    total_seed_count = options['seed_count'] * len(options['regions'])
    seeds_launched = 0
    for region, ips in options['seed_nodes'].items():
        subnets = options['subnets'][region]
        for i, ip in enumerate(ips):
            launch_instance(region, ip,
                            ami=options['taupage_amis'][region],
                            subnet_id=subnets[i % len(subnets)]['SubnetId'],
                            security_group_id=options['security_groups'][region]['GroupId'],
                            is_seed=True,
                            options=options)
            seeds_launched += 1
            if seeds_launched < total_seed_count:
                info("Sleeping for a minute before launching next SEED node..")
                time.sleep(60)


def launch_normal_nodes(options: dict):
    # TODO: parallelize by region?
    for region, ips in options['node_ips'].items():
        subnets = options['subnets'][region]
        for i, ip in enumerate(ips):
            if i >= options['seed_count']:
                # avoid stating all nodes at the same time
                info("Sleeping for one minute before launching next node..")
                time.sleep(60)
                launch_instance(region, ip,
                                ami=options['taupage_amis'][region],
                                subnet_id=subnets[i % len(subnets)]['SubnetId'],
                                security_group_id=options['security_groups'][region]['GroupId'],
                                is_seed=False,
                                options=options)


def print_success_message(options: dict):
    info('Cluster initialization completed successfully!')
    sys.stdout.write('''
The Cassandra cluster {cluster_name} was created with {cluster_size} nodes
in each of the following AWS regions: {regions_list}

You can now login to any of the cluster nodes with the superuser
account using the following command:

$ cqlsh -u cassandra -p '{admin_password}'

From there you can create non-superuser roles and otherwise configure
the cluster.

You might also need to update the Security Groups named {cluster_name}
(in all regions!) to allow access to Cassandra from your application (port 9042)
and optionally to allow access to Jolokia (port 8778) and/or
Prometheus Node Exporter (port 9100) from your monitoring tool.
'''.format(**options, regions_list=' '.join(options['regions']),
           admin_password=options['user_data']['environment']['ADMIN_PASSWORD']))


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


@click.command()
@click.option('--cluster-name', help='name of the cluster, required')
@click.option('--cluster-size', default=3, type=int, help='number of nodes per region, default: 3')
@click.option('--instance-type', default='t2.micro', help='default: t2.micro')
@click.option('--volume-type', default='gp2', help='gp2 (default) | io1 | standard')
@click.option('--volume-size', default=8, type=int, help='in GB, default: 8')
@click.option('--volume-iops', default=100, type=int, help='for type io1, default: 100')
@click.option('--no-termination-protection', is_flag=True, default=False)
@click.option('--internal', is_flag=True, default=False, help='deploy into internal subnets using Private IP addresses, to be used with a single region only')
@click.option('--hosted-zone', help='create SRV records in this Hosted Zone')
@click.option('--scalyr-key')
@click.option('--docker-image', help='Docker image to use (default: use latest planb-cassandra)')
@click.option('--sns-topic', help='SNS topic name to send Auto-Recovery notifications to')
@click.option('--sns-email', help='Email address to subscribe to Auto-Recovery SNS topic')
@click.option('--environment', '-e', multiple=True)
@click.argument('regions', nargs=-1)
def cli(cluster_name: str, regions: list, cluster_size: int, instance_type: str,
        volume_type: str, volume_size: int, volume_iops: int,
        no_termination_protection: bool, internal: bool, hosted_zone: str, scalyr_key: str,
        docker_image: str, sns_topic: str, sns_email: str, environment: list):

    if not cluster_name:
        raise click.UsageError('You must specify the cluster name')

    cluster_name_re = '^[a-z][a-z0-9-]*[a-z0-9]$'
    if not re.match(cluster_name_re, cluster_name):
        raise click.UsageError('Cluster name must only contain lowercase latin letters, digits and dashes (it also must start with a letter and cannot end with a dash), in other words it must be matched by the following regular expression: {}'.format(cluster_name_re))

    if not regions:
        raise click.UsageError('Please specify at least one region')

    if internal and len(regions) > 1:
        raise click.UsageError('You can specify only one region when using --internal')

    if internal:
        region = regions[0]

    if environment:
        environment = dict(map(lambda x: x.split("="), environment))

        for k,v in environment.items():
            print("Adding optional env var: {}={}".format(k, v))

    keystore, truststore = generate_certificate(cluster_name)

    # List of IP addresses by region
    node_ips = collections.defaultdict(list)

    # Mapping of region name to the Security Group
    security_groups = {}

    try:
        taupage_amis = find_taupage_amis(regions)

        subnets = get_subnets('internal-' if internal else 'dmz-', regions)

        allocate_ip_addresses(subnets, cluster_size, node_ips,
                              take_elastic_ips=not(internal))

        if sns_topic or sns_email:
            alarm_topics = setup_sns_topics_for_alarm(regions, sns_topic, sns_email)
        else:
            alarm_topics = {}

        if hosted_zone:
            setup_dns_records(cluster_name, hosted_zone, node_ips)

        setup_security_groups(internal, cluster_name, node_ips, security_groups)

        # We should have up to 3 seeds nodes per DC
        seed_count = min(cluster_size, 3)
        seed_nodes = pick_seed_node_ips(node_ips, seed_count)

        user_data = generate_taupage_user_data(locals())
        taupage_user_data = '#taupage-ami-config\n{}'.format(yaml.safe_dump(user_data))

        launch_seed_nodes(locals())

        # TODO: make sure all seed nodes are up
        launch_normal_nodes(locals())

        print_success_message(locals())

    except:
        print_failure_message()

        for region, sg in security_groups.items():
            ec2 = boto3.client('ec2', region)
            info('Cleaning up security group: {}'.format(sg['GroupId']))
            ec2.delete_security_group(GroupId=sg['GroupId'])

        if not internal:
            for region, ips in node_ips.items():
                ec2 = boto3.client('ec2', region)
                for ip in ips:
                    info('Releasing IP address: {}'.format(ip['PublicIp']))
                    ec2.release_address(AllocationId=ip['AllocationId'])

        raise

if __name__ == '__main__':
    cli()
