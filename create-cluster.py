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
from clickclick import Action, info
from subprocess import check_call, call
import tempfile
import os
import sys
import copy


def setup_security_groups(cluster_name: str, public_ips: dict, result: dict) -> dict:
    '''
    Allow traffic between regions

    Returns a dict of region -> security group ID
    '''
    for region, ips in public_ips.items():
        with Action('Configuring security group in {}..'.format(region)):
            ec2 = boto3.client('ec2', region)
            resp = ec2.describe_vpcs()
            # TODO: support more than one VPC..
            vpc_id = resp['Vpcs'][0]['VpcId']
            sg_name = cluster_name
            sg = ec2.create_security_group(GroupName=sg_name,
                                           VpcId=vpc_id,
                                           Description='Allow cassandra nodes to talk via port 7001')
            result[region] = sg

            ec2.create_tags(Resources=[sg['GroupId']],
                            Tags=[{'Key': 'Name', 'Value': sg_name}])
            ip_permissions = []
            # NOTE: we need to allow ALL public IPs (from all regions)
            for ip in itertools.chain(*public_ips.values()):
                ip_permissions.append({'IpProtocol': 'tcp',
                                       'FromPort': 7001,  # port range: From-To
                                       'ToPort': 7001,
                                       'IpRanges': [{'CidrIp': '{}/32'.format(ip['PublicIp'])}]})
            ip_permissions.append({'IpProtocol': '-1',
                                   'UserIdGroupPairs': [{'GroupId': sg['GroupId']}]})

            # if we can find the Odd security group, authorize SSH access from it
            try:
                resp = ec2.describe_security_groups(GroupNames=['Odd (SSH Bastion Host)'])
                odd_sg = resp['SecurityGroups'][0]

                ip_permissions.append({'IpProtocol': 'tcp',
                                       'FromPort': 22,  # port range: From-To
                                       'ToPort': 22,
                                       'UserIdGroupPairs': [{'GroupId': odd_sg['GroupId']}]})
            except ClientError:
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


def allocate_public_ips(regions: list, cluster_size: int, public_ips: dict):
    # reservice Elastic IPs
    for region in regions:
        with Action('Allocating Public IPs for {}..'.format(region)) as act:
            ec2 = boto3.client('ec2', region_name=region)
            for i in range(cluster_size):
                resp = ec2.allocate_address(Domain='vpc')
                public_ips[region].append(resp)
                act.progress()


def get_dmz_subnets(regions: list) -> dict:
    '''
    Returns a dict of lists of DMZ subnets sorted by AZ.
    '''
    subnets = collections.defaultdict(list)
    for region in regions:
        ec2 = boto3.client('ec2', region)
        resp = ec2.describe_subnets()

        for subnet in sorted(resp['Subnets'], key=lambda subnet: subnet['AvailabilityZone']):
            for tag in subnet['Tags']:
                if tag['Key'] == 'Name':
                    if tag['Value'].startswith('dmz-'):
                        subnets[region].append(subnet['SubnetId'])
    return subnets


@click.command()
@click.option('--cluster-size', default=3, type=int, help='number of nodes per region, default: 3')
@click.option('--instance-type', default='t2.micro', help='default: t2.micro')
@click.option('--volume-type', default='gp2', help='gp2 (default) | io1 | standard')
@click.option('--volume-size', default=8, type=int, help='in GB, default: 8')
@click.option('--volume-iops', default=100, type=int, help='for type io1, default: 100')
@click.option('--no-termination-protection', is_flag=True, default=False)
@click.option('--scalyr-key')
@click.argument('cluster_name')
@click.argument('regions', nargs=-1)
def cli(cluster_name: str, regions: list, cluster_size: int, instance_type: str,
        volume_type: str, volume_size: int, volume_iops: int,
        no_termination_protection: bool, scalyr_key: str):
    if not regions:
        raise click.UsageError('Please specify at least one region')

    # generate keystore/truststore
    keystore, truststore = generate_certificate(cluster_name)

    # Elastic IPs by region
    public_ips = collections.defaultdict(list)
    security_groups = {}
    try:
        allocate_public_ips(regions, cluster_size, public_ips)

        # We should have up to 3 seeds nodes per DC
        seed_count = min(cluster_size, 3)

        # take first {seed_count} IPs in every region for the seed nodes
        seed_nodes = {}
        for region, ips in public_ips.items():
            seed_nodes[region] = ips[0:seed_count]
            list_ips = [ip['PublicIp'] for ip in seed_nodes[region]]
            info('Our seed nodes in {} are: {}'.format(region, ', '.join(list_ips)))

        # Set up Security Groups
        setup_security_groups(cluster_name, public_ips, security_groups)

        taupage_amis = find_taupage_amis(regions)

        def generate_taupage_user_data() -> str:
            '''
            Generate Taupage user data to start a Cassandra node
            http://docs.stups.io/en/latest/components/taupage.html
            '''
            keystore_base64 = base64.b64encode(keystore)
            truststore_base64 = base64.b64encode(truststore)
            version = get_latest_docker_image_version()
            all_seeds = [ip['PublicIp'] for region, ips in seed_nodes.items() for ip in ips]
            data = {'runtime': 'Docker',
                    'source': 'registry.opensource.zalan.do/stups/planb-cassandra:{}'.format(version),
                    'application_id': cluster_name,
                    'application_version': '1.0',
                    'networking': 'host',
                    'ports': {'7001': '7001',
                              '9042': '9042'},
                    'environment': {
                        'CLUSTER_NAME': cluster_name,
                        'CLUSTER_SIZE': cluster_size,
                        'REGIONS': ' '.join(regions),
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
                    'scalyr_account_key': scalyr_key
            }
            # TODO: add KMS-encrypted keystore/truststore

            return data

        user_data = generate_taupage_user_data()
        taupage_user_data = '#taupage-ami-config\n{}'.format(yaml.safe_dump(user_data))

        # Launch EC2 instances with correct user data
        subnets = get_dmz_subnets(regions)

        def launch_instance(region: str, ip: dict, ami: object, subnet_id: str,
                            security_group_id: str, node_type: str):

            with Action('Launching {} node {} in {}..'.format(node_type, ip['PublicIp'], region)) as act:
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

                # make sure our data EBS volume is persisted and encrypted
                data_ebs = {'VolumeType': volume_type,
                            'VolumeSize': volume_size,
                            'DeleteOnTermination': False,
                            'Encrypted': True}
                if volume_type == 'io1':
                    data_ebs['Iops'] = volume_iops

                #
                # Now add the data EBS with pre-defined device name (it is
                # referred to in Taupage user data).
                #
                block_devices.append({'DeviceName': '/dev/xvdf', 'Ebs': data_ebs})

                resp = ec2.run_instances(ImageId=ami.id,
                                         MinCount=1,
                                         MaxCount=1,
                                         SecurityGroupIds=[security_group_id],
                                         UserData=taupage_user_data,
                                         InstanceType=instance_type,
                                         SubnetId=subnet_id,
                                         BlockDeviceMappings=block_devices,
                                         DisableApiTermination=not(no_termination_protection))

                instance = resp['Instances'][0]
                instance_id = instance['InstanceId']

                ec2.create_tags(Resources=[instance_id],
                                Tags=[{'Key': 'Name', 'Value': cluster_name}])

                # wait for instance to initialize before we can assign an IP address to it
                while True:
                    resp = ec2.describe_instances(InstanceIds=[instance_id])
                    instance = resp['Reservations'][0]['Instances'][0]
                    if instance['State']['Name'] != 'pending':
                        break
                    time.sleep(5)
                    act.progress()

                ec2.associate_address(InstanceId=instance_id,
                                      AllocationId=ip['AllocationId'])

                # tag the attached data EBS volume for easier cleanup when testing
                for bd in instance['BlockDeviceMappings']:
                    if bd['DeviceName'] == '/dev/xvdf':
                        ec2.create_tags(Resources=[bd['Ebs']['VolumeId']],
                                        Tags=[{'Key': 'Name', 'Value': cluster_name}])

                # add an auto-recovery alarm for this instance
                cw = boto3.client('cloudwatch', region_name=region)
                cw.put_metric_alarm(AlarmName='{}-{}-auto-recover'.format(cluster_name, instance_id),
                                    AlarmActions=['arn:aws:automate:{}:ec2:recover'.format(region)],
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

        # Launch sequence:
        # start all the seed nodes
        total_seed_count = seed_count * len(regions)
        seeds_launched = 0
        for region, ips in seed_nodes.items():
            region_subnets = subnets[region]
            for i, ip in enumerate(ips):
                launch_instance(region, ip,
                                ami=taupage_amis[region],
                                subnet_id=region_subnets[i % len(region_subnets)],
                                security_group_id=security_groups[region]['GroupId'],
                                node_type='SEED')
                seeds_launched += 1
                if seeds_launched < total_seed_count:
                    info("Sleeping for a minute before launching next SEED node..")
                    time.sleep(60)

        # TODO: make sure all seed nodes are up

        # add remaining nodes one by one
        # TODO: parallelize by region?
        for region, ips in public_ips.items():
            region_subnets = subnets[region]
            for i, ip in enumerate(ips):
                if i >= seed_count:
                    # avoid stating all nodes at the same time
                    info("Sleeping for one minute before launching next node..")
                    time.sleep(60)
                    launch_instance(region, ip,
                                    ami=taupage_amis[region],
                                    subnet_id=region_subnets[i % len(region_subnets)],
                                    security_group_id=security_groups[region]['GroupId'],
                                    node_type='NORMAL')

        info('Cluster initialization completed successfully!')
        sys.stdout.write('''
The Cassandra cluster {cluster_name} was created with {cluster_size} nodes
in each of the following AWS regions: {regions}

You can now login to any of the cluster nodes with the superuser
account using the following command:

  $ cqlsh -u cassandra -p '{admin_password}'

From there you can create non-superuser roles and otherwise configure
the cluster.

You might also need to update the Security Groups named {cluster_name}
(in all regions!) to allow access to Cassandra from your application (port 9042)
and optionally to allow access to Jolokia (port 8778) and/or
Prometheus Node Exporter (port 9100) from your monitoring tool.
'''.format(cluster_size=cluster_size, cluster_name=cluster_name, regions=' '.join(regions),
           admin_password=user_data['environment']['ADMIN_PASSWORD']))

    except:
        for region, sg in security_groups.items():
            ec2 = boto3.client('ec2', region)
            info('Cleaning up security group: {}'.format(sg['GroupId']))
            ec2.delete_security_group(GroupId=sg['GroupId'])

        for region, ips in public_ips.items():
            ec2 = boto3.client('ec2', region)
            for ip in ips:
                info('Releasing IP address: {}'.format(ip['PublicIp']))
                ec2.release_address(AllocationId=ip['AllocationId'])

        raise

if __name__ == '__main__':
    cli()
