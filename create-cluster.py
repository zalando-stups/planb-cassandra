#!/usr/bin/env python3

import itertools
import time
import base64
import boto3
import click
import collections
import yaml
import requests
from clickclick import Action, info
from subprocess import check_call, call
import tempfile
import os


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
            sg = ec2.create_security_group(GroupName=sg_name, VpcId=vpc_id,
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
    return requests.get('https://registry.opensource.zalan.do/teams/stups/artifacts/planb-cassandra/tags').json()[-1]['name']


def generate_taupage_user_data(cluster_name: str, seed_nodes: list, keystore, truststore):
    '''
    Generate Taupage user data to start a Cassandra node
    http://docs.stups.io/en/latest/components/taupage.html
    '''
    keystore_base64 = base64.b64encode(keystore)
    truststore_base64 = base64.b64encode(truststore)
    version = get_latest_docker_image_version()
    data = {'runtime': 'Docker',
            'source': 'registry.opensource.zalan.do/stups/planb-cassandra:{}'.format(version),
            'application_id': cluster_name,
            'application_version': '1.0',
            'networking': 'host',
            'ports': {'7001': '7001',
                '9042': '9042'},
            'environment': {
                'CLUSTER_NAME': cluster_name,
                'SEEDS': ','.join(seed_nodes),
                'KEYSTORE': keystore_base64,
                'TRUSTSTORE': truststore_base64,
                }
            }
    # TODO: add KMS-encrypted keystore/truststore

    serialized = yaml.safe_dump(data)
    user_data = '#taupage-ami-config\n{}'.format(serialized)
    return user_data


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


def launch_instance(cluster_name: str, region: str, ip: str, instance_type: str,
                    ami: str, user_data: str, security_group_id: str):

    with Action('Launching node {} in {}..'.format(ip['PublicIp'], region)) as act:
        ec2 = boto3.client('ec2', region_name=region)

        resp = ec2.describe_subnets()
        # subnet IDs sorted by AZ
        subnets = list([subnet['SubnetId'] for subnet in sorted(resp['Subnets'], key=lambda subnet: subnet['AvailabilityZone'])])

        # start seed node in first AZ
        resp = ec2.run_instances(ImageId=ami.id, MinCount=1, MaxCount=1,
                SecurityGroupIds=[security_group_id],
                UserData=user_data, InstanceType=instance_type,
                SubnetId=subnets[0])

        instance_id = resp['Instances'][0]['InstanceId']

        ec2.create_tags(Resources=[instance_id],
                        Tags=[{'Key': 'Name', 'Value': cluster_name}])

        # wait for instance to initialize before we can assign an IP address to it
        while True:
            resp = ec2.describe_instances(InstanceIds=[instance_id])
            if resp['Reservations'][0]['Instances'][0]['State']['Name'] != 'pending':
                break
            time.sleep(5)
            act.progress()

        ec2.associate_address(InstanceId=instance_id, AllocationId=ip['AllocationId'])


@click.command()
@click.option('--cluster-size', default=3, type=int)
@click.option('--instance-type', default='t2.micro')
@click.argument('cluster_name')
@click.argument('regions', nargs=-1)
def cli(cluster_name: str, regions: list, cluster_size: int, instance_type: str):
    if not regions:
        raise click.UsageError('Please specify at least one region')

    # generate keystore/truststore
    keystore, truststore = generate_certificate(cluster_name)

    # Elastic IPs by region
    public_ips = collections.defaultdict(list)
    security_groups = {}
    try:
        allocate_public_ips(regions, cluster_size, public_ips)

        # take first IP in every region as seed node
        # TODO: support more than one seed node per region for larger clusters
        seed_nodes = {region: ips[0] for region, ips in public_ips.items()}
        seed_node_ips = list([ip['PublicIp'] for ip in seed_nodes.values()])
        info('Our seed nodes are: {}'.format(', '.join(seed_node_ips)))

        # Set up Security Groups
        setup_security_groups(cluster_name, public_ips, security_groups)

        taupage_amis = find_taupage_amis(regions)
        user_data = generate_taupage_user_data(cluster_name, seed_node_ips, keystore, truststore)

        # Launch EC2 instances with correct user data
        # Launch sequence:
        # start seed nodes (e.g. 1 per region if cluster_size == 3)
        for region, ip in seed_nodes.items():
            launch_instance(cluster_name, region, ip, instance_type=instance_type,
                            ami=taupage_amis[region], user_data=user_data,
                            security_group_id=security_groups[region]['GroupId'])

        # TODO: make sure all seed nodes are up

        # add remaining nodes one by one
        # TODO: parallelize by region?
        for region, ips in public_ips.items():
            for ip in ips:
                if ip['PublicIp'] not in seed_node_ips:
                    # avoid stating all nodes at the same time
                    info("Sleeping for 30s before launching next instance..")
                    time.sleep(30)
                    launch_instance(cluster_name, region, ip, instance_type=instance_type,
                                    ami=taupage_amis[region], user_data=user_data,
                                    security_group_id=security_groups[region]['GroupId'])

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
