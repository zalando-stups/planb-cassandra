#!/usr/bin/env python3

import boto3
import click
import collections
import yaml
import requests
from clickclick import Action, info


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
            for ip in ips:
                ip_permissions.append({'IpProtocol': 'tcp',
                                       'FromPort': 7001, # port range: From-To
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


def generate_taupage_user_data(cluster_name: str, seed_nodes: list):
    '''
    Generate Taupage user data to start a Cassandra node
    http://docs.stups.io/en/latest/components/taupage.html
    '''
    keystore_base64 = ''
    truststore_base64 = ''
    version = get_latest_docker_image_version()
    data = {'runtime': 'Docker',
            'source': 'registry.opensource.zalan.do/stups/planb-cassandra:{}'.format(version),
            'application_id': cluster_name,
            'application_version': '1.0',
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


def allocate_public_ips(regions: list, cluster_size: int, public_ips: dict):
    # reservice Elastic IPs
    for region in regions:
        with Action('Allocating Public IPs for {}..'.format(region)) as act:
            ec2 = boto3.client('ec2', region_name=region)
            for i in range(cluster_size):
                resp = ec2.allocate_address(Domain='vpc')
                public_ips[region].append(resp)
                act.progress()


def launch_instance(region: str, ip: str, instance_type: str, ami: str, user_data: str,
                    security_group_id: str):

    with Action('Launching node {}..'.format(ip)):
        ec2 = boto3.client('ec2', region_name=region)

        resp = ec2.describe_subnets()
        # subnet IDs sorted by AZ
        subnets = list([subnet['SubnetId'] for subnet in sorted(resp['Subnets'], key=lambda subnet: subnet['AvailabilityZone'])])

        # start seed node in first AZ
        ec2.run_instances(ImageId=ami.id, MinCount=1, MaxCount=1,
                SecurityGroupIds=[security_group_id],
                UserData=user_data, InstanceType=instance_type,
                SubnetId=subnets[0])


@click.command()
@click.option('--cluster-size', default=3, type=int)
@click.option('--instance-type', default='t2.micro')
@click.argument('cluster_name')
@click.argument('regions', nargs=-1)
def cli(cluster_name: str, regions: list, cluster_size: int, instance_type: str):
    if not regions:
        raise click.UsageError('Please specify at least one region')

    # generate keystore/truststore

    # Elastic IPs by region
    public_ips = collections.defaultdict(list)
    security_groups = {}
    try:
        allocate_public_ips(regions, cluster_size, public_ips)

        # take first IP in every region as seed node
        # TODO: support more than one seed node per region for larger clusters
        seed_nodes = { region: ips[0]['PublicIp'] for region, ips in public_ips.items() }
        info('Our seed nodes are: {}'.format(', '.join(seed_nodes.values())))

        # Set up Security Groups
        setup_security_groups(cluster_name, public_ips, security_groups)

        taupage_amis = find_taupage_amis(regions)
        user_data = generate_taupage_user_data(cluster_name, seed_nodes)

        # Launch EC2 instances with correct user data
        # Launch sequence:
        # start seed nodes (e.g. 1 per region if cluster_size == 3)
        for region, ip in seed_nodes.items():
            launch_instance(region, ip, instance_type=instance_type,
                            ami=taupage_amis[region], user_data=user_data,
                            security_group_id=security_groups[region]['GroupId'])

        # make sure all seed nodes are up
        # add remaining nodes one by one

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
