#!/usr/bin/env python3

import boto3
import click
import collections
from clickclick import Action


@click.command()
@click.option('--cluster-size', default=3, type=int)
@click.argument('regions', nargs=-1)
def cli(regions, cluster_size):
    if not regions:
        raise click.UsageError('Please specify at least one region')

    # generate keystore/truststore

    # Elastic IPs by region
    public_ips = collections.defaultdict(list)

    # reservice Elastic IPs
    for region in regions:
        with Action('Allocating Public IPs for {}..'.format(region)) as act:
            ec2 = boto3.client('ec2', region_name=region)
            for i in range(cluster_size):
                resp = ec2.allocate_address(Domain='vpc')
                public_ips[region].append(resp['PublicIp'])
                act.progress()

    # Now we have all necessary Public IPs

    # Launch EC2 instances with correct user data

if __name__ == '__main__':
    cli()
