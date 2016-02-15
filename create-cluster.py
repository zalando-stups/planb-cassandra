#!/usr/bin/env python3

import boto3
import click

@click.command()
@click.option('--cluster-size', default=3, type=int)
@click.argument('regions', nargs=-1)
def cli(regions, cluster_size):
    if not regions:
        raise click.UsageError('Please specify at least one region')

    # generate keystore/truststore
    # reservice Elastic IPs
    for region in regions:
        ec2 = boto3.client('ec2', region_name=region)
        resp = ec2.allocate_address(DryRun=True, Domain='vpc')

    # Launch EC2 instances with correct user data

if __name__ == '__main__':
    cli()
