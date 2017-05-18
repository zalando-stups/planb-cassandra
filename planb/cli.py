import re
import click
import logging

from .common import ec2_client, list_instances
from .show_cluster import show_instances
from .create_cluster import create_cluster
from .update_cluster import update_cluster


def configure_logging(level):
    logging.basicConfig(level=logging.WARN, format='%(asctime)s %(levelname)s: %(message)s')
    logging.getLogger("planb").setLevel(level)
    logging.getLogger('urllib3.connectionpool').setLevel(logging.WARN)
    logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(logging.WARN)


@click.group()
@click.option('--debug', is_flag=True, default=False)
def cli(debug: bool):
    configure_logging(logging.DEBUG if debug else logging.INFO)


@cli.command()
@click.argument('regions', nargs=-1)
@click.option('--cluster-name', help='name of the cluster, required')
@click.option('--cluster-size', default=3, type=int, help='number of nodes per region, default: 3')
@click.option('--num-tokens', default=256, type=int, help='number of virtual nodes per node, default: 256')
@click.option('--instance-type', default='t2.medium', help='default: t2.medium')
@click.option('--volume-type', default='gp2', help='gp2 (default) | io1 | standard')
@click.option('--volume-size', default=16, type=int, help='in GB, default: 16')
@click.option('--volume-iops', default=100, type=int, help='for type io1, default: 100')
@click.option('--no-termination-protection', is_flag=True, default=False)
@click.option('--use-dmz', is_flag=True, default=False, help='deploy into DMZ subnets using Public IP addresses')
@click.option('--hosted-zone', help='create SRV records in this Hosted Zone')
@click.option('--scalyr-key')
@click.option('--artifact-name', help='Pierone artifact name to use (default: planb-cassandra-3.0)')
@click.option('--docker-image', help='Docker image to use (default: latest planb-cassandra-3.0)')
@click.option('--environment', '-e', multiple=True)
@click.option('--sns-topic', help='SNS topic name to send Auto-Recovery notifications to')
@click.option('--sns-email', help='Email address to subscribe to Auto-Recovery SNS topic')
def create(regions: list,
           cluster_name: str,
           cluster_size: int,
           num_tokens: int,
           instance_type: str,
           volume_type: str,
           volume_size: int,
           volume_iops: int,
           no_termination_protection: bool,
           use_dmz: bool,
           hosted_zone: str,
           scalyr_key: str,
           artifact_name: str,
           docker_image: str,
           environment: list,
           sns_topic: str,
           sns_email: str):

    if not cluster_name:
        raise click.UsageError('You must specify the cluster name')

    #
    # NB: we use cluster_name as the password for generating
    # key/truststore, that requires it to be at least 6 chars long.
    #
    cluster_name_re = '^[a-z][a-z0-9-]{4,}[a-z0-9]$'
    if not re.match(cluster_name_re, cluster_name):
        raise click.UsageError('Cluster name must be at least 6 characters long, it may only contain lowercase latin letters, digits and dashes (it also must start with a letter and cannot end with a dash), in other words it must be matched by the following regular expression: {}'.format(cluster_name_re))

    if not regions:
        raise click.UsageError('Please specify at least one region')

    if len(regions) > 1 and not(use_dmz):
        raise click.UsageError('You must specify --use-dmz when deploying multi-region.')

    create_cluster(options=locals())


@cli.command()
@click.option('--cluster-name', type=str, required=True)
@click.option('--odd-host', '-O', type=str, required=True)
@click.option('--region', type=str, required=True)
@click.option('--force-termination', is_flag=True, default=False)
@click.option('--docker-image', type=str)
@click.option('--taupage-ami-id', type=str)
def update(cluster_name: str,
           odd_host: str,
           region: str,
           force_termination: bool,
           docker_image: str,
           taupage_ami_id: str):

    if not(docker_image or taupage_ami_id):
        raise click.UsageError("Please specify at least one of --docker-image or --taupage-ami-id")

    update_cluster(options=locals())


@cli.command()
@click.option('--cluster-name', type=str, required=True)
@click.option('--region', type=str)
def nodes(region: str, cluster_name: str):
    # TODO: we should extend it to list of regions
    # TODO: we could derive the regions a cluster is deployed to from SRV DNS record
    ec2 = ec2_client(region)
    instances = list_instances(ec2, cluster_name)
    show_instances(instances)
