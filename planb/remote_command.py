import click
import subprocess

from .common import boto_client, list_instances


def quoted(command: str) -> str:
    return '"{}"'.format(
        command.replace("\\", "\\\\").replace("\"", "\\\"").replace("$", "\\$")
    )


def run_on_instance(
        instance: dict, command: list, cluster_name: str, odd_host: str,
        piu: str, echo: bool, no_prompt: bool, no_wait: bool, ip_label: bool):

    ip = instance['PrivateIpAddress']
    if piu:
        piu_cmd = ['piu', 'request-access', '--odd-host', odd_host, ip, piu]
        subprocess.check_call(piu_cmd)

    outer_ssh_cmd = 'ssh -o StrictHostKeyChecking=no -J odd@{} ubuntu@{} {}'.format(
        odd_host,
        ip,
        quoted(' '.join(command))
    )
    if echo:
        print("-"*len(outer_ssh_cmd))
        print(outer_ssh_cmd)

    if ip_label:
        sh_cmd = '{} | grep --label {} -H .'.format(outer_ssh_cmd, ip)
        cmd = ['sh', '-c', sh_cmd]
    else:
        cmd = ['sh', '-c', outer_ssh_cmd]

    # TODO: check istty
    q = "Run on node {} with IP {}?".format(instance['Tags']['Name'], ip)
    if no_prompt or click.confirm(q):
        if no_wait:
            subprocess.Popen(cmd, stdin=subprocess.DEVNULL)
        else:
            subprocess.call(cmd)


def run_shell(
        command: list, cluster_name: str, region: str, filters: list, **kwargs):

    ec2 = boto_client('ec2', region)
    instances = list_instances(ec2, cluster_name, filters)
    if not instances:
        msg = "No running instances found in region {} with Name tag '{}'".format(
            region,
            cluster_name
        )
        click.echo(msg, err=True)
    else:
        for i in instances:
            run_on_instance(i, command, cluster_name, **kwargs)


def run_nodetool(command: list=[], **kwargs):
    nodetool_cmd = ['docker', 'exec', 'taupageapp', 'nodetool']
    run_shell(nodetool_cmd + list(command), **kwargs)


def run_cqlsh(command: list=[], **kwargs):
    cql_cmd = ' '.join(command)
    cqlsh_cmd = 'cqlsh -u admin -p $ADMIN_PASSWORD -e {}'.format(quoted(cql_cmd))
    docker_cmd = ['docker', 'exec', 'taupageapp', 'sh', '-c', quoted(cqlsh_cmd)]
    run_shell(docker_cmd, **kwargs)
