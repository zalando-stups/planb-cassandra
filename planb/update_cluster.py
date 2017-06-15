# update_cluster
from datetime import datetime
import subprocess
import requests
import logging
import base64
import click
import yaml
import time
import sys
import re
import io
import os

# TODO: can we avoid the explicit list here?
from .common import ec2_client, \
    dump_dict_as_file, load_dict_from_file, \
    dump_user_data_for_taupage, list_instances, \
    override_ephemeral_block_devices, \
    setup_sns_topics_for_alarm, create_auto_recovery_alarm, \
    create_instance_profile, get_instance_profile


"""
We implement a finite state automate. State is stored in the tags of a AWS
resource (like volume or instance). We have to read the instance data from AWS
in every state transition to make sure we have the most recent data.
"""

logger = logging.getLogger(__name__)

# TODO: may be this port is occupied?
local_jolokia_port = 8778
remote_jolokia_port = 8778
jolokia_url = "http://localhost:{}/jolokia/".format(local_jolokia_port)


class ClusterUnhealthyException(Exception):
    pass


def text_timestamp():
    return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')


def select_keys(d: dict, keys: list):
    return {k: v for k, v in d.items() if k in keys}


def create_tags(ec2: object, resource_id: str, tags: dict):
    # TODO: make sure this is retried on throttling/ratelimit error
    ec2.create_tags(
        Resources=[resource_id],
        Tags=[{'Key': k, 'Value': v}
              for k, v in tags.items()]
    )


def tags_as_dict(tags: list) -> dict:
    return {t['Key']: t['Value'] for t in tags}


def update_tags(ec2: object, resource_id: str, tags: dict):
    create_tags(
        ec2, resource_id,
        dict(tags, **{'planb:operation:last-modified': text_timestamp()})
    )


def set_state(ec2: object, volume: dict, state: str):
    update_tags(ec2, volume['VolumeId'], {'planb:operation:state': state})


def set_error_state(ec2: object, volume: dict, message: str):
    update_tags(
        ec2, volume['VolumeId'],
        {'planb:operation:state': 'failed', 'planb:update:fail-reason': message}
    )


def get_instance(ec2: object, instance_id: str) -> dict:
    resp = ec2.describe_instances(InstanceIds=[instance_id])
    reservations = resp['Reservations']
    if len(reservations) != 1:
        logger.error("Unexpected number of reservations for {}: {} != 1"
                     .format(instance_id, len(reservations)))
        return None
    return reservations[0]['Instances'][0]


def get_volume(ec2: object, volume_id: str) -> dict:
    resp = ec2.describe_volumes(VolumeIds=[volume_id])
    return resp['Volumes'][0]


def tag_instance_volume(
        ec2: object, volume: dict, tags: dict, instance: dict,
        cluster_name: str):
    new_tags = {
        'planb:operation': 'update',
        'planb:operation:start-time': text_timestamp(),
        'planb:operation:state': 'init'
    }

    desired_name_tag = "{}-{}".format(cluster_name, instance['PrivateIpAddress'])
    if tags.get('Name') != desired_name_tag:
        new_tags['Name'] = desired_name_tag

    create_tags(ec2, volume['VolumeId'], new_tags)


def find_data_volume_id(ec2: object, instance: dict) -> dict:
    v = [m
         for m in instance['BlockDeviceMappings']
         if re.match("^/dev/(xv|s)df$", m['DeviceName'])]
    return v[0]['Ebs']['VolumeId']


def find_instance_from_volume(
        ec2: object, volume: dict, log_missing_attachment=True) -> dict:

    attachments = volume['Attachments']
    if len(attachments) != 1:
        if len(attachments) > 1 or (not(attachments) and log_missing_attachment):
            logger.error("Unexpected number of attachments for {}: {} != 1"
                         .format(volume['VolumeId'], len(attachments)))
        return None
    instance_id = attachments[0]['InstanceId']
    return get_instance(ec2, instance_id)


def get_user_data(ec2: object, instance_id: str) -> dict:
    resp = ec2.describe_instance_attribute(
        InstanceId=instance_id,
        Attribute='userData'
    )
    raw_bytes = base64.b64decode(resp['UserData']['Value'])
    data = str(raw_bytes, 'UTF-8')
    stream = io.StringIO(data)
    return yaml.safe_load(stream)


def is_api_termination_disabled(ec2: object, instance_id: str) -> dict:
    resp = ec2.describe_instance_attribute(
        InstanceId=instance_id,
        Attribute='disableApiTermination'
    )
    return resp['DisableApiTermination']['Value']


def instance_filename(volume: dict):
    return "{}.json".format(volume['VolumeId'])


def list_instance_dump_files() -> list:
    return [x
            for x in os.listdir()
            if re.match('^vol-\w+\.json$', x)]


def get_cluster_status() -> dict:
    try:
        queries = [{
            'mbean': 'org.apache.cassandra.net:type=FailureDetector',
            'type': 'read'
        }]
        response = requests.post(jolokia_url, json=queries).json()
        if len(response) == 1:
            return response[0].get('value', {})
        return {}
    except requests.exceptions.ConnectionError:
        return {}


def prepare_update(ec2: object, volume: dict, options: dict):
    if get_cluster_status().get('DownEndpointCount') != 0:
        raise ClusterUnhealthyException()

    instance = find_instance_from_volume(ec2, volume)
    if not instance:
        set_error_state(
            ec2, volume,
            "Cannot find instance for {}".format(volume['VolumeId'])
        )
        return

    instance_id = instance['InstanceId']
    disable_api_termination = is_api_termination_disabled(ec2, instance_id)

    instance_dump_file = instance_filename(volume)
    if not os.path.exists(instance_dump_file):
        instance_to_dump = dict(
            instance,
            UserData=get_user_data(ec2, instance_id),
            DisableApiTermination=disable_api_termination
        )
        dump_dict_as_file(instance_to_dump, instance_dump_file)

    if disable_api_termination:
        if options['force_termination']:
            ec2.modify_instance_attribute(
                InstanceId=instance_id,
                DisableApiTermination={'Value': False}
            )
        else:
            logger.info("Instance termination is disabled.")
            set_error_state(ec2, volume, "API termination is disabled")
            return

    set_state(ec2, volume, 'prepared')


def drain_cassandra():
    # TODO: what about timeout?
    requests.post(
        jolokia_url,
        json=[{
            'mbean': 'org.apache.cassandra.db:type=StorageService',
            'type': 'exec',
            'operation': 'drain'
        }]
    )


def drain_node(ec2: object, volume: dict, saved_instance: dict):
    logger.info("Draining node {}".format(saved_instance['PrivateIpAddress']))
    drain_cassandra()
    set_state(ec2, volume, 'drained')


def terminate_instance(ec2: object, volume: dict, saved_instance: dict):
    instance_id = saved_instance['InstanceId']
    instance = get_instance(ec2, instance_id)
    if not instance:
        set_error_state(ec2, volume, "Instance {} not found".format(instance_id))
        return
    state = instance['State']['Name']
    if state == 'running':
        logger.info("Terminating instance {}".format(instance_id))
        ec2.terminate_instances(InstanceIds=[instance_id])
    elif state == 'shutting-down':
        logger.info("Instance {} is still shutting down".format(instance_id))
    elif state == 'terminated':
        set_state(ec2, volume, 'terminated')
    else:
        raise Exception("Unexpected state of {}: {}".format(instance_id, state))


def build_run_instances_params(
        ec2: object, volume: dict, saved_instance: dict, options: dict) -> dict:

    inherited_keys = [
        'ImageId',
        'InstanceType',
        'SubnetId',
        'PrivateIpAddress',
        'UserData',
        'DisableApiTermination'
    ]
    params = select_keys(saved_instance, inherited_keys)

    if 'IamInstanceProfile' in saved_instance:
        profile = saved_instance['IamInstanceProfile']
    else:
        profile = get_instance_profile(options['cluster_name'])
        if profile is None:
            profile = create_instance_profile(options['cluster_name'])

    instance_profile = {'Arn': profile['Arn']}
    params = dict(
        params,
        MinCount=1,
        MaxCount=1,
        SecurityGroupIds=[sg['GroupId']
                          for sg in saved_instance['SecurityGroups']],
        IamInstanceProfile=instance_profile
    )

    options_to_api = {'taupage_ami_id': 'ImageId'}
    instance_changes = {
        v: options[k]
        for k, v in options_to_api.items()
        if options[k]
    }
    params = dict(params, **instance_changes)

    image = ec2.describe_images(ImageIds=[params['ImageId']])['Images'][0]
    mappings = override_ephemeral_block_devices(image['BlockDeviceMappings'])
    params['BlockDeviceMappings'] = mappings

    user_data_changes = {
        'volumes': {
            'ebs': {
                '/dev/xvdf': "{}-{}".format(options['cluster_name'],
                                            saved_instance['PrivateIpAddress'])
            }
        }
    }
    docker_image = options.get('docker_image')
    if docker_image:
        user_data_changes['source'] = docker_image
    params['UserData'].update(user_data_changes)
    return params


def create_instance(ec2: object, volume: dict, saved_instance: dict,
                    options: dict):
    params = build_run_instances_params(ec2, volume, saved_instance, options)
    params['UserData'] = dump_user_data_for_taupage(params['UserData'])

    logger.info(
        "Creating new instance with IP {}".format(params['PrivateIpAddress'])
    )
    ec2.run_instances(**params)
    set_state(ec2, volume, 'created')


def configure_instance(ec2: object, volume: dict, saved_instance: dict,
                       options: dict):
    instance = find_instance_from_volume(ec2, volume,
                                         log_missing_attachment=False)
    if not instance:
        logger.info(
            "Waiting for new instance to attach {}".format(volume['VolumeId'])
        )
        return

    instance_id = instance['InstanceId']
    create_tags(ec2, instance_id, {
        t['Key']:t['Value'] 
        for t in saved_instance['Tags']
    })

    region = options['region']
    alarm_sns_topic_arn = None
    if options['alarm_topics']:
        alarm_sns_topic_arn = options['alarm_topics'][region]

    create_auto_recovery_alarm(
        region,
        options['cluster_name'],
        instance_id,
        alarm_sns_topic_arn
    )

    # TODO: we should have another transition to wait for Cassandra to
    # jump to Normal, before declaring it complete
    set_state(ec2, volume, 'configured')


def check_node_status(ec2: object, volume: dict):
    down_count = get_cluster_status().get('DownEndpointCount')
    logger.info("DownEndpointCount: {}".format(down_count))
    if down_count == 0:
        set_state(ec2, volume, 'completed')


def cleanup_state(ec2: object, volume: dict):
    volume_id = volume['VolumeId']
    logger.info("Operation 'update' completed on {}".format(volume_id))
    ec2.delete_tags(
        Resources=[volume_id],
        Tags=[{'Key': 'planb:operation:state'}]
    )


def step_forward(ec2: object, volume_id: str, options: dict):
    volume = get_volume(ec2, volume_id)
    tags = tags_as_dict(volume.get('Tags', []))
    if tags.get('planb:operation') != 'update':
        raise Exception(
            "Volume {} not prepared for operation 'update'".format(volume_id)
        )

    saved_instance = load_dict_from_file(instance_filename(volume))

    state = tags.get('planb:operation:state')
    logger.debug("{} planb:operation:state is {}".format(volume_id, state))
    if state == 'init':
        prepare_update(ec2, volume, options)

    elif state == 'prepared':
        drain_node(ec2, volume, saved_instance)

    elif state == 'drained':
        terminate_instance(ec2, volume, saved_instance)

    elif state == 'terminated':
        create_instance(ec2, volume, saved_instance, options)

    elif state == 'created':
        configure_instance(ec2, volume, saved_instance, options)

    elif state == 'configured':
        check_node_status(ec2, volume)

    elif state == 'completed':
        cleanup_state(ec2, volume)
        return False

    elif state == 'failed':
        logger.error(
            "Operation 'update' failed on {}: {}"
            .format(volume_id, tags.get('planb:update:fail-reason'))
        )
        return False

    else:
        raise Exception(
            "Unexpected planb:operation:state tag value of {}: {}"
            .format(volume_id, state)
        )
    return True


def ssh_command_works(odd_host: str) -> bool:
    ssh = subprocess.Popen(
        ['ssh', odd_host, 'echo', 'test-ssh'],
        stdout=subprocess.PIPE
    )
    try:
        out, err = ssh.communicate(timeout=5)
        return out == b'test-ssh\n'
    except Exception as e:
        logger.error(
            "Failed to open SSH connection to the Odd host: {}".format(e)
        )
        ssh.kill()
        ssh.communicate()


def open_ssh_tunnel(odd_host: str, instance: dict) -> object:

    if is_local_jolokia_port_open():
        click.echo(
            "Port {} is already in use on localhost!".format(local_jolokia_port),
            err=True
        )
        return None

    ip_address = instance['PrivateIpAddress']
    port_forward = "{}:{}:{}".format(
        local_jolokia_port, ip_address, remote_jolokia_port
    )
    cmd = ["ssh", odd_host, "-L", port_forward, "-N"]
    logger.info("Opening SSH tunnel: {}".format(" ".join(cmd)))
    ssh = subprocess.Popen(cmd)
    retry = 1
    while not is_local_jolokia_port_open():
        if retry > 5:
            ssh.terminate()
            return None
        retry += 1
        time.sleep(1)
    return ssh


def is_local_jolokia_port_open() -> bool:
    """
    Returns True if local_jolokia_port is accepting connections.
    """
    rcode = subprocess.call(['nc', 'localhost', str(local_jolokia_port), '-z'])
    return rcode == 0


def list_instances_to_update(ec2: object, cluster_name: str) -> list:
    dumps = list_instance_dump_files()
    if dumps:
        if len(dumps) > 1:
            click.echo(
                "Found more than one instance data dump file: {}".format(dumps),
                err=True
            )
            return None
        saved_instance = load_dict_from_file(dumps[0])
        msg = "Resume interrupted operation on node {}" \
              .format(saved_instance['PrivateIpAddress'])
        if click.confirm(msg):
            return [saved_instance]
    else:
        print("Listing cluster nodes for {}".format(cluster_name))
        alive_instances = [
            i
            for i in list_instances(ec2, cluster_name)
            if 'PrivateIpAddress' in i
        ]
        return sorted(alive_instances, key=lambda i: i['PrivateIpAddress'])


def update_cluster(options: dict):
    ec2 = ec2_client(options['region'])
    instances = list_instances_to_update(ec2, options['cluster_name'])
    if not instances:
        return

    if options['sns_topic'] or options['sns_email']:
        # a list of the only region we act on now
        regions = [options['region']]
        alarm_topics = setup_sns_topics_for_alarm(
            regions,
            options['sns_topic'],
            options['sns_email']
        )
    else:
        alarm_topics = {}
    options = dict(options, alarm_topics=alarm_topics)

    # TODO: List all nodes with IPs and some status information
    for i in instances:
        # TODO: user should hit Ctrl-c to cancel everything
        # don't ask again if resuming after crash
        if len(instances) > 1:
            question = "Update node {}?".format(i['PrivateIpAddress'])
            if not click.confirm(question):
                continue

        if not ssh_command_works(options['odd_host']):
            click.echo(
                "Cannot ssh to the Odd host!".format(local_jolokia_port),
                err=True
            )
            return

        ssh = open_ssh_tunnel(options['odd_host'], i)
        if not ssh:
            click.echo(
                "Cannot forward local port {} via ssh!"
                .format(local_jolokia_port),
                err=True
            )
            return

        try:
            volume_id = find_data_volume_id(ec2, i)
            volume = get_volume(ec2, volume_id)
            tags = tags_as_dict(volume.get('Tags', []))
            if 'planb:operation:state' not in tags:
                tag_instance_volume(ec2, volume, tags, i, options['cluster_name'])

            while step_forward(ec2, volume_id, options):
                time.sleep(5)

            # clean up any stale instance data dump file
            instance_dump_file = instance_filename(volume)
            if os.path.exists(instance_dump_file):
                os.unlink(instance_dump_file)

        except ClusterUnhealthyException:
            sys.stderr.write("""
Some nodes are DOWN.  Not updating anything!

Please make sure all nodes are UP before proceeding with update.
            """)
            return

        finally:
            ssh.terminate()
