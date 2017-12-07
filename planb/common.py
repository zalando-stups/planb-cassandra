import boto3
import botocore
import base64
import yaml
import json
import copy
import time
import io
import os
from datetime import datetime


class SessionRefreshingBotoClient(object):

    def __init__(self, profile_name: str, service_name: str, region_name: str):
        self._profile_name = profile_name
        self._service_name = service_name
        self._region_name = region_name
        self._refresh_session()

    def _refresh_session(self):
        # creating the session explicitly avoids use of stale credentials
        session = boto3.session.Session(profile_name=self._profile_name)
        self._client = session.client(self._service_name, self._region_name)

    def _wrap_callable(self, name: str):
        def wrapper(*args, **kwargs):
            retried = False
            while True:
                try:
                    attr = getattr(self._client, name)
                    return attr(*args, **kwargs)
                except botocore.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == 'RequestExpired':
                        if not retried:
                            retried = True
                            self._refresh_session()
                            continue
                    raise
        return wrapper

    def __getattr__(self, name: str):
        attr = getattr(self._client, name)
        return self._wrap_callable(name) if callable(attr) else attr


def boto_client(service_name: str, region_name: str = None,
                profile_name: str = None) -> object:
    return SessionRefreshingBotoClient(profile_name, service_name, region_name)


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""

    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, bytes):
        return str(obj, 'UTF-8')

    raise TypeError("Type not serializable")


# TODO: can be actually a list of dicts...
# use better name
def dump_dict_as_file(data: dict, filename: str):
    with open(filename, 'w') as f:
        json.dump(data, f, default=json_serial)


def load_dict_from_file(filename: str) -> dict:
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            return json.load(f)


def get_user_data(ec2: object, instance_id: str) -> dict:
    resp = ec2.describe_instance_attribute(
        InstanceId=instance_id,
        Attribute='userData'
    )
    raw_bytes = base64.b64decode(resp['UserData']['Value'])
    data = str(raw_bytes, 'UTF-8')
    stream = io.StringIO(data)
    return yaml.safe_load(stream)


def dump_user_data_for_taupage(user_data: dict) -> str:
    return '#taupage-ami-config\n{}'.format(yaml.safe_dump(user_data))


def list_instances(ec2: object, cluster_name: str):
    resp = ec2.describe_instances(Filters=[{
            'Name': 'tag:Name',
            'Values': [cluster_name]
        }])
    return sum([r['Instances'] for r in resp['Reservations']], [])


def override_ephemeral_block_devices(mappings: dict) -> dict:
    #
    # Override any ephemeral volumes with NoDevice mapping,
    # otherwise auto-recovery alarm cannot be actually enabled.
    #
    block_devices = []
    for bd in mappings:
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
            block_devices.append(
                {'DeviceName': bd['DeviceName'],
                 'NoDevice': ''}
            )
    return block_devices


def setup_sns_topics_for_alarm(regions: list, topic_name: str, email: str) -> list:
    if not(topic_name):
        topic_name = 'planb-cassandra-system-event'

    result = {}
    for region in regions:
        sns = boto_client('sns', region)
        resp = sns.create_topic(Name=topic_name)
        topic_arn = resp['TopicArn']
        if email:
            sns.subscribe(TopicArn=topic_arn, Protocol='email', Endpoint=email)
        result[region] = topic_arn
    return result


def create_auto_recovery_alarm(region: str, cluster_name: str,
                               instance_id: str, alarm_sns_topic_arn: str):
    cw = boto_client('cloudwatch', region, profile_name='planb_autorecovery')
    alarm_name = '{}-{}-auto-recover'.format(cluster_name, instance_id)

    alarm_actions = ['arn:aws:automate:{}:ec2:recover'.format(region)]
    if alarm_sns_topic_arn:
        alarm_actions.append(alarm_sns_topic_arn)

    cw.put_metric_alarm(
        AlarmName=alarm_name,
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
        ComparisonOperator='GreaterThanThreshold'
    )


def make_instance_profile_name(cluster_name: str) -> str:
    return 'profile-{}'.format(cluster_name)


def get_instance_profile(cluster_name: str) -> dict:
    iam = boto_client('iam')
    try:
        profile_name = make_instance_profile_name(cluster_name)
        profile = iam.get_instance_profile(InstanceProfileName=profile_name)
        return profile['InstanceProfile']
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return None
        raise e


def create_instance_profile(cluster_name: str):
    profile_name = make_instance_profile_name(cluster_name)
    role_name = 'role-{}'.format(cluster_name)
    policy_name = 'policy-{}-datavolume'.format(cluster_name)

    iam = boto_client('iam')

    profile = iam.create_instance_profile(InstanceProfileName=profile_name)

    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument="""{
            "Version": "2012-10-17",
            "Statement": [{
                "Action": "sts:AssumeRole",
                "Effect": "Allow",
                "Principal": {
                    "Service": "ec2.amazonaws.com"
                }
            }]
        }"""
    )

    policy_document = """{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ec2:DescribeTags",
                    "ec2:DeleteTags",
                    "ec2:DescribeVolumes",
                    "ec2:AttachVolume"
                ],
                "Resource": "*"
            }
        ]
    }"""
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=policy_document
    )

    iam.add_role_to_instance_profile(
        InstanceProfileName=profile_name,
        RoleName=role_name
    )

    #
    # FIXME: using an instance profile right after creating one
    # can result in 'not found' error, because of eventual
    # consistency.  For now fix with a sleep, should rather
    # examine exception and retry after some delay.
    #
    time.sleep(30)
    return profile['InstanceProfile']


def ensure_instance_profile(cluster_name: str):
    profile = get_instance_profile(cluster_name)
    if profile is None:
        profile = create_instance_profile(cluster_name)
    return profile
