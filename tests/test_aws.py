import pytest
import copy

from unittest.mock import MagicMock

from planb.aws import add_sns_topics_for_alarm, create_auto_recovery_alarm


def install_boto_client_mock(monkeypatch, region_mock: dict):
    client = MagicMock()
    client.side_effect = lambda _, region_name, **kwargs: region_mock[region_name]
    monkeypatch.setattr('planb.aws.boto_client', client)


@pytest.fixture
def base_fixture(monkeypatch):
    eu_central = MagicMock()
    eu_west = MagicMock()
    mock = {
        'eu-central-1': eu_central,
        'eu-west-1': eu_west
    }
    install_boto_client_mock(monkeypatch, mock)
    return mock


def test_setup_sns(base_fixture):
    regions = {
        'eu-central-1': {
            'some': 'data'
        },
        'eu-west-1': {
            'other': 'stuff'
        }
    }
    base_fixture['eu-central-1'].create_topic.return_value = {
        'TopicArn': 'arn:central'
    }
    base_fixture['eu-west-1'].create_topic.return_value = {
        'TopicArn': 'arn:west'
    }
    expected = copy.deepcopy(regions)
    expected['eu-central-1']['alarm_sns_topic_arn'] = 'arn:central'
    expected['eu-west-1']['alarm_sns_topic_arn'] = 'arn:west'
    actual = add_sns_topics_for_alarm(regions, 'xxx', 'xxx@zzz.com')
    assert actual == expected

    base_fixture['eu-central-1'].subscribe.assert_called_once_with(
        TopicArn='arn:central',
        Protocol='email',
        Endpoint='xxx@zzz.com'
    )
    base_fixture['eu-west-1'].subscribe.assert_called_once_with(
        TopicArn='arn:west',
        Protocol='email',
        Endpoint='xxx@zzz.com'
    )

def test_create_auto_recovery_alarm(base_fixture):
    create_auto_recovery_alarm('eu-central-1', 'test-cluster', 'i-1234', 'sns-arn')

    base_fixture['eu-central-1'].put_metric_alarm.assert_called_once_with(
        AlarmName='test-cluster-i-1234-auto-recover',
        AlarmActions=['arn:aws:automate:eu-central-1:ec2:recover', 'sns-arn'],
        MetricName='StatusCheckFailed_System',
        Namespace='AWS/EC2',
        Statistic='Minimum',
        Dimensions=[{
            'Name': 'InstanceId',
            'Value': 'i-1234'
        }],
        Period=60,
        EvaluationPeriods=2,
        Threshold=0,
        ComparisonOperator='GreaterThanThreshold'
    )
