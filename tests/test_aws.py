import pytest

from unittest.mock import MagicMock

from planb.aws import create_auto_recovery_alarm


def install_boto_client_mock(monkeypatch, region_mock: dict):
    client = MagicMock()
    client.side_effect = lambda _, region_name, **kwargs: region_mock[region_name]
    monkeypatch.setattr('planb.aws.boto_client', client)


def test_create_auto_recovery_alarm(monkeypatch):
    ec2_central = MagicMock()
    ec2 = {
        'eu-central-1': ec2_central
    }
    install_boto_client_mock(monkeypatch, ec2)

    create_auto_recovery_alarm('eu-central-1', 'test-cluster', 'i-1234', 'sns-arn')

    ec2_central.put_metric_alarm.assert_called_once_with(
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
