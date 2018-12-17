from .common import boto_client, get_instance, \
    setup_sns_topics_for_alarm, create_auto_recovery_alarm


def set_auto_recovery_alarm(options: dict):
    region = options['region']

    alarm_sns_topic_arn = None
    if options['sns_topic'] or options['sns_email']:
        regions = [region]
        alarm_topics = setup_sns_topics_for_alarm(
            regions,
            options['sns_topic'],
            options['sns_email']
        )
        alarm_sns_topic_arn = alarm_topics[region]

    ec2 = boto_client('ec2', region)
    instance_id = options['instance_id']
    instance = get_instance(ec2, instance_id)

    create_auto_recovery_alarm(
        region,
        instance['Tags']['Name'],
        instance_id,
        alarm_sns_topic_arn
    )
