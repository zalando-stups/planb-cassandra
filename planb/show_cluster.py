def show_instances(instances):
    for i in instances:
        f ="{InstanceId} {PrivateIpAddress}".format(**i)
        print(f)
