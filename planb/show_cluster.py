from clickclick import print_table

TITLES = {
    'NameTag': 'Name Tag',
    'PrivateIpAddress': 'Private IP',
}

def show_instances(instances):
    print_table(["NameTag", "PrivateIpAddress"],
                [dict(i, NameTag=i['Tags']['Name'])
                 for i in instances],
                titles=TITLES)
