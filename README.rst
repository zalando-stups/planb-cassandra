================
Plan B Cassandra
================

Bootstrap a multi-region Cassandra cluster on STUPS_/AWS with static Elastic IPs.

The ``create-cluster.py`` script will start individual EC2 instances running Taupage_ & Docker
in multiple AWS regions to form a Cassandra cluster with multi-region replication.

Features:

* fully-automated setup including Elastic IPs, EC2 security groups, SSL certs
* multi-region replication (Ec2MultiRegionSnitch_)
* encrypted inter-node communication (SSL/TLS)
* `EC2 Auto Recovery`_ enabled
* Jolokia_ agent to expose JMX metrics via HTTP

Non-Features:

* dynamic cluster sizing - please see `STUPS Cassandra`_ if you need a dynamic Cassandra cluster setup


Usage
=====

Prerequisites:

* Python 3.5+
* Python dependencies (``sudo pip3 install -r requirements.txt``)
* Java 8 with ``keytool`` in your ``PATH`` (required to generate SSL certs)

To create a cluster named "mycluster" in two regions with 3 nodes per region (default size):

.. code-block:: bash

    $ mai login  # get temporary AWS credentials
    $ ./create_cluster.py --cluster-name mycluster eu-west-1 eu-central-1

After allowing SSH access (TCP port 22) by changing the Security Group,
you can use `Più`_ to get SSH access and create your application user and
the first schema:

.. code-block:: bash

    $ piu 172.31.1.1 "initial Cassandra setup"  # replace private IP
    $ docker exec -it taupageapp bash
    (docker)$ cqlsh -u cassandra -p $ADMIN_PASSWORD
    cqlsh> CREATE USER myuser WITH PASSWORD '...' NOSUPERUSER;
    cqlsh> CREATE SCHEMA myschema WITH replication = {'class': 'NetworkTopologyStrategy', 'eu-west': 3, 'eu-central': 3};

The generated administrator password is available inside the docker
container in an environment variable ``ADMIN_PASSWORD``.

The list of private IP contact points for the application can be obtained with the following snippet:

.. code-block:: bash

    $ aws ec2 describe-instances --region $REGION --filter 'Name=tag:Name,Values=planb-cassandra' | grep PrivateIp | sed s/[^0-9.]//g | sort -u


Troubleshooting
===============

To watch the cluster's node status (e.g. joining during initial bootstrap):

.. code-block:: bash

    $ # on Taupage instance
    $ watch docker exec -it taupageapp nodetool status

The output should look something like this (freshly bootstrapped cluster):

::

    Datacenter: eu-central
    ======================
    Status=Up/Down
    |/ State=Normal/Leaving/Joining/Moving
    --  Address        Load       Tokens  Owns (effective)  Host ID                               Rack
    UN  52.29.137.93   66.59 KB   256     34.8%             62f50c2c-cb0f-4f62-a518-aa7b1fd04377  1a
    UN  52.28.11.187   66.43 KB   256     31.1%             69d698a9-7357-46b2-93b8-6c038155f0c1  1b
    UN  52.29.41.128   71.79 KB   256     35.0%             b76e7ed7-78de-4bbc-9742-13adbbcfd438  1a
    Datacenter: eu-west
    ===================
    Status=Up/Down
    |/ State=Normal/Leaving/Joining/Moving
    --  Address        Load       Tokens  Owns (effective)  Host ID                               Rack
    UN  52.49.209.129  91.29 KB   256     34.8%             140bc7de-9973-46fd-af8c-68148bf20524  1b
    UN  52.49.192.149  81.16 KB   256     32.1%             cb45fc4c-291d-4b2b-b50f-3a11048f0211  1c
    UN  52.49.128.58   81.22 KB   256     32.1%             8a270de3-b419-4baf-8449-f4bc65c51d0d  1a


.. _STUPS: https://stups.io/
.. _Taupage: http://docs.stups.io/en/latest/components/taupage.html
.. _Ec2MultiRegionSnitch: http://docs.datastax.com/en/cassandra/2.1/cassandra/architecture/architectureSnitchEC2MultiRegion_c.html
.. _EC2 Auto Recovery: https://aws.amazon.com/blogs/aws/new-auto-recovery-for-amazon-ec2/
.. _Jolokia: https://jolokia.org/
.. _STUPS Cassandra: https://github.com/zalando/stups-cassandra
.. _Più: http://docs.stups.io/en/latest/components/piu.html
