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

* Python 3.4+
* Python dependencies (``sudo pip3 install -r requirements.txt``)
* Java 8 with ``keytool`` in your ``PATH`` (required to generate SSL certs)

To create a cluster named "mycluster" in two regions with 3 nodes per region (default size):

.. code-block:: bash

    $ mai login  # get temporary AWS credentials
    $ ./create-cluster.py mycluster eu-west-1 eu-central-1

After allowing SSH access (TCP port 22) by changing the Security Group,
you can use `Più`_ to get SSH access and create your first schema:

.. code-block:: bash

    $ piu 172.31.1.1 "initial Cassandra setup"  # replace private IP
    $ docker exec -it taupageapp cqlsh
    cqlsh> CREATE SCHEMA myschema WITH replication = {'class': 'NetworkTopologyStrategy', 'eu-west': 3, 'eu-central': 3};


Troubleshooting
===============

To watch the cluster's node status (e.g. joining during initial bootstrap):

.. code-block:: bash

    $ # on Taupage instance
    $ watch docker exec -it taupageapp nodetool status

.. _STUPS: https://stups.io/
.. _Taupage: http://docs.stups.io/en/latest/components/taupage.html
.. _Ec2MultiRegionSnitch: http://docs.datastax.com/en/cassandra/2.1/cassandra/architecture/architectureSnitchEC2MultiRegion_c.html
.. _EC2 Auto Recovery: https://aws.amazon.com/blogs/aws/new-auto-recovery-for-amazon-ec2/
.. _Jolokia: https://jolokia.org/
.. _STUPS Cassandra: https://github.com/zalando/stups-cassandra
.. _Più: http://docs.stups.io/en/latest/components/piu.html
