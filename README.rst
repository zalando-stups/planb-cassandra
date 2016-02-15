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

To create a cluster named "mycluster" in two regions with 3 nodes per region (default size):

.. code-block:: bash

    $ mai login  # get temporary AWS credentials
    $ ./create-cluster.py mycluster eu-west-1 eu-central-1


Troubleshooting
===============

.. code-block:: bash

    $ # on Taupage instance
    $ watch docker exec -it taupageapp nodetool status

.. _STUPS: https://stups.io/
.. _Taupage: http://docs.stups.io/en/latest/components/taupage.html
.. _Ec2MultiRegionSnitch: http://docs.datastax.com/en/cassandra/2.1/cassandra/architecture/architectureSnitchEC2MultiRegion_c.html
.. _EC2 Auto Recovery: https://aws.amazon.com/blogs/aws/new-auto-recovery-for-amazon-ec2/
.. _Jolokia: https://jolokia.org/
.. _STUPS Cassandra: https://github.com/zalando/stups-cassandra
