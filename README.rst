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

In order to be able to receive notification emails in case instance
recovery is triggered, provide either SNS topic name in
``--sns-topic``, or email to subscribe in ``--sns-email`` (or both).

If only the email address is specified, then SNS topic name defaults
to ``planb-cassandra-system-event``.  An SNS topic will be created (if
it doesn't exist) in each of the specified regions.  If email is
specified, then it will be subscribed to the topic.

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


Scaling up instance
===================

The following manual process may be applied whenever there is a need
to scale up EC2 instances or update Taupage AMI.

For every node in the cluster, one by one:

#. Stop a node (``nodetool stopdaemon``).
#. Terminate EC2 instance, remember its IP.  Simply stopping will not work as the private IP will be still occupied by the stopped instance.
#. Use the 'Launch More Like This' menu in AWS web console on one of the remaining nodes.
#. Be sure to reuse the IP of the node you just terminated on the new node and to change the instance type (and/or pick a different Taupage AMI).
#. While the new instance is spinning up, attach the (now detached) data volume to the new instance.  Use ``/dev/sdf`` as the device name.
#. Log in to node, check application logs, if it didn't start up correctly: ``docker restart taupageapp``.
#. Repair the node with ``nodetool repair`` (optional: if the node was down for less than ``max_hint_window_in_ms``, which is by default 3 hours, hinted hand off should take care of streaming the changes from alive nodes).
#. Check status with ``nodetool status``.

Proceed with other nodes as long as the current one is back and
everything looks OK from nodetool and application points of view.


Scaling out cluster
===================

It is possible to manually scale out already deployed cluster by
following these steps:

#. Increase replication factor of ``system_auth`` keyspace to the
   desired new total number of nodes in every region affected.

   For example, if you run in two regions and want to scale to 5 nodes
   per region, issue the following CQL command on any of the nodes:

   ``ALTER KEYSPACE system_auth WITH replication = {'class': 'NetworkTopologyStrategy', 'eu-central': 5, 'eu-west': 5};``

#. *For public IPs setup only:* pre-allocate Elastic IPs for the new
   nodes in every region, then update security groups in every region
   to include all newly allocated Elastic IP addresses.

   For example, if scaling from 3 to 5 nodes in two regions you will
   need 2 new IP addresses in every region and both security groups
   need to be updated to include a total of 4 new addresses.

#. Use the 'Launch More Like This' menu in the AWS web console on one
   of the running nodes.

#. Make sure that under 'Instance Details' the setting 'Auto-assign
   Public IP' is set to 'Disable'.

#. At the 'Add Storage' step add a data volume for the new node.  It
   should use ``/dev/sdf`` as the device name.  EBS encryption is not
   recommended as it might prevent auto-recovery.

#. Launch the instance.

#. *For public IPs setup:* while the instance is starting up,
   associate one of the pre-allocated Elastic IP addresses with it.

   **Caution!** For multi-region setup the nodes are started in DMZ
   subnet and thus don't have internet traffic before you give them a
   public IP.  Be sure to do this before anything else, or the new
   node won't be able to ship its logs and you won't be able to ssh
   into it (restarting the node should help if it was too late).

#. Monitor the logs of the new instance and ``nodetool status`` to
   track its progress in joining the ring.

#. Locate the new instance's data volume and add the ``Name`` tag for
   it (look at existing nodes and their data volumes).

#. Use the 'CloudWatch Monitoring' > 'Add/Edit Alarms' to add an
   auto-recovery alarm for the new instance.

   Check '[x] Take the action: [*] Recover this instance' and leave
   the rest of parameters at their default values.  It is also
   recommended to set up a notification SNS topic for actual recovery
   events.

Only when the new node has fully joined, proceed to add more nodes.
After all new nodes have joined, issue ``nodetool cleanup`` command on
every node in order to free up the space that is still occupied by the
data that the node is no longer responsible for.

.. _STUPS: https://stups.io/
.. _Taupage: http://docs.stups.io/en/latest/components/taupage.html
.. _Ec2MultiRegionSnitch: http://docs.datastax.com/en/cassandra/2.1/cassandra/architecture/architectureSnitchEC2MultiRegion_c.html
.. _EC2 Auto Recovery: https://aws.amazon.com/blogs/aws/new-auto-recovery-for-amazon-ec2/
.. _Jolokia: https://jolokia.org/
.. _STUPS Cassandra: https://github.com/zalando/stups-cassandra
.. _Più: http://docs.stups.io/en/latest/components/piu.html
