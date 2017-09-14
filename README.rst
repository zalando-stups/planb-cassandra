================
Plan B Cassandra
================

Bootstrap and update a Cassandra cluster on STUPS_/AWS.

Planb deploys Cassandra by means of individual EC2 instances running Taupage_ & Docker with the latest
Cassandra version 3.0.x (default, the new 'tick-tock' releases 3.x and older version 2.1
are still available).

Features:

* internal to a VPC or span multiple AWS regions
* fully-automated setup including Elastic IPs (when needed), EC2 security groups, SSL certs
* multi-region replication available (using Ec2MultiRegionSnitch_)
* encrypted inter-node communication (SSL/TLS)
* `EC2 Auto Recovery`_ enabled
* Jolokia_ agent to expose JMX metrics via HTTP

Non-Features:

* dynamic cluster sizing - please see `STUPS Cassandra`_ if you need a dynamic Cassandra cluster setup


Prerequisites
==============

* Python 3.5+
* Python dependencies (``sudo pip3 install -r requirements.txt``)
* Java 8 with ``keytool`` in your ``PATH`` (required to generate SSL certificates)
* Latest Stups tooling installed and configured
* You have created a dedicated AWS IAM user for auto-recovery.  The policy
  document for this user should look like the following::

    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ec2:DescribeInstanceRecoveryAttribute",
                    "ec2:RecoverInstances",
                    "ec2:DescribeInstanceStatus",
                    "ec2:DescribeInstances",
                    "cloudwatch:PutMetricAlarm"
                ],
                "Resource": [
                    "*"
                ]
            }
        ]
    }
* You have a ``planb_autorecovery`` section in your AWS credentials file
  (``~/.aws/credentials``) with the access key of the auto-recovery user::

    [planb_autorecovery]
    aws_access_key_id = THEKEYID
    aws_secret_access_key = THESECRETKEY

  These credentials are only used to create the auto-recovery alarm.  When
  triggered by the failing system status check, the recovery action is
  performed by this dedicated user.

  .. note::

     The access keys for the auto-recovery user can be rotated or made
     inactive at any time, without impacting its ability to perform the
     recovery action.  The user still needs to be there, however.


Usage
=====

Create a Cluster
----------------

To create a cluster named "mycluster" in two regions with 3 nodes per region
(the default size, enough for testing):

.. code-block:: bash

    $ zaws login  # get temporary AWS credentials
    $ ./planb.py create --cluster-name mycluster --use-dmz eu-west-1 eu-central-1

The above example requires Elastic IPs to be allocated in every region (this
might require to increase the AWS limits for Elastic IPs).

To create a cluster in a single region, using private IPs only, see
the following example:

.. code-block:: bash

    $ ./planb.py create --cluster-name mycluster eu-central-1

It is possible to use Public IPs even with a single region, for
example, if your application(s) connect from different VPC(s).  This
is currently **not recommended**, though, as there is no provision for
client-to-server encryption.

Available options are:

===========================  ============================================================================
--cluster-name               Not actually an option, you must specify the name of a cluster to create
--cluster-size               Number of nodes to create per AWS region.  Default: 3
--num-tokens                 Number of virtual nodes per node.  Default: 256
--instance-type              AWS EC2 instance type to use for the nodes.  Default: t2.medium
--volume-type                Type of EBS data volume to create for every node.  Default: gp2 (General Purpose SSD).
--volume-size                Size of EBS data volume in GB for every node.  Default: 16
--volume-iops                Number of provisioned IOPS for the volumes, used only for volume type of io1.  Default: 100 (when applicable).
--no-termination-protection  Don't protect EC2 instances from accidental termination.  Useful for testing and development.
--use-dmz                    Deploy the cluster into DMZ subnets using Public IPs (required for multi-region setup).
--hosted-zone                Specify this to create SRV records for every region, listing all nodes' private IP addresses in that region.  This is optional.
--scalyr-key                 Write Logs API Key for Scalyr (optional).
--artifact-name              Override Pierone artifact name.  Default: planb-cassandra-3.0
--docker-image               Override default Docker image.
--environment, -e            Extend/override environment section of Taupage user data.
--sns-topic                  Amazon SNS topic name to use for notifications about Auto-Recovery.
--sns-email                  Email address to subscribe to Amazon SNS notification topic.  See below for details.
===========================  ============================================================================

In order to be able to receive notification emails in case instance
recovery is triggered, provide either SNS topic name in
``--sns-topic``, or email to subscribe in ``--sns-email`` (or both).

If only the email address is specified, then SNS topic name defaults
to ``planb-cassandra-system-event``.  An SNS topic will be created (if
it doesn't exist) in each of the specified regions.  If email is
specified, then it will be subscribed to the topic.

If you use the Hosted Zone parameter, a full name specification is
required e.g.: ``--hosted-zone myzone.example.com.`` (note the
trailing dot.)

After the create command finishes successfully, follow the on-screen
instructions to create the admin superuser, set replication factors for
system_auth keyspace and then create your application user and the data
keyspace.

The generated administrator password is available inside the docker
container in an environment variable ``ADMIN_PASSWORD``.

The list of private IP contact points for the application can be
obtained with the following snippet:

.. code-block:: bash

    $ aws ec2 describe-instances --region $REGION --filter 'Name=tag:Name,Values=planb-cassandra' | grep PrivateIp | sed s/[^0-9.]//g | sort -u

Update of a cluster
-------------------

.. important::

   The Jolokia port 8778 should be accessible from the Odd host. Ensure the
   ingress rule for your clusters security group allows connections from the Odd
   host.

To update the Docker image or AMI you should ensure that you are logged in to
your account and have SSH access to your Odd host. The following commands will
allow you to update the Docker image on all nodes of the cluster `mycluster`.
If an action is interrupted the next call will resume with the last action on
the last used node.

.. code-block:: bash

    $ zaws re $ACCOUNT
    $ piu re -O $ODDHOST $ODDHOST
    $ ./planb.py update --cluster-name mycluster \
        --docker-image registry.opensource.zalan.do/stups/planb-cassandra-3.0:cd-69 \
        --region eu-central-1 \
        -O $ODDHOST \
        --sns-topic planb-cassandra-system-event \
        --sns-email test@example.com

Available options for update:

===================  ========================================================
--cluster-name       The name of your cluster (required)
--odd-host           The Odd host in the region of your VPC (required)
--region             The region where the update should be applied (required)
--force-termination  Disable termination protection for the duration of update
--docker-image       The full specified name of the Docker image
--taupage-ami-id     The full specified name of the AMI
--instance-type      The type of instance to deploy each node on (e.g. t2.medium)
--sns-topic          Amazon SNS topic name to use for notifications about Auto-Recovery.
--sns-email          Email address to subscribe to Amazon SNS notification topic.  See description of ``create`` subcommand above for details.
===================  ========================================================


Client configuration for Public IPs setup
=========================================

When configuring your client application to talk to a Cassandra
cluster deployed in AWS using Public IPs, be sure to enable address
translation using EC2MultiRegionAddressTranslator_.  Not only it saves
costs when communicating within single AWS region, it also prevents
availability problems when security group for your Cassandra is not
configured to allow client access on Public IPs (via the region's NAT
instances addresses).

Even if your client connects to the ring using Private IPs, the list
of peers it gets from the first Cassandra node to be contacted only
consists of Public IPs in such setup.  Should that node go down at a
later time, the client has no chance of reconnecting to a different
node if the client traffic on Public IPs is not allowed.  For the same
reason the client won't be able to distribute load efficiently, as it
will have to choose the same coordinator node for every request it
sends (namely, the one it has first contacted via the Private IP).


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

#. Stop a node (``nodetool drain; nodetool stopdaemon``).
#. Terminate EC2 instance, **take note of its IP address(es)**.  Simply stopping will not work as the private IP will be still occupied by the stopped instance.
#. Use the 'Launch More Like This' menu in AWS web console on one of the remaining nodes.
#. **Use the latest available Taupage AMI version.  Older versions are subject to data loss race conditions when attaching EBS volumes.**
#. Be sure to reuse the private IP of the node you just terminated on the new node.
#. In the 'Instance Details' section, edit 'User Data' to add ``erase_on_boot: false`` flag under ``mounts: /var/lib/cassandra``.  See documentation of Taupage_ for detailed description and syntax example.  The docker image version being used can also be updated in this section, however, it is recommended to avoid changing multiple things at a time.  Also, docker image can be updated without terminating the instance, by stopping and starting it with updated 'User Data' instead.
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

#. If present remove the volumes section from user data. It references
   the data volume of the original instance.

#. Choose appropriate subnet for the new node: ``internal-...``
   vs. ``dmz-...`` for public IPs setup.  Also try to pick an
   under-represented Availability Zone here, the subnet name suffix
   gives a hint: ``1a``, ``1b``, etc.

#. Make sure that under 'Instance Details' the setting 'Auto-assign
   Public IP' is set to 'Disable'.

#. **Review UserData.**  Make sure that ``AUTO_BOOTSTRAP`` environment
   variable is set to ``true`` or not present.

#. At the 'Add Storage' step add a data volume for the new node.  It
   should use ``/dev/xvdf`` as the device name.  EBS encryption is not
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
.. _Odd: http://docs.stups.io/en/latest/components/odd.html
.. _Taupage: http://docs.stups.io/en/latest/components/taupage.html
.. _Ec2MultiRegionSnitch: http://docs.datastax.com/en/cassandra/2.1/cassandra/architecture/architectureSnitchEC2MultiRegion_c.html
.. _EC2MultiRegionAddressTranslator: https://datastax.github.io/java-driver/manual/address_resolution/#ec2-multi-region
.. _EC2 Auto Recovery: https://aws.amazon.com/blogs/aws/new-auto-recovery-for-amazon-ec2/
.. _Jolokia: https://jolokia.org/
.. _STUPS Cassandra: https://github.com/zalando/stups-cassandra
.. _Più: http://docs.stups.io/en/latest/components/piu.html

Upgrade your cluster from Cassandra 2.1 -> 3.0.x
===================

In order to upgrade your Cluster you should run the following steps. You should have in mind that this process is a rolling update, which means applying the changes for each node in your cluster one by one.
After upgrading the last node in your cluster you are done.

**Disclaimer: Before you actually start, you should:**
  1. Read the [Datastax guide](https://docs.datastax.com/en/latest-upgrade/upgrade/cassandra/upgrdCassandraDetails.html) and consider the upgrade restrictions.
  2. Check if your client applications driver actually support V4 of the cql-protocol


1. Check for the latest Plan-B Cassandra image version: 
  `curl https://registry.opensource.zalan.do/teams/stups/artifacts/planb-cassandra-3.0/tags | jq '.[-1].name'`
2. Connect to the instance where you want to run the upgrade and enter your docker container. 
3. Run `nodetool upgradesstables` and `nodetool drain`. The latter command will flush the memtables and speed up the upgrade process later on. *This command is mandatory and cannot be skipped.*
   Excerpt from the manual `Cassandra stops listening for connections from the client and other nodes. You need to restart Cassandra after running nodetool drain.`
4. Remove the docker container by running on the host `docker rm -f taupageapp`
5. If you are running cassandra with the old folder structure where the data is directly located in __mounts/var/lib/cassandra/__ do the following. **If not go on with step 6.** 
  1. Move all keyspaces to __/mounts/var/lib/cassandra/data/data__
  2. Move the folder  commit_logs to __/mounts/var/lib/cassandra/data/commitlog__ 
  3. Move the folder saved_caches to __/mounts/var/lib/cassandra/data/__
  4. Set owner of data folders to application
    Example:
    ```
    **Before Move**

    /mounts/var/lib/cassandra$ ls
    commit_logs  keyspace_1 saved_caches  system_auth  system_traces 


    **After Move**

    /mounts/var/lib/cassandra$ ls -la
    total 28
    drwxrwxrwx 4 application application  4096 Oct 10 12:21 .
    drwxr-xr-x 3 root        root         4096 Aug 25 13:27 ..
    drwxrwxr-x 5 application mpickhan     4096 Oct 10 12:21 data

    /mounts/var/lib/cassandra$ ls -la data/
    total 36
    drwxrwxr-x 5 application mpickhan     4096 Oct 10 12:21 .
    drwxrwxrwx 4 application application  4096 Oct 10 12:21 ..
    drwxr-xr-x 2 application root        20480 Oct 10 12:15 commitlog
    drwxrwxr-x 9 application mpickhan     4096 Oct 10 12:19 data
    drwxr-xr-x 2 application root         4096 Oct 10 10:52 saved_caches

    /mounts/var/lib/cassandra$ ls -la data/data/
    total 36
    drwxrwxr-x  9 application mpickhan 4096 Oct 10 12:19 .
    drwxrwxr-x  5 application mpickhan 4096 Oct 10 12:21 ..
    drwxr-xr-x 10 application root     4096 Aug 25 14:29 keyspace_1
    drwxr-xr-x 19 application root     4096 Aug 25 13:27 system
    drwxr-xr-x  5 application root     4096 Aug 25 13:27 system_auth
    drwxr-xr-x  4 application root     4096 Aug 25 13:27 system_traces
    ```
6. **Stop** the ec2-Instance and change the user details `Go to Actions -> Instance Settings -> View/Change User Details` Change the "source" entry to the version you want to upgrade to:
    **Important:** Use the stop command and __not__ terminate.
    ```
    Example:

    From: "source: registry.opensource.zalan.do/stups/planb-cassandra:cd89"
    To: "source: registry.opensource.zalan.do/stups/planb-cassandra-3.0:cd105"
    ```
7. Start the instance and connect to it. At this point your node should be working and serving reads and writes. Login to the docker container and finish the upgrade by running `nodetool upgradesstables`.
   Check the logs for errors and warnings. (__Note:__ For the size of ~12GB SSTables it takes approximately one hour to convert them to the new format.)
8. Proceed with each node in your cluster.
