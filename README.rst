================
Plan B Cassandra
================

Cassandra with static Elastic IPs.

Usage
=====

.. code-block:: bash

    $ ./create-cluster.py mycluster eu-west-1 eu-central-1


Troubleshooting
===============

.. code-block:: bash

    $ # on Taupage instance
    $ watch docker exec -it taupageapp nodetool status
