#!/bin/sh
# CLUSTER_NAME
# DATA_DIR
# COMMIT_LOG_DIR
# LISTEN_ADDRESS

# http://docs.datastax.com/en/cassandra/2.0/cassandra/architecture/architectureGossipAbout_c.html
# "...it is recommended to use a small seed list (approximately three nodes per data center)."
NEEDED_SEEDS=$((CLUSTER_SIZE > 3 ? 3 : 1))
TTL=${TTL:-30}

if [ -z "$CLUSTER_NAME" ] ;
then
    echo "Cluster name is not defined."
    exit 1
fi

# TODO: use public-ipv4 if multi-region
if [ -z "$LISTEN_ADDRESS" ] ;
then
    export LISTEN_ADDRESS=$(curl -Ls -m 4 http://169.254.169.254/latest/meta-data/local-ipv4)
fi

if [ -z "$BROADCAST_ADDRESS" ] ;
then
    export BROADCAST_ADDRESS=$(curl -Ls -m 4 http://169.254.169.254/latest/meta-data/public-ipv4)
fi

echo "Node IP address is $LISTEN_ADDRESS ..."

# TODO: Use diff. Snitch if Multi-Region
if [ -z $SNITCH ] ;
then
    export SNITCH="Ec2MultiRegionSnitch"
fi

export DATA_DIR=${DATA_DIR:-/var/lib/cassandra}
export COMMIT_LOG_DIR=${COMMIT_LOG_DIR:-/var/lib/cassandra/commit_logs}

echo "Finished bootstrapping node."
# Add route 53record seed1.${CLUSTER_NAME}.domain.tld ?

echo "Generating configuration from template ..."
python -c "import os; print os.path.expandvars(open('/etc/cassandra/cassandra_template.yaml').read())" > /etc/cassandra/cassandra.yaml


echo "Starting Cassandra ..."
/usr/sbin/cassandra -f
