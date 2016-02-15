#!/bin/sh
# CLUSTER_NAME
# DATA_DIR
# COMMIT_LOG_DIR
# LISTEN_ADDRESS

if [ -z "$CLUSTER_NAME" ] ;
then
    echo "Cluster name is not defined."
    exit 1
fi

if [ -z "$LISTEN_ADDRESS" ] ;
then
    export LISTEN_ADDRESS=$(curl -Ls -m 4 http://169.254.169.254/latest/meta-data/local-ipv4)
fi
echo "Node IP address is $LISTEN_ADDRESS ..."

while [ -z "$BROADCAST_ADDRESS" ] ;
do
    echo "Waiting for Public IP address to be assigned ..."
    export BROADCAST_ADDRESS=$(curl -Ls -m 4 http://169.254.169.254/latest/meta-data/public-ipv4)
    sleep 5
done
echo "Public IP address is $BROADCAST_ADDRESS ..."

if [ -z $SNITCH ] ;
then
    export SNITCH="Ec2MultiRegionSnitch"
fi

export DATA_DIR=${DATA_DIR:-/var/lib/cassandra}
export COMMIT_LOG_DIR=${COMMIT_LOG_DIR:-/var/lib/cassandra/commit_logs}

echo "Finished bootstrapping node."
# Add route 53record seed1.${CLUSTER_NAME}.domain.tld ?

echo "Generating configuration from template ..."
python -c "import sys, os; sys.stdout.write(os.path.expandvars(open('/etc/cassandra/cassandra_template.yaml').read()))" > /etc/cassandra/cassandra.yaml


echo "Starting Cassandra ..."
/usr/sbin/cassandra -f
