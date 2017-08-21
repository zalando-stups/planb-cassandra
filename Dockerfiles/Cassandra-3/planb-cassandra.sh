#!/bin/sh
# CLUSTER_NAME
# AUTO_BOOTSTRAP
# LISTEN_ADDRESS
# BROADCAST_ADDRESS
# SNITCH
# DC_SUFFIX
# CASSANDRA_DATA_DIR
# TRUSTSTORE
# KEYSTORE
# ADMIN_PASSWORD
# MEMTABLE_FLUSH_WRITERS
# CONCURRENT_COMPACTORS
# AUTHENTICATOR
# AUTHORIZER
# ROLE_MANAGER

if [ -z "$CLUSTER_NAME" ] ;
then
    echo "Cluster name is not defined."
    exit 1
fi

if [ -z "$AUTO_BOOTSTRAP" ];
then
    echo "Automatic bootstrap is not set, defaulting to 'true'."
    export AUTO_BOOTSTRAP=true
fi

EC2_META_URL=http://169.254.169.254/latest/meta-data

if [ -z "$LISTEN_ADDRESS" ] ;
then
    export LISTEN_ADDRESS=$(curl -Ls -m 4 ${EC2_META_URL}/local-ipv4)
fi
echo "Local IP address is $LISTEN_ADDRESS ..."

if [ "x$SUBNET_TYPE" = xinternal ];
then
    export BROADCAST_ADDRESS=$LISTEN_ADDRESS

    if [ -z $SNITCH ] ;
    then
        export SNITCH="Ec2Snitch"
    fi
else
    while [ -z "$BROADCAST_ADDRESS" ] ;
    do
        echo "Waiting for Public IP address to be assigned ..."
        export BROADCAST_ADDRESS=$(curl -Ls -m 4 ${EC2_META_URL}/public-ipv4)
        sleep 5
    done

    if [ -z $SNITCH ] ;
    then
        export SNITCH="Ec2MultiRegionSnitch"
    fi
fi
echo "Broadcast IP address is $BROADCAST_ADDRESS ..."

export CASSANDRA_DATA_DIR=${CASSANDRA_DATA_DIR:-/var/lib/cassandra}

if [ -z "$TRUSTSTORE" ]; then
    echo "TRUSTSTORE must be set (base64 encoded)."
    exit 1
fi

if [ -z "$KEYSTORE" ]; then
    echo "KEYSTORE must be set (base64 encoded)."
    exit 1
fi

echo $TRUSTSTORE | base64 -d > /etc/cassandra/truststore
echo $KEYSTORE | base64 -d > /etc/cassandra/keystore

echo "Finished bootstrapping node."
# Add route 53record seed1.${CLUSTER_NAME}.domain.tld ?

ncores=$(grep -c ^processor /proc/cpuinfo)
ncores_4=$(( ncores / 4 ))
[ $ncores_4 -gt 0 ] || ncores_4=1

#
# Assuming we are using SSD storage, set memtable_flush_writers to the
# number of CPU cores divided by 4:
#
if [ -z "$MEMTABLE_FLUSH_WRITERS" ]; then
    export MEMTABLE_FLUSH_WRITERS=$ncores_4
fi

# the same for concurrent_compactors setting:
if [ -z "$CONCURRENT_COMPACTORS" ]; then
    export CONCURRENT_COMPACTORS=$ncores_4
fi

if [ -z "$AUTHENTICATOR" ]; then
    export AUTHENTICATOR=PasswordAuthenticator
fi

if [ -z "$AUTHORIZER" ]; then
    export AUTHORIZER=CassandraAuthorizer
fi

if [ -z "$ROLE_MANAGER" ]; then
    export ROLE_MANAGER=CassandraRoleManager
fi

echo "Generating configuration from template ..."
python -c "import sys, os; sys.stdout.write(os.path.expandvars(open('/etc/cassandra/cassandra_template.yaml').read()))" > /etc/cassandra/cassandra.yaml

if [ -n "$DC_SUFFIX" ]; then
    echo "Setting dc_suffix in cassandra-rackdc.properties ..."
    echo "dc_suffix=$DC_SUFFIX" > /etc/cassandra/cassandra-rackdc.properties
fi

echo "Starting Cassandra ..."
exec /usr/sbin/cassandra -R -f
