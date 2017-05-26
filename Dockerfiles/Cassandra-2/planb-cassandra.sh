#!/bin/sh
# CLUSTER_NAME
# CASSANDRA_DIR
# CASSANDRA_CONF
# TRUSTSTORE
# KEYSTORE
# ADMIN_PASSWORD

export CASSANDRA_DIR=${CASSANDRA_DIR:-/var/lib/cassandra}

export CASSANDRA_CONF=${CASSANDRA_CONF:-/var/lib/cassandra/conf}
if [ ! -d "$CASSANDRA_CONF" ]; then
    if [ -z "$CLUSTER_NAME" ]; then
        echo "CLUSTER_NAME must be set"
        exit 1
    fi
    if [ -z "$TRUSTSTORE" ]; then
        echo "TRUSTSTORE must be set (base64 encoded)."
        exit 1
    fi
    if [ -z "$KEYSTORE" ]; then
        echo "KEYSTORE must be set (base64 encoded)."
        exit 1
    fi

    # copy default config from package-installed /etc/cassandra
    cp -r /etc/cassandra/ "$CASSANDRA_CONF"

    echo $TRUSTSTORE | base64 -d > "$CASSANDRA_CONF/truststore"
    echo $KEYSTORE   | base64 -d > "$CASSANDRA_CONF/keystore"

    ncores=$(grep -c ^processor /proc/cpuinfo)
    ncores_4=$(( ncores / 4 ))
    [ $ncores_4 -gt 0 ] || ncores_4=1

    echo "Generating configuration from template ..."
    merge-yaml.py \
        "$(cat "$CASSANDRA_CONF/cassandra.yaml-original")" \
        "\
# unset some parameters to reset defaults
listen_address:
broadcast_address:
data_file_directories:
commitlog_directory:
saved_caches_directory:

# enforce password check
authenticator: PasswordAuthenticator
authorizer: CassandraAuthorizer

concurrent_compactors: ${ncores_4}
memtable_flush_writers: ${ncores_4}

# protect internode traffic
server_encryption_options:
    internode_encryption: all
    keystore: $CASSANDRA_CONF/keystore
    keystore_password: $CLUSTER_NAME
    truststore: $CASSANDRA_CONF/truststore
    truststore_password: $CLUSTER_NAME" \
        "$YAML_CONFIG" \
        >"$CASSANDRA_CONF/cassandra.yaml"
fi

echo "Starting Cassandra ..."
/usr/sbin/cassandra -f &

#
# Try to create admin user and drop the default superuser (we don't care if it
# fails, that would just mean we are not the first one to do that).
#
sleep 60
cqlsh -u cassandra -p cassandra \
      -e "\
CREATE USER admin WITH PASSWORD '$ADMIN_PASSWORD' SUPERUSER; \
DROP USER cassandra; \
ALTER KEYSPACE system_auth WITH replication = { 'class': 'NetworkTopologyStrategy' $(echo $REGIONS | sed "s/\([^ ]*\)-1/, '\1': $CLUSTER_SIZE/g") };"

# Make sure the script don't exit at this point, if cassandra is still there.
wait
