#!/bin/bash

./create_truststore.py

export TRUSTSTORE=$(cat test_truststore.base64)
export KEYSTORE=$(cat test_keystore.base64)

if [ x"$SNITCH" = "x" ]; then
    echo "Setting snitch to SimpleSnitch"
	SNITCH="SimpleSnitch"
fi

if [ x"$SUBNET_TYPE" = "x" ]; then
    echo "Setting subnet type to internal..."
	SUBNET_TYPE="internal"
fi

docker run -e KEYSTORE=$KEYSTORE \
           -e TRUSTSTORE=$TRUSTSTORE \
           -e SUBNET_TYPE=internal \
           -e CLUSTER_NAME=test-cluster \
           -e LISTEN_ADDRESS=localhost \
           -e SNITCH=SimpleSnitch \
           -e SEEDS=127.0.0.1 \
           -e SNITCH=$SNITCH \
           -e SUBNET_TYPE=$SUBNET_TYPE \
           -u 106 \
           -it $1 $2
