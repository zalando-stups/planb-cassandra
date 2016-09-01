#!/bin/bash

./create_truststore.py

export TRUSTSTORE=$(cat test_truststore.base64)
export KEYSTORE=$(cat test_keystore.base64)

docker run -e KEYSTORE=$KEYSTORE \
           -e TRUSTSTORE=$TRUSTSTORE \
           -e SUBNET_TYPE=internal \
           -e CLUSTER_NAME=test-cluster \
           -e LISTEN_ADDRESS=localhost \
           -e SNITCH=SimpleSnitch \
           -e SEEDS=127.0.0.1 \
           -u 106 \
           -it $1 $2
