#!/bin/bash

./create_truststore.py

export TRUSTSTORE=$(cat test_truststore.base64)
export KEYSTORE=$(cat test_keystore.base64)

docker run -e KEYSTORE=$KEYSTORE \
           -e TRUSTSTORE=$TRUSTSTORE \
           -e SUBNET_TYPE=internal \
           -e CLUSTER_NAME=test-cluster \
           -e LISTEN_ADDRESS=localhost \
           -u 106 \
           -it registry.opensource.zalan.do/stups/planb-cassandra-3.7:v1 $1
