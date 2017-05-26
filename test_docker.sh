#!/bin/bash

./create_truststore.py

docker run -e KEYSTORE=$(cat test_truststore.base64) \
           -e TRUSTSTORE=$(cat test_keystore.base64) \
           -e CLUSTER_NAME=test-cluster \
           -e YAML_CONFIG="
cluster_name: test-cluster
listen_address: localhost
endpoint_snitch: SimpleSnitch
seed_provider:
- class_name: org.apache.cassandra.locator.SimpleSeedProvider
  parameters:
  - seeds: 127.0.0.1
" \
           -it "$@"
#           -u 999 \
