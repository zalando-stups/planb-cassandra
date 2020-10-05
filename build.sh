#!/bin/bash

set -ex

if [[ "$#" != 1 ]]; then
    echo "Usage: build.sh N"
    exit 1
fi
DATE_TAG="$(date +%Y%m%d)-$1"

PIERONE_URL=registry-write.opensource.zalan.do
pierone login --url $PIERONE_URL

function build_docker() {
    dir_suffix=$1
    version=$2
    image_suffix=$3

    cd "Dockerfiles/Cassandra-${dir_suffix}/"
    scm-source --fail-on-modified

    TAG="${PIERONE_URL}/stups/planb-cassandra-${image_suffix}:$(echo $version | tr '~' '_')_${DATE_TAG}"

    docker build . --pull -t "$TAG" --build-arg CASSANDRA_VERSION="$version"

    docker push "$TAG"
}

# to contain the side-effect of cd inside the function, make it look like Lisp:
(build_docker	4	4.0~beta2	4)
(build_docker	3	3.11.8		3)
(build_docker	3.0.x	3.0.22		3.0)
(build_docker	2.2	2.2.18		2.2)
(build_docker	2	2.1.22		2)
