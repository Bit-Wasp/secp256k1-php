#!/bin/bash

PROJECTNAME="$1"

echo "${PROJECTNAME}"

mkdir -p ${DOCKER_CACHE_DIR}

docker history -q ${PROJECTNAME}:latest | grep -v '<missing>'

NEW=$(docker history -q ${PROJECTNAME}:latest | grep -v '<missing>' | sha256sum | awk '{print $1}')
OLD=$(cat ${DOCKER_CACHE_DIR}/${PROJECTNAME}.checksum)

echo "new=${NEW} old=${OLD}"

if [ "$NEW" != "$OLD" ]; then
    echo "saving"
    docker save $(docker history -q ${PROJECTNAME}:latest | grep -v '<missing>') | gzip > ${DOCKER_CACHE_DIR}/${PROJECTNAME}.gz
    echo "$NEW" > ${DOCKER_CACHE_DIR}/${PROJECTNAME}.checksum
else
    echo "no change"
fi

