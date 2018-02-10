#!/bin/bash

PROJECTNAME="$1"

echo "${PROJECTNAME}"

mkdir -p ${DOCKER_CACHE_DIR}

if [ -f ${DOCKER_CACHE_DIR}/${PROJECTNAME}.gz ]; then
    echo "load cache"
    zcat ${DOCKER_CACHE_DIR}/${PROJECTNAME}.gz | sudo docker load;
else
    echo "no cache"
fi
