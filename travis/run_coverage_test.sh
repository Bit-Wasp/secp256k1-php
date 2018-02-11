#!/bin/bash

cd ../secp256k1 ; make clean ; cd ../travis
exitHard=false

if [ "${COVERAGE}" = "true" ]; then
    cd phpqa;
    ./container_command.sh coverage.sh
    if [ "$?" != "0" ]; then
        exitHard=true
    fi
    docker stop s1 > /dev/null;
    docker rm s1 > /dev/null;
fi

if [ "${exitHard}" = "true" ]; then
    echo "received error from coverage.sh"
    exit 1;
fi

echo "completed coverage command"
exit 0;
