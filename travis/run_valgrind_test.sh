#!/bin/bash

exitHard=false
if [ "${VALGRIND}" = "true" ]; then
    cd $(git rev-parse --show-toplevel)/secp256k1
    sudo make clean
    cd $(git rev-parse --show-toplevel)/travis/phpqa
    ./build_container.sh
    ./container_command.sh valgrind.sh
    if [ "$?" != "0" ]; then
        exitHard=true
    fi
    docker stop s1 > /dev/null;
    docker rm s1 > /dev/null;
    echo "completed valgrind command";
fi

if [ "${exitHard}" = "true" ]; then
    echo "received error from valgrind.sh"
    exit 1;
fi

exit 0;
