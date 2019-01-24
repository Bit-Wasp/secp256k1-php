#!/bin/bash
if [ "${COVERAGE}" = "true" ]; then
    for i in $(git rev-parse --show-toplevel)/examples/*.php; do
        php -d"extension=$(git rev-parse --show-toplevel)/modules/secp256k1.so" $i > /dev/null
        if [ $? -ne 0 ]; then
            echo "Error running example code: $i";
            exit -1
        fi;
    done
    echo "examples OK"
fi