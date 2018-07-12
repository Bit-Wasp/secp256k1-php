#!/bin/bash
set -e
cd $(git rev-parse --show-toplevel)

if [ "${COVERAGE}" = "true" ]; then
    travis/generate_stubs.sh

    cmp --silent stubs/const.php travis/stubs/output/const.php

    if [ $? -eq 0 ]
    then
        echo "const file ok";
    else
        echo "const file not up to date";
        exit -1;
    fi

    cmp --silent stubs/functions.php travis/stubs/output/functions.php

    if [ $? -eq 0 ]
    then
        echo "functions file ok";
    else
        echo "functions file not up to date";
        exit -1;
    fi
fi