#!/bin/bash
_PHPQA_DIR=$(git rev-parse --show-toplevel)/travis/phpqa
_GCOV_DIR=${_PHPQA_DIR}/output
_EXT_DIR=$(git rev-parse --show-toplevel)/secp256k1
_CMD=$1

sudo rm -rf ${_GCOV_DIR}

_PHP=${PHPQA_PHP_VERSION}

_php="7.1.7"
if [ ${_PHP} = "7.1.7" ]; then
  _php=${_PHP}
elif [ ${_PHP} = "7.2.20" ]; then
   _php=${_PHP}
elif [ ${_PHP} = "7.3.7" ]; then
  _php=${_PHP}
elif [ ${_PHP} = "7.0.33" ]; then
   _php=${_PHP}
fi

docker run -it \
     -v ${_GCOV_DIR}:/usr/src/php/lcov_html \
     -v ${_EXT_DIR}:/usr/src/php/ext/secp256k1 \
     --name s1 secp256k1-${_php} ${_CMD}
