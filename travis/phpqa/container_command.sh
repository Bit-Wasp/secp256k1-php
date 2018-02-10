#!/bin/bash
_PHPQA_DIR=$(git rev-parse --show-toplevel)/travis/phpqa
_GCOV_DIR=${_PHPQA_DIR}/output
_EXT_DIR=$(git rev-parse --show-toplevel)/secp256k1
_CMD=$1

rm -rf ${_GCOV_DIR}
docker build -t secp256k1build .
docker run -it \
     -v ${_GCOV_DIR}:/usr/src/php/lcov_html \
     -v ${_EXT_DIR}:/usr/src/php/ext/secp256k1 \
     -e "COVERAGE_TARGET=${COVERAGE_TARGET}" \
     -e "COVERAGE_PREFIX_FUNCTIONS=${COVERAGE_PREFIX_FUNCTIONS}" \
     --name s1 secp256k1build ${_CMD}
