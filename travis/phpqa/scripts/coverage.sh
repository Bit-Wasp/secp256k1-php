#!/bin/bash
target=$1
set -x

gnuArch="$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)"
debMultiarch="$(dpkg-architecture --query DEB_BUILD_MULTIARCH)"

rm configure && ./buildconf --force

./configure \
    --build="$gnuArch" \
    --with-config-file-path="$PHP_INI_DIR" \
    --with-config-file-scan-dir="$PHP_INI_DIR/conf.d" \
    --enable-gcov \
    --with-curl \
		--with-openssl \
    --with-secp256k1 \
    --with-secp256k1-config \
    --with-module-ecdh \
    --with-module-recovery \
    --with-module-schnorrsig \
    --with-libdir="lib/$debMultiarch" \
    $PHP_EXTRA_CONFIGURE_ARGS \
&& make -j "$(nproc)" \
&& make install \
&& php -m \
&& ls -lsh ext/secp256k1 \
&& make lcov TESTS=ext/secp256k1/tests \
&& gcov lcov_data/ext/secp256k1/secp256k1.c -f > coverage.output

cp -v coverage.output ext/secp256k1/
cp -v secp256k1.c.gcov ext/secp256k1/
