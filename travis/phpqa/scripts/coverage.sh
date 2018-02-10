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
    --enable-ftp \
    --enable-mbstring \
    --enable-mysqlnd \
    --with-zlib \
    --enable-zip \
    --with-curl \
    --enable-gcov \
    --with-libedit \
    --with-openssl \
    --with-gd \
    --with-secp256k1 \
    --with-jpeg-dir \
    --with-png-dir \
    --with-pcre-regex \
    --with-libdir="lib/$debMultiarch" \
    $PHP_EXTRA_CONFIGURE_ARGS \
&& make -j "$(nproc)" \
&& make install \
&& php -m \
&& ls -lsh ext/secp256k1 \
&& make lcov TESTS=ext/secp256k1/tests \
&& gcov lcov_data/ext/secp256k1/secp256k1.c -f > coverage.output \
&& php parse_coverage.php coverage.output
