FROM debian:jessie

ARG BUILD_PHP_VERSION="7.1.7"
ARG BUILD_GPG_KEYS="A917B1ECDA84AEC2B568FED6F50ABC807BD5DCD0 528995BFEDFBA7191D46839EF9BA0ADA31CBD89E"
ARG BUILD_PHP_SHA256="0d42089729be7b2bb0308cbe189c2782f9cb4b07078c8a235495be5874fff729"
ARG BUILD_CHECK_SIGNATURE=true
ARG BUILD_CUSTOM_URL=''
ARG BUILD_REPO_URL=''

ENV PHPIZE_DEPS \
		autoconf \
		dpkg-dev \
		file \
		g++ \
		gcc \
		libc-dev \
		lcov \
		libpcre3-dev \
		make \
		pkg-config \
		re2c
ENV COVERAGE_TARGET=
ENV COVERAGE_PREFIX_FUNCTIONS=
ENV SECP256K1_COMMIT=cd329dbc3eaf096ae007e807b86b6f5947621ee3
ENV PHP_INI_DIR /usr/local/etc/php
ENV PHP_CFLAGS="-fstack-protector-strong -fpic -fpie -O2"
ENV PHP_CPPFLAGS="$PHP_CFLAGS"
ENV PHP_LDFLAGS="-Wl,-O1 -Wl,--hash-style=both -pie"
ENV GPG_KEYS="$BUILD_GPG_KEYS"
ENV PHP_VERSION="$BUILD_PHP_VERSION"
ENV PHP_URL="https://secure.php.net/get/php-$PHP_VERSION.tar.xz/from/this/mirror"
ENV PHP_ASC_URL="https://secure.php.net/get/php-$PHP_VERSION.tar.xz.asc/from/this/mirror"
ENV PHP_SHA256="$BUILD_PHP_SHA256"
ENV CHECK_SIGNATURE="$BUILD_CHECK_SIGNATURE"
ENV CUSTOM_URL="$BUILD_CUSTOM_URL"
ENV REPO_URL="$BUILD_REPO_URL"

RUN apt-get update && apt-get install -y \
		$PHPIZE_DEPS \
		ca-certificates \
		curl \
		git \
		libedit2 \
		libsqlite3-0 \
		libxml2 \
		xz-utils \
        libjpeg-dev \
        libpng-dev \
        libfreetype6-dev \
        libzip-dev \
	--no-install-recommends && rm -r /var/lib/apt/lists/*
RUN mkdir -p $PHP_INI_DIR/conf.d
RUN set -xe; \
	\
	fetchDeps=' \
		wget \
		unzip \
	'; \
	apt-get update; \
	apt-get install -y --no-install-recommends $fetchDeps; \
	rm -rf /var/lib/apt/lists/*; \
	mkdir -p /usr/src; \
	cd /usr/src; \
	if [ -n "$REPO_URL" ]; then \
    	wget -O php-src-master.zip "$REPO_URL"; \
	elif [ -n "$CUSTOM_URL" ]; then \
	    wget -O php.tar.xz "$CUSTOM_URL"; \
	else \
	    wget -O php.tar.xz "$PHP_URL"; \
	fi; \
	if [ -n "$PHP_SHA256" ] && [ "$CHECK_SIGNATURE" = "true" ]; then \
		echo "$PHP_SHA256 *php.tar.xz" | sha256sum -c -; \
	fi; \
	if [ -n "$PHP_ASC_URL" ] && [ "$CHECK_SIGNATURE" = "true" ]; then \
		wget -O php.tar.xz.asc "$PHP_ASC_URL"; \
		export GNUPGHOME="$(mktemp -d)"; \
		for key in $GPG_KEYS; do \
			gpg --keyserver ha.pool.sks-keyservers.net --recv-keys "$key"; \
		done; \
		gpg --batch --verify php.tar.xz.asc php.tar.xz; \
		rm -r "$GNUPGHOME"; \
	fi;

COPY scripts/docker-php-* /usr/local/bin/

RUN set -xe \
	&& buildDeps=" \
		$PHP_EXTRA_BUILD_DEPS \
		libcurl4-openssl-dev \
		libedit-dev \
		libsqlite3-dev \
		libssl-dev \
		libxml2-dev \
		nano \
		build-essential \
		autoconf \
        automake \
        libtool \
        bison \
        re2c \
	" \
	&& apt-get update && apt-get install -y $buildDeps --no-install-recommends && rm -rf /var/lib/apt/lists/* \
	&& export CFLAGS="$PHP_CFLAGS" \
		CPPFLAGS="$PHP_CPPFLAGS" \
		LDFLAGS="$PHP_LDFLAGS"

RUN docker-php-source extract \
	&& cd /usr/src/php \
	&& gnuArch="$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)" \
	&& debMultiarch="$(dpkg-architecture --query DEB_BUILD_MULTIARCH)" \
	&& if [ -n "$REPO_URL" ]; then ./buildconf; fi \
	&& ./configure \
		--build="$gnuArch" \
		--with-config-file-path="$PHP_INI_DIR" \
		--with-config-file-scan-dir="$PHP_INI_DIR/conf.d" \
		--enable-ftp \
		--enable-mbstring \
		--enable-mysqlnd \
		--enable-zip \
		--with-curl \
		--enable-gcov \
		--with-libedit \
		--with-openssl \
		--with-zlib \
		--with-gd \
        --with-jpeg-dir \
        --with-png-dir \
		--with-pcre-regex \
		--with-libdir="lib/$debMultiarch" \
		$PHP_EXTRA_CONFIGURE_ARGS \
	&& make -j "$(nproc)" \
	&& make install \
	&& { find /usr/local/bin /usr/local/sbin -type f -executable -exec strip --strip-all '{}' + || true; } \
	&& cd / \
	&& pecl update-channels \
	&& rm -rf /tmp/pear ~/.pearrc \
	&& apt-get purge -y --auto-remove $fetchDeps

RUN cd /usr/src/php/scripts/dev \
    && rm generate-phpt.phar \
    && php -d phar.readonly=0 generate-phpt/gtPackage.php \
    && cd /

RUN cd / && git clone https://github.com/bitcoin-core/secp256k1.git \
    && cd secp256k1 && git checkout $SECP256K1_COMMIT \
    && ./autogen.sh \
    && ./configure --enable-benchmark=no --enable-tests=no --enable-experimental --enable-module-ecdh --enable-module-recovery \
    && make && make install && ldconfig

ADD scripts/coverage.sh /usr/bin
ADD scripts/parse_coverage.php /usr/src/php

RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /usr/src/php/
CMD ["/bin/bash"]
