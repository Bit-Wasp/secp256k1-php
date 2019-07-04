phpqa container
===============

This Dockerfile was inspired by the [docker-phpqa](https://github.com/herdphp/docker-phpqa) project,
borrowing their original file so we can make some customizations. Once the project stabilizes we will
review for being able to just pull upstream and work with their images. 

## Starting a container

docker build -it secp256k1build .
docker run -it -v /path/to/output:/usr/src/php/lcov_html -v /path/to/secp256k1-php/secp256k1:/usr/src/php/ext/secp256k1 --name s1 secp256k1build

## supported versions

default: secp256k1-v7.1.7

supported:
* secp256k1-v7.1.7
* secp256k1-v7.2.20

## scripts!

#### ./build_container.sh

this command builds the container for us

versions can be chosen using PHPQA_PHP_VERSION in the environment

support for other php versions is added by updating the build_container.sh with
 - php version
 - gpg keys
 - sha256sum

#### ./container_command.sh $command

run $command in the container. 
versions can be chosen using PHPQA_PHP_VERSION in the environment