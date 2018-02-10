phpqa container
===============

This Dockerfile was inspired by the [docker-phpqa](https://github.com/herdphp/docker-phpqa) project,
borrowing their original file so we can make some customizations. Once the project stabilizes we will
review for being able to just pull upstream and work with their images. 

# Starting a container

docker build -it secp256k1build .
docker run -it -v /path/to/output:/usr/src/php/lcov_html -v /path/to/secp256k1-php/secp256k1:/usr/src/php/ext/secp256k1 --name s1 secp256k1build
