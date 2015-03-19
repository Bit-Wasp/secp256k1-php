# secp256k1-php

PHP bindings for https://github.com/bitcoin/secp256k1

# To Install:
```
    git clone git@github.com:afk11/secp256k1-php
    git clone git@github.com:bitcoin/secp256k1
    cd secp256k1
    ./autogen.sh && ./configure && make && sudo make install
    cd ../secp256k1-php/secp256k1
    phpize && ./configure --with-secp256k1 && make && sudo make install
```

# Run Benchmarks
```
    time php -dextension=secp256k1.so ../benchmark.php > /dev/null
```
Yes - it is FAST!

# Run Tests
```
    php -dextension=secp256k1.so vendor/bin/phpunit tests/
```
