# secp256k1-php

PHP bindings for https://github.com/bitcoin/secp256k1

# About
This extension is a work-in-progress! Please create an issue or PR 
if you might be able to help, as currently some things aren't 100%. 
  
  - Currently has all functions from secp256k1 besides two - secp256k1_ec_sign_compact() and secp256k1_ec_recover_compact(). They will follow shortly. 
  - Seg fault in secp256k1_ec_pubkey_decompress() - not sure where this is coming from.
  - Positive tests are present for all currently added functions. The C library also has it's own tests, with some useful edge case tests, which will be ported soon. 
  - For now, tests likely need to be run individually 
  - It has mainly been tested on PHP5.6. 

# To Install:
```
    git clone git@github.com:afk11/secp256k1-php
    git clone git@github.com:bitcoin/secp256k1
    cd secp256k1
    ./autogen.sh && ./configure && make && sudo make install
    cd ../secp256k1-php/secp256k1
    phpize && ./configure --with-secp256k1 && make && sudo make install
```

# (Optional) - Enable extension by default!
If you're a heavy user, you can add this line to your php.ini files for php-cli, apache2, or php-fpm. 
```
extension=secp256k1.so
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
    or individually:
```
    php -dextension=secp256k1.so vendor/bin/phpunit tests/Secp256k1PubkeyVerifyTest.php
```
