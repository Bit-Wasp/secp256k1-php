--TEST--
secp256k1_ec_privkey_tweak_add returns false if modified parameter is not a string
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$secKeyFirst = 1;
$secKeyTwo = str_repeat("\x00", 31) . "\x02";

try {
    \secp256k1_ec_privkey_tweak_add($context, $secKeyFirst, $secKeyTwo);
} catch (\Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}

?>
--EXPECT--
secp256k1_ec_privkey_tweak_add(): Parameter 2 should be string