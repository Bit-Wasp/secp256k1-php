--TEST--
secp256k1_schnorrsig_parse errors when signature is invalid
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_schnorrsig_verify")) print "skip no schnorrsig support";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$sig = hex2bin("7a");
$schnorrsig = null;
try {
    secp256k1_schnorrsig_parse($ctx, $schnorrsig, $sig);
} catch (\Exception $e) {
    echo $e->getMessage();
}
?>
--EXPECT--
secp256k1_schnorrsig_parse(): Parameter 3 should be 64 bytes