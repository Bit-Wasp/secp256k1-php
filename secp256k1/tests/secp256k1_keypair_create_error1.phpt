--TEST--
secp256k1_keypair_create errors if key parameter is not 32 bytes
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_schnorrsig_verify")) print "skip no schnorrsig support";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$priv = \pack("H*", "cf5f5900d8406e2726dedfc61c7cf43ebad");

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$keypair = null;
try {
    secp256k1_keypair_create($ctx, $keypair, $priv);
} catch (\Exception $e) {
    echo $e->getMessage().PHP_EOL;
}

?>
--EXPECT--
secp256k1_keypair_create(): Parameter 3 should be 32 bytes