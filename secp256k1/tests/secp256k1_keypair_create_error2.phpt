--TEST--
secp256k1_keypair_create fails when seckey is invalid
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_schnorrsig_verify")) print "skip no schnorrsig support";
?>
--FILE--
<?php

$priv = \pack("H*", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

$ctx = \secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$keypair = null;
$result = secp256k1_keypair_create($ctx, $keypair, $priv);
echo $result . PHP_EOL;

?>
--EXPECT--
0