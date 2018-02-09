--TEST--
secp256k1_ec_pubkey_create returns -1 if seckey isn't valid
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$secKeyOrder = pack("H*", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

$pub = null;
$result = secp256k1_ec_pubkey_create($context, $pub, $secKeyOrder);
echo $result . PHP_EOL;

?>
--EXPECT--
0
