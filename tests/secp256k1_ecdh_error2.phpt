--TEST--
secp256k1_ecdh errors with 0 key
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
$priv1 = str_pad('', 32, "\x41");
$priv2 = str_pad('', 32, "\x00");

/** @var resource $pub1 */
$pub1 = null;
$result = \secp256k1_ec_pubkey_create($context, $pub1, $priv1);
echo $result . PHP_EOL;

$secret = '';
$result = \secp256k1_ecdh($context, $secret, $pub1, $priv2);
echo $result . PHP_EOL;

?>
--EXPECT--
1
0
