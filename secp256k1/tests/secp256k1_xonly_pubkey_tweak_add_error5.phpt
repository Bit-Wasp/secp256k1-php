--TEST--
secp256k1_xonly_pubkey_tweak_add operation can fail due to input (tweak overflows scalar)
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY);

$pubkey1 = null;
$pubkey2 = null;
$tweakedPub = null;
$privKey1 = str_repeat("\x42", 32);
$tweakOverflow = str_repeat("\xff", 32);

$result = secp256k1_xonly_pubkey_create($ctx, $pubkey1, $privKey1);
echo $result . PHP_EOL;
echo get_resource_type($pubkey1) . PHP_EOL;

$isPositive = null;
$result = secp256k1_xonly_pubkey_tweak_add($ctx, $tweakedPub, $isPositive, $pubkey1, $tweakOverflow);
echo $result . PHP_EOL;

?>
--EXPECT--
1
secp256k1_xonly_pubkey
0