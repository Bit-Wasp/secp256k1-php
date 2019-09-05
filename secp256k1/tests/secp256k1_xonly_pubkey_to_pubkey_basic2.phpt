--TEST--
secp256k1_xonly_pubkey_to_pubkey works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$pubKeyIn = hex2bin("24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c");
$sign = 0;
$pubkey = null;
$xonlyPubKey = null;

$result = secp256k1_xonly_pubkey_parse($ctx, $xonlyPubKey, $pubKeyIn);
echo $result . PHP_EOL;
echo get_resource_type($xonlyPubKey) . PHP_EOL;

$result = secp256k1_xonly_pubkey_to_pubkey($ctx, $pubkey, $xonlyPubKey, $sign);
echo $result . PHP_EOL;

$serialized = null;
$result = secp256k1_ec_pubkey_serialize($ctx, $serialized, $pubkey, SECP256K1_EC_COMPRESSED);
echo $result . PHP_EOL;

echo bin2hex($serialized) . PHP_EOL;

?>
--EXPECT--
1
secp256k1_xonly_pubkey
1
1
0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c