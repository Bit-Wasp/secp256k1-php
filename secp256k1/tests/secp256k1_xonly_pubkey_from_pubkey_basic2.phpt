--TEST--
secp256k1_xonly_pubkey_from_pubkey works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$privKey = str_repeat("\x42", 32);
//0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c

$pubkey = null;
$xonlyPubKey = null;
$sign = null;
$pubkey2 = null;
$result = secp256k1_ec_pubkey_create($ctx, $pubkey, $privKey);
echo $result . PHP_EOL;
echo get_resource_type($pubkey) . PHP_EOL;

$result = secp256k1_xonly_pubkey_from_pubkey($ctx, $xonlyPubKey, $sign, $pubkey);
echo $result . PHP_EOL;

echo "sign: $sign\n";

$serialized = null;
$result = secp256k1_xonly_pubkey_serialize($ctx, $serialized, $xonlyPubKey);
echo $result . PHP_EOL;

echo bin2hex($serialized) . PHP_EOL;

?>
--EXPECT--
1
secp256k1_pubkey
1
sign: 0
1
24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c