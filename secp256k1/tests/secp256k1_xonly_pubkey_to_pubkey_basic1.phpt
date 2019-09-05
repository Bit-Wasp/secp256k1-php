--TEST--
secp256k1_xonly_pubkey_to_pubkey works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$pubKeyIn = hex2bin("eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619");
$sign = 1;
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
02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619