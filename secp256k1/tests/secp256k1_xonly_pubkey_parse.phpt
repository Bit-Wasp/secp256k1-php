--TEST--
secp256k1_xonly_pubkey_parse works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$pubKeyIn = pack("H*", "eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619");

$pubKey = null;
$pubKeyOut = '';
$result = secp256k1_xonly_pubkey_parse($ctx, $pubKey, $pubKeyIn);
echo $result . PHP_EOL;
echo get_resource_type($pubKey) . PHP_EOL;

$result = secp256k1_xonly_pubkey_serialize($ctx, $pubKeyOut, $pubKey);
echo $result . PHP_EOL;
echo unpack("H*", $pubKeyOut)[1] . PHP_EOL;

?>
--EXPECT--
1
secp256k1_xonly_pubkey
1
eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619