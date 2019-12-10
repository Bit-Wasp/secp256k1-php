--TEST--
secp256k1_xonly_pubkey_parse rejects invalid keys
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$pubKeyIn = pack("H*", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");

$pubKey = null;
$pubKeyOut = '';
$result = secp256k1_xonly_pubkey_parse($ctx, $pubKey, $pubKeyIn);
echo $result . PHP_EOL;

?>
--EXPECT--
0
