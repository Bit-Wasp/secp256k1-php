--TEST--
secp256k1_ecdsa_signature_parse_der errors signature is garbage
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$ctx = \secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$sig = \hex2bin("3001024242");
$secp256k1Sig = null;
$result = \secp256k1_ecdsa_signature_parse_der($ctx, $secp256k1Sig, $sig);
echo $result . PHP_EOL;

?>
--EXPECT--
0