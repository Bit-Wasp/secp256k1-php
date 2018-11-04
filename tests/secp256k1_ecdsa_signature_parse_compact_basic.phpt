--TEST--
secp256k1_ecdsa_signature_parse_compact works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$sig = hex2bin("7a8e3bdc7c64f31b119a849e8bb39ddbdc0a64abd4cadcc5cfc15d3ec06354ed4719389aedb16b2dd13552eed546b24350d6e636ac454ea72afc1ffd0cf421b7");
$secp256k1Sig = null;
$result = secp256k1_ecdsa_signature_parse_compact($ctx, $secp256k1Sig, $sig);
echo $result . PHP_EOL;

?>
--EXPECT--
1
