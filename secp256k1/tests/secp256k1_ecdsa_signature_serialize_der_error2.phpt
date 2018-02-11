--TEST--
secp256k1_ecdsa_signature_serialize_der returns false if signature is wrong resource type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
$sig = hex2bin("304402207a8e3bdc7c64f31b119a849e8bb39ddbdc0a64abd4cadcc5cfc15d3ec06354ed02204719389aedb16b2dd13552eed546b24350d6e636ac454ea72afc1ffd0cf421b7");
$secp256k1Sig = null;
$result = secp256k1_ecdsa_signature_parse_der($ctx, $secp256k1Sig, $sig);
echo $result . PHP_EOL;
echo get_resource_type($secp256k1Sig) . PHP_EOL;

$ctxBad = tmpfile();
$sigOut = null;
$result = secp256k1_ecdsa_signature_serialize_der($ctxBad, $sigOut, $secp256k1Sig);
echo gettype($result) . PHP_EOL;
echo ($result ? "true" : "false") . PHP_EOL;

?>
--EXPECT--
1
secp256k1_ecdsa_signature
secp256k1_ecdsa_signature_serialize_der(): supplied resource is not a valid secp256k1_context resource
boolean
false
