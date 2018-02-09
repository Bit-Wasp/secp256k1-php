--TEST--
ecdsa_signature_parse_der_lax errors if context is wrong resource type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$ctx = tmpfile();
$sig = hex2bin("304402207a8e3bdc7c64f31b119a849e8bb39ddbdc0a64abd4cadcc5cfc15d3ec06354ed02204719389aedb16b2dd13552eed546b24350d6e636ac454ea72afc1ffd0cf421b7");

// Parse signature using lax DER encoding
/** @var resource $laxSig */
$laxSig = null;
$result = ecdsa_signature_parse_der_lax($ctx, $laxSig, $sig);
echo gettype($result) . PHP_EOL;
echo ($result ? "true" : "false") . PHP_EOL;

?>
--EXPECT--
ecdsa_signature_parse_der_lax(): supplied resource is not a valid secp256k1_context resource
boolean
false