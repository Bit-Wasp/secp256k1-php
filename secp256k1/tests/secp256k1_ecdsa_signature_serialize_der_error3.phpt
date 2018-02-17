--TEST--
secp256k1_ecdsa_signature_serialize_der returns false if signature is not a resource
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
$sigIn = hex2bin("304402207a8e3bdc7c64f31b119a849e8bb39ddbdc0a64abd4cadcc5cfc15d3ec06354ed02204719389aedb16b2dd13552eed546b24350d6e636ac454ea72afc1ffd0cf421b7");

$sigOut = null;
try {
    secp256k1_ecdsa_signature_serialize_der($ctx, $sigOut, $sigIn);
} catch (\TypeError $e) {
    echo $e->getMessage() . PHP_EOL;
}

?>
--EXPECT--
Argument 3 passed to secp256k1_ecdsa_signature_serialize_der() must be of the type resource, string given
