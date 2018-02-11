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
$sigIn = tmpfile();

$sigOut = '';
$result = secp256k1_ecdsa_signature_serialize_der($ctx, $sigOut, $sigIn);
echo gettype($result) . PHP_EOL;
echo ($result ? "true" : "false") . PHP_EOL;

?>
--EXPECT--
secp256k1_ecdsa_signature_serialize_der(): supplied resource is not a valid secp256k1_ecdsa_signature resource
boolean
false
