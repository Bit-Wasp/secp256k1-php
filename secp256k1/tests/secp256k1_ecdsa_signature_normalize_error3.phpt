--TEST--
secp256k1_ecdsa_signature_normalize works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$sigIn = tmpfile();
$inputSig = null;
$result = secp256k1_ecdsa_signature_normalize($ctx, $inputSig, $sigIn);
echo gettype($result) . PHP_EOL;
echo ($result ? "true" : "false") . PHP_EOL;

?>
--EXPECT--
secp256k1_ecdsa_signature_normalize(): supplied resource is not a valid secp256k1_ecdsa_signature resource
boolean
false
