--TEST--
secp256k1_ecdsa_recoverable_signature_convert returns false when context is wrong type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$privKey = hash('sha256', 'private key', true);
$msg32 = hash('sha256', 'msg', true);

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$recid = 1;
$signature = tmpfile();

// Convert secp256k1_ecdsa_recoverable_signature -> secp256k1_ecdsa_signature
/** @var resource $convertedSig */
$convertedSig = null;
$result = secp256k1_ecdsa_recoverable_signature_convert($context, $convertedSig, $signature);
echo gettype($result) . PHP_EOL;
echo ($result ? "true" : "false") . PHP_EOL;

?>
--EXPECT--
secp256k1_ecdsa_recoverable_signature_convert(): supplied resource is not a valid secp256k1_ecdsa_recoverable_signature resource
boolean
false
