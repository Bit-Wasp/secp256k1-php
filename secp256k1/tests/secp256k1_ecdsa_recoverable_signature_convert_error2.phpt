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
$sigIn = pack("H*", 'fe5fe404f3d8c21e1204a08c38ff3912d43c5a22541d2f1cdc4977cbcad240015a3b6e9040f62cacf016df4fef9412091592e4908e5e3a7bd2a42a4d1be01951');

/** @var resource $signature */
$signature = null;
$result = secp256k1_ecdsa_recoverable_signature_parse_compact($context, $signature, $sigIn, $recid);
echo $result . PHP_EOL;

$badCtx = tmpfile();
// Convert secp256k1_ecdsa_recoverable_signature -> secp256k1_ecdsa_signature
/** @var resource $convertedSig */
$convertedSig = null;
$result = secp256k1_ecdsa_recoverable_signature_convert($badCtx, $convertedSig, $signature);
echo gettype($result) . PHP_EOL;
echo ($result ? "true" : "false") . PHP_EOL;

?>
--EXPECT--
1
secp256k1_ecdsa_recoverable_signature_convert(): supplied resource is not a valid secp256k1_context resource
boolean
false
