--TEST--
secp256k1_ecdsa_recoverable_signature_serialize_compact returns false when context is wrong resource type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$recid = 1;
$sigIn = pack("H*", 'fe5fe404f3d8c21e1204a08c38ff3912d43c5a22541d2f1cdc4977cbcad240015a3b6e9040f62cacf016df4fef9412091592e4908e5e3a7bd2a42a4d1be01951');

/** @var resource $signature */
$signature = null;
$result = secp256k1_ecdsa_recoverable_signature_parse_compact($context, $signature, $sigIn, $recid);
echo $result . PHP_EOL;

$ctxBad = tmpfile();
$sigOut = '';
$result = secp256k1_ecdsa_recoverable_signature_serialize_compact($ctxBad, $signature, $sigOut, $recid);
echo $result . PHP_EOL;
echo unpack("H*", $sigOut)[1] . PHP_EOL;

?>
--EXPECT--
1
secp256k1_ecdsa_recoverable_signature_serialize_compact(): supplied resource is not a valid secp256k1_context resource
