--TEST--
secp256k1_ecdsa_recoverable_signature_parse_compact returns false on bad recid
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$recid = 10;
$sigIn = pack("H*", 'fe5fe404f3d8c21e1204a08c38ff3912d43c5a22541d2f1cdc4977cbcad240015a3b6e9040f62cacf016df4fef9412091592e4908e5e3a7bd2a42a4d1be01951');
$signature = null;

try {
    secp256k1_ecdsa_recoverable_signature_parse_compact($context, $signature, $sigIn, $recid);
} catch (\Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}
?>
--EXPECT--
secp256k1_ecdsa_recoverable_signature_parse_compact(): recid should be between 0-3