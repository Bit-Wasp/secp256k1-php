--TEST--
secp256k1_ecdsa_recoverable_signature_parse_compact returns false on bad sig
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$recid = 1;
$sigIn = pack("H*", 'bcad240015a3b6e9040f62cacf016df4fef9412091592e4908e5e3a7bd2a42a4d1be01951');
$signature = null;

try {
    secp256k1_ecdsa_recoverable_signature_parse_compact($context, $signature, $sigIn, $recid);
} catch (\Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}
?>
--EXPECT--
secp256k1_ecdsa_recoverable_signature_parse_compact(): Parameter 3 should be 64 bytes