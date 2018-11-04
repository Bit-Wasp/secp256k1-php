--TEST--
secp256k1_ecdsa_signature_parse_compact returns false if signature is wrong size
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$sig = "sig";
$secp256k1Sig = null;
try {
    secp256k1_ecdsa_signature_parse_compact($ctx, $secp256k1Sig, $sig);
} catch (\Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}

?>
--EXPECT--
secp256k1_ecdsa_signature_parse_compact(): Parameter 3 should be 64 bytes
