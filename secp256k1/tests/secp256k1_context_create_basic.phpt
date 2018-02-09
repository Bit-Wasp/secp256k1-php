--TEST--
secp256k1_context_create works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$ctx1 = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
echo get_resource_type($ctx1) . "\n";
$ctx2 = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
echo get_resource_type($ctx2) . "\n";
$ctx3 = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
echo get_resource_type($ctx3) . "\n";
?>
--EXPECT--
secp256k1_context
secp256k1_context
secp256k1_context
