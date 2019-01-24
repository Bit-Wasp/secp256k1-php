--TEST--
secp256k1_context_clone works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php
$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
echo get_resource_type($ctx) . "\n";

$clone = secp256k1_context_clone($ctx);
echo get_resource_type($clone) . "\n";
?>
--EXPECT--
secp256k1_context
secp256k1_context
