--TEST--
secp256k1_context_destroy works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php
$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
echo get_resource_type($ctx) . "\n";

secp256k1_context_destroy($ctx);
echo get_resource_type($ctx) . "\n";
?>
--EXPECT--
secp256k1_context
Unknown
