--TEST--
Check for libsecp256k1 context clone function
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php
$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
echo get_resource_type($ctx) . "\n";

$result = secp256k1_context_randomize($ctx);
echo $result . PHP_EOL;
?>
--EXPECT--
secp256k1_context
1
