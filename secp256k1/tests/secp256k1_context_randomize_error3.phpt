--TEST--
secp256k1_context_randomize throws an exception if not byte32/null
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php
$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
echo get_resource_type($ctx) . "\n";

$state1 = 1;
try {
    \secp256k1_context_randomize($ctx, $state1);
} catch (\Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}

?>
--EXPECT--
secp256k1_context
secp256k1_context_randomize(): Parameter 2 should be a 32 byte string, or null