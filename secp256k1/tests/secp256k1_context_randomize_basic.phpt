--TEST--
secp256k1_context_randomize works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php
$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
echo get_resource_type($ctx) . "\n";

$state1 = str_repeat("\x42", 32);
$result = secp256k1_context_randomize($ctx, $state1);
echo $result . PHP_EOL;

// reset operation
$result = secp256k1_context_randomize($ctx, null);
echo $result . PHP_EOL;

// reset operation (implicit)
$result = secp256k1_context_randomize($ctx);
echo $result . PHP_EOL;

?>
--EXPECT--
secp256k1_context
1
1
1
