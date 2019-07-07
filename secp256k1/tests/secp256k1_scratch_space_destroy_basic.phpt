--TEST--
secp256k1_scratch_space_destroy works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$size = 1024;
$scratch = secp256k1_scratch_space_create($ctx, $size);
echo get_resource_type($scratch) . "\n";

var_dump(secp256k1_scratch_space_destroy($ctx, $scratch));
?>
--EXPECT--
secp256k1_scratch_space
bool(true)