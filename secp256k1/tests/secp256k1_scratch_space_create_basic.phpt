--TEST--
secp256k1_scratch_space_create works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$size = 1024;
$result = secp256k1_scratch_space_create($ctx, $size);
echo get_resource_type($result) . "\n";

?>
--EXPECT--
secp256k1_scratch_space