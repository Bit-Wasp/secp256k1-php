--TEST--
secp256k1_scratch_space_create errors if secp256k1 context is wrong resource type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$ctx = tmpfile();
var_dump(secp256k1_scratch_space_create($ctx, 1024));
?>
--EXPECT--
secp256k1_scratch_space_create(): supplied resource is not a valid secp256k1_context resource
NULL