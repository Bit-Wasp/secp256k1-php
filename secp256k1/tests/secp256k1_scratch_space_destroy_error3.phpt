--TEST--
secp256k1_scratch_space_destroy works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$badScratch = tmpfile();
var_dump(secp256k1_scratch_space_destroy($ctx, $badScratch));
?>
--EXPECT--
secp256k1_scratch_space_destroy(): supplied resource is not a valid secp256k1_scratch_space resource
bool(false)