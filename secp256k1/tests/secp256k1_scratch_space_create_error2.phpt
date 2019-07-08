--TEST--
secp256k1_scratch_space_create errors if parameter parsing fails
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

var_dump(secp256k1_scratch_space_create());
?>
--EXPECT--
secp256k1_scratch_space_create() expects exactly 2 parameters, 0 given
NULL