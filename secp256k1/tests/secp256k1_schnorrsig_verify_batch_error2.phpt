--TEST--
secp256k1_schnorrsig_verify_batch errors when parameter parsing fails
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php
set_error_handler(function($code, $str) { echo $str . PHP_EOL; });
var_dump(secp256k1_schnorrsig_verify_batch());
?>
--EXPECT--
secp256k1_schnorrsig_verify_batch() expects exactly 6 parameters, 0 given
int(0)