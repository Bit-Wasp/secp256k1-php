--TEST--
secp256k1_schnorrsig_sign returns int 0 if parameter parsing fails
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_schnorrsig_verify")) print "skip no schnorrsig support";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$result = secp256k1_schnorrsig_sign();
echo $result . PHP_EOL;

?>
--EXPECT--
secp256k1_schnorrsig_sign() expects at least 4 parameters, 0 given
0
