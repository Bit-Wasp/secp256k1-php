--TEST--
secp256k1_ecdsa_signature_normalize returns false if missing context argument
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$result = secp256k1_ecdsa_signature_normalize();
echo $result . PHP_EOL;

?>
--EXPECT--
secp256k1_ecdsa_signature_normalize() expects exactly 3 parameters, 0 given
0