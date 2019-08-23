--TEST--
secp256k1_ecdsa_sign_recoverable returns false if parameter parsing fails
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_ecdsa_recover")) print "skip no recovery support";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$result = secp256k1_ecdsa_sign_recoverable();
echo $result . PHP_EOL;

?>
--EXPECT--
secp256k1_ecdsa_sign_recoverable() expects exactly 4 parameters, 0 given
0