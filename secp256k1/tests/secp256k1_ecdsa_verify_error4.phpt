--TEST--
secp256k1_ecdsa_verify returns false when parameter parsing fails
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php
set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$result = secp256k1_ecdsa_verify();
echo $result . PHP_EOL;

?>
--EXPECT--
secp256k1_ecdsa_verify() expects exactly 4 parameters, 0 given
0