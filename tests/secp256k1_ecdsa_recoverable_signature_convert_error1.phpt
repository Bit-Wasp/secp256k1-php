--TEST--
secp256k1_ecdsa_recoverable_signature_convert returns false if parameter parsing fails
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$result = secp256k1_ecdsa_recoverable_signature_convert();
echo $result . PHP_EOL;

?>
--EXPECT--
secp256k1_ecdsa_recoverable_signature_convert() expects exactly 3 parameters, 0 given
0