--TEST--
secp256k1_ec_seckey_verify errors if context is wrong resource type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$result = secp256k1_ec_seckey_verify();
echo gettype($result) . PHP_EOL;
echo ($result ? "true" : "false") . PHP_EOL;

?>
--EXPECT--
secp256k1_ec_seckey_verify() expects exactly 2 parameters, 0 given
boolean
false
