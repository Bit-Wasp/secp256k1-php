--TEST--
secp256k1_keypair_create errors on invalid parameters
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php
set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$result = secp256k1_keypair_create();
echo $result . PHP_EOL;

?>
--EXPECT--
secp256k1_keypair_create() expects exactly 3 parameters, 0 given
0