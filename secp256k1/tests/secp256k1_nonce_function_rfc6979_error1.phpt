--TEST--
secp256k1_nonce_function_rfc6979 returns 0 if parameter parsing fails
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php
set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$output = '';
$msg32 = str_repeat('A', 32);
$key32 = str_repeat('Z', 32);
$algo = NULL;

$result = secp256k1_nonce_function_rfc6979();
echo $result . PHP_EOL;

?>
--EXPECT--
secp256k1_nonce_function_rfc6979() expects exactly 6 parameters, 0 given
0