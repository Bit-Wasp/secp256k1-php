--TEST--
secp256k1_nonce_function_bipschnorr returns 0 if data string length is not 32
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_schnorrsig_verify")) print "skip no schnorrsig support";
?>
--FILE--
<?php

$output = '';
$msg32 = str_repeat('A', 32);
$key32 = str_repeat('Z', 32);

$result = secp256k1_nonce_function_bipschnorr($output, $msg32, $key32, $_algo=str_repeat("W", 16), $_data=str_repeat("Y", 31), $_attempt=0);
echo $result . PHP_EOL;

$result = secp256k1_nonce_function_bipschnorr($output, $msg32, $key32, $_algo=str_repeat("W", 16), $_data=str_repeat("Y", 33), $_attempt=0);
echo $result . PHP_EOL;

$result = secp256k1_nonce_function_bipschnorr($output, $msg32, $key32, $_algo=str_repeat("W", 16), $_data=str_repeat("Y", 32), $_attempt=0);
echo $result . PHP_EOL;

?>
--EXPECT--
0
0
1