--TEST--
secp256k1_nonce_function_bipschnorr returns 0 if attempt != 0
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
$algo = NULL;

$result = secp256k1_nonce_function_bipschnorr($output, $msg32, $key32, $_algo=null, $_data=null, $_attempt=0);
echo $result . PHP_EOL;
echo unpack("H*", $output)[1] . PHP_EOL;

$result = secp256k1_nonce_function_bipschnorr($output, $msg32, $key32, $_algo=null, $_data=null, $_attempt=1);
echo $result . PHP_EOL;

?>
--EXPECT--
1
a0b9a53702d507e80caf8ff0a1b5803f47a26e1f5a4d5143aabb29705ada87ed
0