--TEST--
secp256k1_nonce_function_bip340 returns a result
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_schnorrsig_verify")) print "skip no schnorrsig support";
?>
--FILE--
<?php

$output = '';
$msg32 = hex2bin("0000000000000000000000000000000000000000000000000000000000000000");
$key32 = hex2bin("0000000000000000000000000000000000000000000000000000000000000003");
$xonlyPubKey32 = hex2bin("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
$algo16 = "BIP0340/nonce\x00\x00\x00";
$auxRand = hex2bin("0000000000000000000000000000000000000000000000000000000000000000");

$result = secp256k1_nonce_function_bip340($output, $msg32, $key32, $xonlyPubKey32, $algo16, $auxRand);
echo $result . PHP_EOL;
echo unpack("H*", $output)[1] . PHP_EOL;

?>
--EXPECT--
1
1d2dc1652fee3ad08434469f9ad30536a5787feccfa308e8fb396c8030dd1c69