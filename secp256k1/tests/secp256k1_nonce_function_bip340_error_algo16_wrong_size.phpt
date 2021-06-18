--TEST--
secp256k1_nonce_function_bip340 returns 0 if algo16 is neither NULL, or a 16 byte string
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
$auxRand = hex2bin("0000000000000000000000000000000000000000000000000000000000000000");

try {
    secp256k1_nonce_function_bip340($output, $msg32, $key32, $xonlyPubKey32, $algo16 = "BIP0340/nonce\x00\x00", $auxRand); // 15
} catch (\Exception $e) {
    echo $e->getMessage().PHP_EOL;
}


try {
    secp256k1_nonce_function_bip340($output, $msg32, $key32, $xonlyPubKey32, $algo16 = "BIP0340/nonce\x00\x00\x00\x00", $auxRand); // 17
} catch (\Exception $e) {
    echo $e->getMessage().PHP_EOL;
}

$result = secp256k1_nonce_function_bip340($output, $msg32, $key32, $xonlyPubKey32, $algo16 = "BIP0340/nonce\x00\x00\x00", $auxRand); // 16
echo $result . PHP_EOL;
echo unpack("H*", $output)[1] . PHP_EOL;
?>
--EXPECT--
secp256k1_nonce_function_bip340(): Parameter 5 should be 16 bytes
secp256k1_nonce_function_bip340(): Parameter 5 should be 16 bytes
1
1d2dc1652fee3ad08434469f9ad30536a5787feccfa308e8fb396c8030dd1c69