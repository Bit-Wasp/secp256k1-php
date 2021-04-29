--TEST--
secp256k1_nonce_function_bip340 throws if parameters have the wrong length
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

try {
    secp256k1_nonce_function_bip340($output, substr($msg32, 0, 31), $key32, $xonlyPubKey32, $algo16, $auxRand);
} catch (\Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}
try {
    secp256k1_nonce_function_bip340($output, $msg32, substr($key32, 0, 31), $xonlyPubKey32, $algo16, $auxRand);
} catch (\Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}
try {
    secp256k1_nonce_function_bip340($output, $msg32, $key32, substr($xonlyPubKey32, 0, 31), $algo16, $auxRand);
} catch (\Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}
try {
    secp256k1_nonce_function_bip340($output, $msg32, $key32, $xonlyPubKey32, substr($algo16, 0, 15), $auxRand);
} catch (\Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}
?>
--EXPECT--
secp256k1_nonce_function_bip340(): Parameter 2 should be 32 bytes
secp256k1_nonce_function_bip340(): Parameter 3 should be 32 bytes
secp256k1_nonce_function_bip340(): Parameter 4 should be 32 bytes
secp256k1_nonce_function_bip340(): Parameter 5 should be 16 bytes