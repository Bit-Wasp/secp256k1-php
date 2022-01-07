--TEST--
secp256k1_nonce_function_bip340 returns 0 if data is neither NULL, or a 32 byte string
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

$result = secp256k1_nonce_function_bip340($output, $msg32, $key32, $xonlyPubKey32, $algo16, new stdClass());
echo $result . PHP_EOL;

$result = secp256k1_nonce_function_bip340($output, $msg32, $key32, $xonlyPubKey32, $algo16, 1);
echo $result . PHP_EOL;

$result = secp256k1_nonce_function_bip340($output, $msg32, $key32, $xonlyPubKey32, $algo16, []);
echo $result . PHP_EOL;

?>
--EXPECT--
0
0
0