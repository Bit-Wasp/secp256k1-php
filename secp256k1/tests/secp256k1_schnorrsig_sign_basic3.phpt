--TEST--
secp256k1_schnorrsig_sign works with bip vector 2
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_schnorrsig_verify")) print "skip no schnorrsig support";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

//https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
$privKey = hex2bin("C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9");
//DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8

$keypair = null;
$result = secp256k1_keypair_create($ctx, $keypair, $privKey);
echo $result.PHP_EOL;

$xonlyPubKey = null;
$parity = null;
$result = secp256k1_keypair_xonly_pub($ctx, $xonlyPubKey, $parity, $keypair);
echo $result.PHP_EOL;

$xonlyOutput32 = null;
$result = secp256k1_xonly_pubkey_serialize($ctx, $xonlyOutput32, $xonlyPubKey);
echo $result.PHP_EOL;

echo strtoupper(unpack("H*", $xonlyOutput32)[1]) . PHP_EOL;

$auxRand = hex2bin("C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906");
$sig64 = null;
$msg32 = hex2bin("7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C");

$result = secp256k1_schnorrsig_sign($ctx, $sig64, $msg32, $keypair, 'secp256k1_nonce_function_bip340', $auxRand);
echo $result . PHP_EOL;

echo strtoupper(unpack("H*", $sig64)[1]) . PHP_EOL;

$result = secp256k1_schnorrsig_verify($ctx, $sig64, $msg32, $xonlyPubKey);
echo $result . PHP_EOL;

?>
--EXPECT--
1
1
1
DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8
1
5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7
1