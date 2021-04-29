--TEST--
secp256k1_schnorrsig_sign works with bip vector 0
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_schnorrsig_verify")) print "skip no schnorrsig support";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

//https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
$privKey = hex2bin("0000000000000000000000000000000000000000000000000000000000000003");
//F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9

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

$auxRand = hex2bin("0000000000000000000000000000000000000000000000000000000000000000");
$sig64 = null;
$msg32 = hex2bin("0000000000000000000000000000000000000000000000000000000000000000");

$result = secp256k1_schnorrsig_sign($ctx, $sig64, $msg32, $keypair, 'secp256k1_nonce_function_bip340', $auxRand);
echo $result . PHP_EOL;

echo strtoupper(unpack("H*", $sig64)[1]) . PHP_EOL;

?>
--EXPECT--
1
1
1
F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9
1
E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0