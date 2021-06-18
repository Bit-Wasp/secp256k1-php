--TEST--
secp256k1_schnorrsig_sign works with bip vector 3
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_schnorrsig_verify")) print "skip no schnorrsig support";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

//https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
$privKey = hex2bin("0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710");
//25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517

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

$auxRand = hex2bin("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
$sig64 = null;
$msg32 = hex2bin("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");

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
25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517
1
7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3
1