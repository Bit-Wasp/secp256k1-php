--TEST--
secp256k1_schnorrsig_sign with secp256k1_nonce_function_bip340 matches default
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_schnorrsig_verify")) print "skip no schnorrsig support";
?>
--FILE--
<?php

$msg32 = \pack("H*", "9e5755ec2f328cc8635a55415d0e9a09c2b6f2c9b0343c945fbbfe08247a4cbe");
$priv = \pack("H*", "31a84594060e103f5a63eb742bd46cf5f5900d8406e2726dedfc61c7cf43ebad");

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$keypair = null;
$result = secp256k1_keypair_create($ctx, $keypair, $priv);
echo $result . PHP_EOL;

// use internal default:
$sigOut = null;
$result = secp256k1_schnorrsig_sign($ctx, $sigOut, $msg32, $keypair);
echo $result . PHP_EOL;
$sig1 = unpack("H*", $sigOut)[1];

// use PHP exposed function
$sigOut = null;
$result = secp256k1_schnorrsig_sign($ctx, $sigOut, $msg32, $keypair, 'secp256k1_nonce_function_bip340');
echo $result . PHP_EOL;

$sig2 = unpack("H*", $sigOut)[1];
echo "Signatures are equal: " . ((int) ($sig1 == $sig2));
?>
--EXPECT--
1
1
1
Signatures are equal: 1