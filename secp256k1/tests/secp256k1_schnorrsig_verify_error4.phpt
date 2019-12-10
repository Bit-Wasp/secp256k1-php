--TEST--
secp256k1_schnorrsig_verify returns an error on invalid input
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_schnorrsig_verify")) print "skip no schnorrsig support";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$sigBin1 = pack("H*", "21aedc76051415c8d083683842e5bab7995580f9df8ce703234893d14b8d0fa7e852bee5e7eb94dd11d70185bcaa7ef67aafe28ebc109ee63353c182330be2de");
$sigBin2 = pack("H*", "badbad0a96431b8a15c71f128f1f9bc9dd2e01c75894f757d0ee4aa6a1ca60fc9753f61ce15907f7a1adcac85e3f93cb256c01d040b575b0bf74e8b9661a75fa");
$msg32a = hash('sha256', "a message", true);
$msg32b = hash('sha256', "b message", true);
$pubKeyBin1 = pack("H*", "eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619");
$pubKeyBin2 = pack("H*", "62cd4a67842524034e9b3f313feab032bdb4858588c193bc26ce9f380321ef79");
$sig1 = null;
$sig2 = null;
$pubKey1 = null;

$result = secp256k1_schnorrsig_parse($ctx, $sig1, $sigBin1);
echo $result.PHP_EOL;

$result = secp256k1_schnorrsig_parse($ctx, $sig2, $sigBin2);
echo $result.PHP_EOL;

$result = secp256k1_xonly_pubkey_parse($ctx, $pubKey1, $pubKeyBin1);
echo $result.PHP_EOL;

$result = secp256k1_xonly_pubkey_parse($ctx, $pubKey2, $pubKeyBin2);
echo $result.PHP_EOL;

$result = secp256k1_schnorrsig_verify($ctx, $sig1, $msg32a, $pubKey1);
echo $result.PHP_EOL;

$result = secp256k1_schnorrsig_verify($ctx, $sig1, $msg32a, $pubKey2);
echo $result.PHP_EOL;

$result = secp256k1_schnorrsig_verify($ctx, $sig1, $msg32b, $pubKey1);
echo $result.PHP_EOL;

$result = secp256k1_schnorrsig_verify($ctx, $sig2, $msg32a, $pubKey1);
echo $result.PHP_EOL;

?>
--EXPECT--
1
1
1
1
1
0
0
0