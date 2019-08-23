--TEST--
secp256k1_schnorrsig_verify works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_schnorrsig_verify")) print "skip no schnorrsig support";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$sigBin = pack("H*", "b8edb50a96431b8a15c71f128f1f9bc9dd2e01c75894f757d0ee4aa6a1ca60fc9753f61ce15907f7a1adcac85e3f93cb256c01d040b575b0bf74e8b9661a75fa");
$msg32 = hash('sha256', "a message", true);
$pubKeyBin = pack("H*", "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619");
$sig = null;
$pubKey = null;

$result = secp256k1_schnorrsig_parse($ctx, $sig, $sigBin);
echo $result.PHP_EOL;

$result = secp256k1_ec_pubkey_parse($ctx, $pubKey, $pubKeyBin);
echo $result.PHP_EOL;

$result = secp256k1_schnorrsig_verify($ctx, $sig, $msg32, $pubKey);
echo $result.PHP_EOL;

?>
--EXPECT--
1
1
1