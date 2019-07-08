--TEST--
secp256k1_schnorrsig_verify_batch errors when the signature array has the wrong type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$sigBin1 = pack("H*", "b8edb50a96431b8a15c71f128f1f9bc9dd2e01c75894f757d0ee4aa6a1ca60fc9753f61ce15907f7a1adcac85e3f93cb256c01d040b575b0bf74e8b9661a75fa");
$msg321 = hash('sha256', "a message", true);
$msg322 = hash('sha256', "another message", true);
$pubKeyBin1 = pack("H*", "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619");
$pubKeyBin2 = pack("H*", "0262cd4a67842524034e9b3f313feab032bdb4858588c193bc26ce9f380321ef79");
$sig1 = null;
$pubKey1 = null;
$pubKey2 = null;

echo "setup:\n";

$result = secp256k1_schnorrsig_parse($ctx, $sig1, $sigBin1);
echo $result.PHP_EOL;

$result = secp256k1_ec_pubkey_parse($ctx, $pubKey1, $pubKeyBin1);
echo $result.PHP_EOL;

$result = secp256k1_ec_pubkey_parse($ctx, $pubKey2, $pubKeyBin2);
echo $result.PHP_EOL;

$scratch = secp256k1_scratch_space_create($ctx, 1024 * 1024 * 1024 * 1);
echo $result.PHP_EOL;

echo "tests:\n";

$sig2 = tmpfile();
$result = secp256k1_schnorrsig_verify_batch(
    $ctx, $scratch, [$sig1, $sig2], [$msg321, $msg322], [$pubKey1, $pubKey2], 2);
echo $result.PHP_EOL;

?>
--EXPECT--
setup:
1
1
1
1
tests:
secp256k1_schnorrsig_verify_batch(): supplied resource is not a valid secp256k1_schnorrsig resource
0