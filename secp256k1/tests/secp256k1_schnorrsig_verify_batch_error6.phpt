--TEST--
secp256k1_schnorrsig_verify_batch errors when the signature array has the wrong type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_schnorrsig_verify")) print "skip no schnorrsig support";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$sigBin1 = pack("H*", "21aedc76051415c8d083683842e5bab7995580f9df8ce703234893d14b8d0fa7e852bee5e7eb94dd11d70185bcaa7ef67aafe28ebc109ee63353c182330be2de");
$msg321 = hash('sha256', "a message", true);
$msg322 = hash('sha256', "another message", true);
$pubKeyBin1 = pack("H*", "eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619");
$pubKeyBin2 = pack("H*", "62cd4a67842524034e9b3f313feab032bdb4858588c193bc26ce9f380321ef79");
$sig1 = null;
$pubKey1 = null;
$pubKey2 = null;

echo "setup:\n";

$result = secp256k1_schnorrsig_parse($ctx, $sig1, $sigBin1);
echo $result.PHP_EOL;

$result = secp256k1_xonly_pubkey_parse($ctx, $pubKey1, $pubKeyBin1);
echo $result.PHP_EOL;

$result = secp256k1_xonly_pubkey_parse($ctx, $pubKey2, $pubKeyBin2);
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