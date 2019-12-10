--TEST--
secp256k1_schnorrsig_verify_batch errors if msg32 has a non-string in the array
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_schnorrsig_verify")) print "skip no schnorrsig support";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$sigBin1 = pack("H*", "21aedc76051415c8d083683842e5bab7995580f9df8ce703234893d14b8d0fa7e852bee5e7eb94dd11d70185bcaa7ef67aafe28ebc109ee63353c182330be2de");
$sigBin2 = pack("H*", "b2579a4e31562773bf4b3717527013f9e996f0a712b4606321f16e705b9a5e179b6cd094edfcfcb1cd82c1ac46e496423fc51a9a8f4fbcde4f8b9bc8207f6c87");
$msg321 = hash('sha256', "a message", true);
$pubKeyBin1 = pack("H*", "eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619");
$pubKeyBin2 = pack("H*", "62cd4a67842524034e9b3f313feab032bdb4858588c193bc26ce9f380321ef79");
$sig1 = null;
$sig2 = null;
$pubKey1 = null;
$pubKey2 = null;

echo "setup:\n";

$result = secp256k1_schnorrsig_parse($ctx, $sig1, $sigBin1);
echo $result.PHP_EOL;

$result = secp256k1_schnorrsig_parse($ctx, $sig2, $sigBin2);
echo $result.PHP_EOL;

$result = secp256k1_xonly_pubkey_parse($ctx, $pubKey1, $pubKeyBin1);
echo $result.PHP_EOL;

$result = secp256k1_xonly_pubkey_parse($ctx, $pubKey2, $pubKeyBin2);
echo $result.PHP_EOL;

$scratch = secp256k1_scratch_space_create($ctx, 1024 * 1024 * 1024 * 1);
echo $result.PHP_EOL;

echo "tests:\n";

$result = secp256k1_schnorrsig_verify_batch(
    $ctx, $scratch, [$sig1, $sig2], [$msg321, 1], [$pubKey1, $pubKey2], 2);
echo $result.PHP_EOL;

?>
--EXPECT--
setup:
1
1
1
1
1
tests:
0