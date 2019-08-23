--TEST--
secp256k1_schnorrsig_sign works with a different key
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_schnorrsig_verify")) print "skip no schnorrsig support";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$privKey = str_repeat("\x90", 32);
//0262cd4a67842524034e9b3f313feab032bdb4858588c193bc26ce9f380321ef79

$msg32 = hash('sha256', "another message", true);
$sig = null;
$sigOut = '';

$result = secp256k1_schnorrsig_sign($ctx, $sig, $msg32, $privKey);
echo $result.PHP_EOL;

$result = secp256k1_schnorrsig_serialize($ctx, $sigOut, $sig);
echo $result.PHP_EOL;

echo unpack("H*", $sigOut)[1].PHP_EOL;

?>
--EXPECT--
1
1
b2579a4e31562773bf4b3717527013f9e996f0a712b4606321f16e705b9a5e179b6cd094edfcfcb1cd82c1ac46e496423fc51a9a8f4fbcde4f8b9bc8207f6c87