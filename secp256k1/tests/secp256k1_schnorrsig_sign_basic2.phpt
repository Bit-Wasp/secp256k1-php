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
76b598bae61948c3054c19a7864b56d7b772452274c522f9608fe3cd17c13dc61226c722111ed04629965d91d10e30b4024a11c76172924373969261be41640c