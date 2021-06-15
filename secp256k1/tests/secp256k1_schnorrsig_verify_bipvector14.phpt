--TEST--
secp256k1_schnorrsig_verify - bip vector 14 - returns false
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_schnorrsig_verify")) print "skip no schnorrsig support";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$sig64 = pack("H*", "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B");
$msg32 = hex2bin("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89");
$pubKeyBin = pack("H*", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30");
$sig = null;
$pubKey = null;

$result = secp256k1_xonly_pubkey_parse($ctx, $pubKey, $pubKeyBin);
echo $result.PHP_EOL;

?>
--EXPECT--
0