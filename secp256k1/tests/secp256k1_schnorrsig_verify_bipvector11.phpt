--TEST--
secp256k1_schnorrsig_verify - bip vector 11 - returns false
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_schnorrsig_verify")) print "skip no schnorrsig support";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$sig64 = pack("H*", "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B");
$msg32 = hex2bin("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89");
$pubKeyBin = pack("H*", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659");
$sig = null;
$pubKey = null;

$result = secp256k1_xonly_pubkey_parse($ctx, $pubKey, $pubKeyBin);
echo $result.PHP_EOL;

$result = secp256k1_schnorrsig_verify($ctx, $sig64, $msg32, $pubKey);
echo $result.PHP_EOL;

?>
--EXPECT--
1
0