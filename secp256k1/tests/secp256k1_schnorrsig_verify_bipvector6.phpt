--TEST--
secp256k1_schnorrsig_verify - bip vector 6 - returns false
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_schnorrsig_verify")) print "skip no schnorrsig support";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$sig64 = pack("H*", "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2");
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