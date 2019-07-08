--TEST--
secp256k1_schnorrsig_verify errors when signature is wrong resource type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$msg32 = hash('sha256', "a message", true);
$pubKeyBin = pack("H*", "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619");
$sig = null;
$pubKey = null;

$result = secp256k1_ec_pubkey_parse($ctx, $pubKey, $pubKeyBin);
echo $result.PHP_EOL;

$sig = tmpfile();

$result = secp256k1_schnorrsig_verify($ctx, $sig, $msg32, $pubKey);
echo $result.PHP_EOL;

?>
--EXPECT--
1
secp256k1_schnorrsig_verify(): supplied resource is not a valid secp256k1_schnorrsig resource
0