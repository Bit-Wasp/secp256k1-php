--TEST--
secp256k1_schnorrsig_verify errors if provided an invalid resource as a context
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_schnorrsig_verify")) print "skip no schnorrsig support";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$sigBin = pack("H*", "21aedc76051415c8d083683842e5bab7995580f9df8ce703234893d14b8d0fa7e852bee5e7eb94dd11d70185bcaa7ef67aafe28ebc109ee63353c182330be2de");
$msg32 = hash('sha256', "a message", true);
$pubKeyBin = pack("H*", "eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619");
$sig = null;
$pubKey = null;

$result = secp256k1_schnorrsig_parse($ctx, $sig, $sigBin);
echo $result.PHP_EOL;

$result = secp256k1_xonly_pubkey_parse($ctx, $pubKey, $pubKeyBin);
echo $result.PHP_EOL;

$badctx = tmpfile();

$result = secp256k1_schnorrsig_verify($badctx, $sig, $msg32, $pubKey);
echo $result.PHP_EOL;

?>
--EXPECT--
1
1
secp256k1_schnorrsig_verify(): supplied resource is not a valid secp256k1_context resource
0