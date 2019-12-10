--TEST--
secp256k1_schnorrsig_sign works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
if (!function_exists("secp256k1_schnorrsig_verify")) print "skip no schnorrsig support";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$privKey = str_repeat("\x41", 32);
//02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619

$msg32 = hash('sha256', "a message", true);
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
9cead1aa6d49645937911478aa052d7fab3f6b1338f378216e32ffd17c049c204e4c7f672e1facbd281d717f609586f05c84b86d5c3791924f3953afaeea7f18