--TEST--
secp256k1_xonly_pubkey_tweak_add fails with warning if context is wrong resource type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY);

$privKey1 = str_repeat("\x42", 32);

$pubkey1 = null;
$tweakedPub = null;
$tweakTwo = str_repeat("\x00", 31) . "\x02";
$privKey2 = str_repeat("\x42", 31) . "\x44";

$result = secp256k1_xonly_pubkey_create($ctx, $pubkey1, $privKey1);
echo $result . PHP_EOL;
echo get_resource_type($pubkey1) . PHP_EOL;

$badCtx = tmpfile();

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });
$hasSquareY = null;
$result = secp256k1_xonly_pubkey_tweak_add($badCtx, $tweakedPub, $hasSquareY, $pubkey1, $tweakTwo);
echo $result . PHP_EOL;

?>
--EXPECT--
1
secp256k1_xonly_pubkey
secp256k1_xonly_pubkey_tweak_add(): supplied resource is not a valid secp256k1_context resource
0