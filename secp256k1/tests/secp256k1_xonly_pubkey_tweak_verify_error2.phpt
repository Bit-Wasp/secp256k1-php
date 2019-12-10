--TEST--
secp256k1_xonly_pubkey_tweak_test errors if context is wrong resource type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY);

$pubkey1 = null;
$pubKey1Out = null;
$tweakedPub = null;
$tweak = hex2bin("3e10c475efefd59fc14d56706902ef73d5759191065a4c286d4054ed5b6f8258");
$privKey1 = str_repeat("\x42", 32);
//02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619

$result = secp256k1_xonly_pubkey_create($ctx, $pubkey1, $privKey1);
echo $result . PHP_EOL;
echo get_resource_type($pubkey1) . PHP_EOL;

$hasSquareY = null;
$result = secp256k1_xonly_pubkey_tweak_add($ctx, $tweakedPub, $hasSquareY, $pubkey1, $tweak);
echo $result . PHP_EOL;

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$badCtx = tmpfile();
$result = secp256k1_xonly_pubkey_tweak_test($badCtx, $tweakedPub, $hasSquareY, $pubkey1, $tweak);
echo $result.PHP_EOL;

?>
--EXPECT--
1
secp256k1_xonly_pubkey
1
secp256k1_xonly_pubkey_tweak_test(): supplied resource is not a valid secp256k1_context resource
0
