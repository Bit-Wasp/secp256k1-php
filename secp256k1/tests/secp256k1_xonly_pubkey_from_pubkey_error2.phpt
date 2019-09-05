--TEST--
secp256k1_xonly_pubkey_from_pubkey returns false with warning if context is wrong resource type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$privKey = str_repeat("\x41", 32);
//02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619

$pubkey = null;
$xonlyPubKey = null;
$sign = null;
$pubkey2 = null;
$result = secp256k1_ec_pubkey_create($ctx, $pubkey, $privKey);
echo $result . PHP_EOL;
echo get_resource_type($pubkey) . PHP_EOL;

$badCtx = tmpfile();
set_error_handler(function($code, $str) { echo $str . PHP_EOL; });
$result = secp256k1_xonly_pubkey_from_pubkey($badCtx, $xonlyPubKey, $sign, $pubkey);
echo $result . PHP_EOL;

?>
--EXPECT--
1
secp256k1_pubkey
secp256k1_xonly_pubkey_from_pubkey(): supplied resource is not a valid secp256k1_context resource
0