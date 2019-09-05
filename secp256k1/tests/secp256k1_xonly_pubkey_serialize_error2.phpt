--TEST--
secp256k1_xonly_pubkey_serialize errors if context is wrong resource type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$privKey1 = str_repeat("\x41", 32);
//02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619

$pubkey1 = null;
$pubkeyout1 = '';
$result = secp256k1_xonly_pubkey_create($ctx, $pubkey1, $privKey1);
echo $result . PHP_EOL;

$result = secp256k1_xonly_pubkey_serialize(tmpfile(), $pubkeyout1, $pubkey1);
echo $result . PHP_EOL;
echo unpack("H*", $pubkeyout1)[1] . PHP_EOL;

?>
--EXPECT--
1
secp256k1_xonly_pubkey_serialize(): supplied resource is not a valid secp256k1_context resource
0