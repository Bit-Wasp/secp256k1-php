--TEST--
secp256k1_xonly_pubkey_parse works
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
$result = secp256k1_xonly_pubkey_create($ctx, $pubkey, $privKey);
echo $result . PHP_EOL;
echo get_resource_type($pubkey) . PHP_EOL;

$result = secp256k1_xonly_pubkey_serialize($ctx, $pubkeyout, $pubkey);
echo $result . PHP_EOL;
echo unpack("H*", $pubkeyout)[1] . PHP_EOL;

?>
--EXPECT--
1
secp256k1_xonly_pubkey
1
eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619