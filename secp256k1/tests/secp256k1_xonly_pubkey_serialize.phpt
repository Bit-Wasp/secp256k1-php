--TEST--
secp256k1_xonly_pubkey_serialize works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$privKey1 = str_repeat("\x41", 32);
//02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619
$privKey2 = str_repeat("\x90", 32);
//0262cd4a67842524034e9b3f313feab032bdb4858588c193bc26ce9f380321ef79

$pubkey1 = null;
$pubkeyout1 = '';
$result = secp256k1_xonly_pubkey_create($ctx, $pubkey1, $privKey1);
echo $result . PHP_EOL;

$result = secp256k1_xonly_pubkey_serialize($ctx, $pubkeyout1, $pubkey1);
echo $result . PHP_EOL;
echo unpack("H*", $pubkeyout1)[1] . PHP_EOL;

$pubkey2 = null;
$pubkeyout2 = '';
$result = secp256k1_xonly_pubkey_create($ctx, $pubkey2, $privKey2);
echo $result . PHP_EOL;

$result = secp256k1_xonly_pubkey_serialize($ctx, $pubkeyout2, $pubkey2);
echo $result . PHP_EOL;
echo unpack("H*", $pubkeyout2)[1] . PHP_EOL;


?>
--EXPECT--
1
1
eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619
1
1
62cd4a67842524034e9b3f313feab032bdb4858588c193bc26ce9f380321ef79