--TEST--
secp256k1_xonly_pubkey_tweak_add works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY);

$pubkey1 = null;
$pubkey2 = null;
$pubKey1Out = null;
$pubKey2Out = null;
$tweakedPub = null;
$tweakTwo = str_repeat("\x00", 31) . "\x02";
$privKey1 = str_repeat("\x42", 32);
//02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619
$privKey2 = str_repeat("\x42", 31) . "\x44";

$result = secp256k1_xonly_pubkey_create($ctx, $pubkey1, $privKey1);
echo $result . PHP_EOL;
echo get_resource_type($pubkey1) . PHP_EOL;

$result = secp256k1_xonly_pubkey_create($ctx, $pubkey2, $privKey2);
echo $result . PHP_EOL;
echo get_resource_type($pubkey2) . PHP_EOL;


$result = secp256k1_xonly_pubkey_tweak_add($ctx, $tweakedPub, $pubkey1, $tweakTwo);
echo $result . PHP_EOL;

$result = secp256k1_ec_pubkey_serialize($ctx, $pubKey1Out, $tweakedPub, SECP256K1_EC_COMPRESSED);
echo $result . PHP_EOL;

$result = secp256k1_xonly_pubkey_serialize($ctx, $pubKey2Out, $pubkey2);
echo $result . PHP_EOL;

if (substr($pubKey1Out, 1) === $pubKey2Out) {
    echo "public keys equal";
} else {
    echo bin2hex($pubKey1Out)." !== ".bin2hex($pubKey2Out)."\n";
}

?>
--EXPECT--
1
secp256k1_xonly_pubkey
1
secp256k1_xonly_pubkey
1
1
1
public keys equal