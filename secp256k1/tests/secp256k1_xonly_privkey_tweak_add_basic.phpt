--TEST--
secp256k1_xonly_privkey_tweak_add works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY);

$pubkey1 = null;
$pubkey2 = null;
$tweakTwo = str_repeat("\x00", 31) . "\x02";
$privKey1 = str_repeat("\x42", 32);
//02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619
$privKey2 = str_repeat("\x42", 31) . "\x44";

$result = secp256k1_xonly_privkey_tweak_add($ctx, $privKey1, $tweakTwo);
echo $result . PHP_EOL;

if ($privKey1 === $privKey2) {
    echo "private keys equal";
} else {
    echo bin2hex($privKey1)." !== ".bin2hex($privKey2)."\n";
}

?>
--EXPECT--
1
private keys equal