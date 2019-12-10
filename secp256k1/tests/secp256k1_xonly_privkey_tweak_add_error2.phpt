--TEST--
secp256k1_xonly_privkey_tweak_add returns false with warning if context resource is wrong type
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

$badCtx = tmpfile();
set_error_handler(function($code, $str) { echo $str . PHP_EOL; });
$result = secp256k1_xonly_privkey_tweak_add($badCtx, $privKey1, $tweakTwo);
echo $result . PHP_EOL;

?>
--EXPECT--
secp256k1_xonly_privkey_tweak_add(): supplied resource is not a valid secp256k1_context resource
0