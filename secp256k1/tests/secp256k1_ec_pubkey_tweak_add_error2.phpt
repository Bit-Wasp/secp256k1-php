--TEST--
secp256k1_ec_pubkey_tweak_add returns false if pubkey wrong type
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

\set_error_handler(function($code, $str) { echo $str . PHP_EOL; });

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$secKeyTwo = str_repeat("\x00", 31) . "\x02";

$pubKey = tmpfile();
$result = secp256k1_ec_pubkey_tweak_add($context, $pubKey, $secKeyTwo);
echo gettype($result) . PHP_EOL;
echo ($result ? "true" : "false") . PHP_EOL;

?>
--EXPECT--
secp256k1_ec_pubkey_tweak_add(): supplied resource is not a valid secp256k1_pubkey resource
boolean
false