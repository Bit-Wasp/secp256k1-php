--TEST--
secp256k1_ec_pubkey_parse fails if public key is garbage
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
$pubIn = hex2bin("02427c42fab42d1b7424247a5ac42638ed4222423c42da428842fe425a37f5935e");
$pubKey = '';
$result = \secp256k1_ec_pubkey_parse($context, $pubKey, $pubIn);
echo $result . PHP_EOL;
?>

--EXPECT--
0