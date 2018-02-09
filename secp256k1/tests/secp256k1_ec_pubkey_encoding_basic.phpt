--TEST--
secp256k1_ec_pubkey_serialize and secp256k1_ec_pubkey_parse are consistent
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

$pubIn = hex2bin("02227cedfab55d1b7642d47a5ac92638ed8822a23c3ddadf88defea45a37f5935e");
$pubKey = '';
$result = \secp256k1_ec_pubkey_parse($context, $pubKey, $pubIn);
echo $result . PHP_EOL;
echo get_resource_type($pubKey) . PHP_EOL;

$pubKeySer = null;
$result = \secp256k1_ec_pubkey_serialize($context, $pubKeySer, $pubKey, 1);
echo $result . PHP_EOL;;
echo bin2hex($pubKeySer) . PHP_EOL;
?>

--EXPECT--
1
secp256k1_pubkey
1
02227cedfab55d1b7642d47a5ac92638ed8822a23c3ddadf88defea45a37f5935e
