--TEST--
secp256k1_ec_pubkey_combine works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

set_error_handler(function($code, $str) { echo $str . PHP_EOL; });
$ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
$seckey = hex2bin('7ccca75d019dbae79ac4266501578684ee64eeb3c9212105f7a3bdc0ddb0f27e');
$pubKey = null;
$pubKeyOut1 = '';
$pubKeyOut2 = '';
$result = secp256k1_ec_pubkey_create($ctx, $pubKey, $seckey);
echo $result . PHP_EOL;

$result = secp256k1_ec_pubkey_serialize($ctx, $pubKeyOut1, $pubKey, 1);
echo unpack("H*", $pubKeyOut1)[1] . PHP_EOL;

$pubKeys = [$pubKey];

$combinedPubKey = null;
$result = secp256k1_ec_pubkey_combine($ctx, $combinedPubKey, $pubKeys);
echo $result . PHP_EOL;

$result = secp256k1_ec_pubkey_serialize($ctx, $pubKeyOut2, $combinedPubKey, 1);
echo unpack("H*", $pubKeyOut2)[1] . PHP_EOL;

?>
--EXPECT--
1
03e9a06e539d6bf5cf1ca5c41b59121fa3df07a338322405a312c67b6349a707e9
1
03e9a06e539d6bf5cf1ca5c41b59121fa3df07a338322405a312c67b6349a707e9