--TEST--
secp256k1_ec_pubkey_tweak_add works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$secKeyOne = str_repeat("\x00", 31) . "\x01";
$secKeyFour = str_repeat("\x00", 31) . "\x04";

/** @var resource $pubKey */
$pubKey = null;
$serKey = '';
$cmpKey = null;
$serCmp = '';

$result = secp256k1_ec_pubkey_create($context, $pubKey, $secKeyOne);
echo $result . PHP_EOL;
// 1

$result = secp256k1_ec_pubkey_tweak_add($context, $pubKey, $secKeyOne);
echo $result . PHP_EOL;

$result = secp256k1_ec_pubkey_tweak_add($context, $pubKey, $secKeyOne);
echo $result . PHP_EOL;

$result = secp256k1_ec_pubkey_tweak_add($context, $pubKey, $secKeyOne);
echo $result . PHP_EOL;
// 4

$result = secp256k1_ec_pubkey_serialize($context, $serKey, $pubKey, 1);
echo $result . PHP_EOL;
echo unpack("H*", $serKey)[1] . PHP_EOL;

$result = secp256k1_ec_pubkey_create($context, $cmpKey, $secKeyFour);
echo $result . PHP_EOL;

$result = secp256k1_ec_pubkey_serialize($context, $serCmp, $cmpKey, 1);
echo $result . PHP_EOL;
echo unpack("H*", $serCmp)[1] . PHP_EOL;
?>
--EXPECT--
1
1
1
1
1
02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13
1
1
02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13
