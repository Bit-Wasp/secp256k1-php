--TEST--
secp256k1_ec_pubkey_tweak_mul works
--SKIPIF--
<?php
if (!extension_loaded("secp256k1")) print "skip extension not loaded";
?>
--FILE--
<?php

$context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

$secKeyOne = str_repeat("\x00", 31) . "\x01";
$secKeyTwo = str_repeat("\x00", 31) . "\x02";
$secKeyFour = str_repeat("\x00", 31) . "\x02";
$secKeyEight = str_repeat("\x00", 31) . "\x08";
$secKeySixteen = str_repeat("\x00", 31) . "\x0f";

/** @var resource $pubKey */
$pubKey = null;
$serKey = '';
$cmpKey = null;
$serCmp = '';

$result = secp256k1_ec_pubkey_create($context, $pubKey, $secKeyOne);
echo $result . PHP_EOL;
// 1

$result = secp256k1_ec_pubkey_tweak_mul($context, $pubKey, $secKeyTwo);
echo $result . PHP_EOL;

$result = secp256k1_ec_pubkey_create($context, $cmpKey, $secKeyTwo);
echo $result . PHP_EOL;

$result = secp256k1_ec_pubkey_serialize($context, $serKey, $pubKey, 1);
echo $result . PHP_EOL;
echo unpack("H*", $serKey)[1] . PHP_EOL;

$result = secp256k1_ec_pubkey_serialize($context, $serCmp, $cmpKey, 1);
echo $result . PHP_EOL;
echo unpack("H*", $serKey)[1] . PHP_EOL;
// 2

$result = secp256k1_ec_pubkey_tweak_mul($context, $pubKey, $secKeyTwo);
echo $result . PHP_EOL;

$result = secp256k1_ec_pubkey_create($context, $cmpKey, $secKeyFour);
echo $result . PHP_EOL;

$result = secp256k1_ec_pubkey_serialize($context, $serKey, $pubKey, 1);
echo $result . PHP_EOL;
echo unpack("H*", $serKey)[1] . PHP_EOL;

$result = secp256k1_ec_pubkey_serialize($context, $serCmp, $cmpKey, 1);
echo $result . PHP_EOL;
echo unpack("H*", $serKey)[1] . PHP_EOL;
// 4

$result = secp256k1_ec_pubkey_tweak_mul($context, $pubKey, $secKeyTwo);
echo $result . PHP_EOL;

$result = secp256k1_ec_pubkey_create($context, $cmpKey, $secKeyEight);
echo $result . PHP_EOL;

$result = secp256k1_ec_pubkey_serialize($context, $serKey, $pubKey, 1);
echo $result . PHP_EOL;
echo unpack("H*", $serKey)[1] . PHP_EOL;

$result = secp256k1_ec_pubkey_serialize($context, $serCmp, $cmpKey, 1);
echo $result . PHP_EOL;
echo unpack("H*", $serKey)[1] . PHP_EOL;
// 8

$result = secp256k1_ec_pubkey_tweak_mul($context, $pubKey, $secKeyTwo);
echo $result . PHP_EOL;

$result = secp256k1_ec_pubkey_create($context, $cmpKey, $secKeySixteen);
echo $result . PHP_EOL;

$result = secp256k1_ec_pubkey_serialize($context, $serKey, $pubKey, 1);
echo $result . PHP_EOL;
echo unpack("H*", $serKey)[1] . PHP_EOL;

$result = secp256k1_ec_pubkey_serialize($context, $serCmp, $cmpKey, 1);
echo $result . PHP_EOL;
echo unpack("H*", $serKey)[1] . PHP_EOL;
// 16

?>
--EXPECT--
1
1
1
1
02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
1
02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
1
1
1
02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13
1
02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13
1
1
1
022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01
1
022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01
1
1
1
03e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a
1
03e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a
